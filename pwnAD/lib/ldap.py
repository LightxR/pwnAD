import datetime
import ldap3
from ldap3.utils.conv import escape_filter_chars
import logging
import os
import ssl
import struct
import sys
import tempfile
from typing import Any, List, Union

from pwnAD.lib.certificate import key_to_pem, cert_to_pem, load_pfx, rsa, x509


class LDAPAuthenticationError(Exception):
    """Raised when LDAP authentication fails"""
    pass


class _KerberosSealSocket:
    """
    Socket wrapper that applies GSS-API sealing to all LDAP PDUs.

    Delegates to impacket's GSSAPI_AES* (RFC 4121, key_usages 22/24) or
    GSSAPI_RC4 (RFC 4757 old-format tokens) depending on the session cipher,
    ensuring the correct wire format for each enctype.

    SASL wire framing: each PDU is prefixed with a 4-byte big-endian length.
    """

    def __init__(self, sock, gss, session_key):
        self._sock = sock
        self._gss = gss
        self._session_key = session_key
        self._seq_num = 0
        self._buf = b''

    def _wrap(self, data):
        payload, header = self._gss.GSS_Wrap_LDAP(self._session_key, data, self._seq_num)
        self._seq_num += 1
        return header + payload

    def _unwrap(self, token):
        from impacket.krb5.gssapi import GSSAPI_RC4
        if isinstance(self._gss, GSSAPI_RC4):
            # impacket's MechIndepToken.from_bytes() has an off-by-one BER length
            # bug: for tokens with single-byte length encoding (content < 128 bytes)
            # it does not advance past the length byte, so the WRAP header is parsed
            # 4 bytes off → wrong SGN_CKSUM/SND_SEQ → wrong Kcrypt → garbage output.
            # Bypass it and parse the BER structure ourselves.
            return self._unwrap_rc4(token)
        data, _ = self._gss.GSS_Unwrap_LDAP(self._session_key, token, 0)
        return data

    def _unwrap_rc4(self, data):
        """Correct RC4-HMAC GSS_Unwrap for LDAP tokens (RFC 4757)."""
        from Cryptodome.Hash import HMAC as _HMAC, MD5 as _MD5
        from Cryptodome.Cipher import ARC4 as _ARC4

        # Parse outer GSSAPI APPLICATION token:
        # 0x60 [BER_len] 0x06 [oid_len] [oid_bytes] [WRAP_token]
        if not data or data[0] != 0x60:
            raise ValueError(f'Expected GSSAPI APPLICATION tag 0x60, got 0x{data[0]:02x}')
        i = 1
        if data[i] < 0x80:
            i += 1                     # single-byte length — skip it
        else:
            i += 1 + (data[i] & 0x7f) # multi-byte — skip the extra length bytes too
        if data[i] != 0x06:
            raise ValueError(f'Expected OID tag 0x06, got 0x{data[i]:02x}')
        i += 2 + data[i + 1]           # skip OID tag + length + value

        # RC4 WRAP token layout (32-byte header + ciphertext):
        #   [0:2]   TOK_ID      (0x0102)
        #   [2:4]   SGN_ALG     (0x0000 = HMAC-MD5)
        #   [4:6]   SEAL_ALG    (0x0010 = RC4)
        #   [6:8]   Filler      (0xffff)
        #   [8:16]  SND_SEQ     (enc sequence number, 8 bytes)
        #   [16:24] SGN_CKSUM   (HMAC signature, 8 bytes)
        #   [24:32] Confounder  (encrypted, 8 bytes)
        #   [32:]   Ciphertext  (encrypted data + trailing 0x01 byte)
        wrap = data[i:]
        sgn_cksum   = wrap[16:24]
        snd_seq_enc = wrap[8:16]
        confounder  = wrap[24:32]
        ciphertext  = wrap[32:]

        key = self._session_key
        Klocal = bytes(b ^ 0xF0 for b in key.contents)

        Kseq = _HMAC.new(key.contents, b'\x00\x00\x00\x00', _MD5).digest()
        Kseq = _HMAC.new(Kseq, sgn_cksum, _MD5).digest()
        snd_seq = _ARC4.new(Kseq).encrypt(snd_seq_enc)

        Kcrypt = _HMAC.new(Klocal, b'\x00\x00\x00\x00', _MD5).digest()
        Kcrypt = _HMAC.new(Kcrypt, snd_seq[:4], _MD5).digest()

        # Feed enc_confounder to advance RC4 state, then decrypt ciphertext from pos 8
        plaintext = _ARC4.new(Kcrypt).decrypt(confounder + ciphertext)[8:]
        return plaintext[:-1]  # strip trailing 0x01 added by GSS_Wrap_LDAP

    def sendall(self, data, *args, **kwargs):
        wrapped = self._wrap(data)
        return self._sock.sendall(struct.pack('>I', len(wrapped)) + wrapped, *args, **kwargs)

    def send(self, data, *args, **kwargs):
        wrapped = self._wrap(data)
        frame = struct.pack('>I', len(wrapped)) + wrapped
        sent = self._sock.send(frame, *args, **kwargs)
        return len(data) if sent == len(frame) else 0

    def recv(self, bufsize, *args, **kwargs):
        while len(self._buf) < 4:
            chunk = self._sock.recv(4096)
            if not chunk:
                return b''
            self._buf += chunk
        msg_len = struct.unpack('>I', self._buf[:4])[0]
        self._buf = self._buf[4:]
        while len(self._buf) < msg_len:
            chunk = self._sock.recv(4096)
            if not chunk:
                return b''
            self._buf += chunk
        wrapped, self._buf = self._buf[:msg_len], self._buf[msg_len:]
        return self._unwrap(wrapped)

    def __getattr__(self, name):
        return getattr(self._sock, name)


# Kerberos auth
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type.univ import noValue
from pyasn1.type import tag as asn1tag
from impacket.krb5.ccache import CCache
from impacket.krb5.asn1 import AP_REQ, Authenticator, Checksum as KrbChecksum, TGS_REP, seq_set
from impacket.krb5.gssapi import GSSAPI
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
      

class LDAPConnection:
    def __init__(
            self, 
            target, 
            domain=None, 
            _baseDN="", 
            configuration_path="", 
            ldap_user=None, 
            ldap_pass=None, 
            lmhash='', 
            nthash='', 
            aesKey=None, 
            pfx :str=None, 
            pfx_pass=None, 
            key: rsa.RSAPublicKey=None, 
            cert: x509.Certificate =None, 
            use_kerberos=None, 
            kdcHost=None, 
            _do_tls=False, 
            port=None
        ):
        self.target=target
        self.domain=domain
        self._baseDN=_baseDN
        self.configuration_path = configuration_path
        self.ldap_user=ldap_user
        self.ldap_pass=ldap_pass
        self.lmhash=lmhash
        self.nthash=nthash
        self.aesKey=aesKey
        self.pfx=pfx
        self.pfx_pass=pfx_pass
        self.key=key
        self.cert=cert
        self.use_kerberos=use_kerberos
        self.kdcHost=kdcHost
        self._do_tls=_do_tls
        self.port=port

        self._ldap_server = None
        self._ldap_connection = None

        self.domaindump()

        try:
            if ldap3.SIGN and ldap3.ENCRYPT:
                self._sign_and_seal_supported = True
                logging.debug('LDAP sign and seal are supported')
        except AttributeError:
            self._sign_and_seal_supported = False
            logging.debug('LDAP sign and seal are not supported')

        try:    
            if ldap3.TLS_CHANNEL_BINDING:
                self._tls_channel_binding_supported = True
                logging.debug('TLS channel binding is supported')
        except AttributeError:
            self._tls_channel_binding_supported = False
            logging.debug('TLS channel binding is not supported')

        self._do_certificate = (True if self.pfx or (self.key and self.cert) else False)
        if self._do_certificate:
            logging.debug("Authentication with certificate")

        if self.port is None:
            if self._do_tls is True:
                self.port = 636
            else:
                self.port = 389

    def _ntlm_auth(self, ldap_scheme, seal_and_sign=False, tls_channel_binding=False):
        logging.debug(f"LDAP authentication with NTLM: ldap_scheme = {ldap_scheme} / seal_and_sign = {seal_and_sign} / tls_channel_binding = {tls_channel_binding}")
        ldap_server = ldap3.Server(f"{ldap_scheme}://{self.target}")
        self.user = f"{self.domain}\\{self.ldap_user}"
        ldap_connection_kwargs = {'user': self.user, 'raise_exceptions': True, 'authentication': ldap3.NTLM}

        if self.lmhash and self.nthash:
            ldap_connection_kwargs['password'] = f"{self.lmhash}:{self.nthash}"
            logging.debug(f"LDAP binding parameters: server = {self.target} / user = {self.user} / auth = hash")

        else:
            ldap_connection_kwargs['password'] = self.ldap_pass
            logging.debug(f"LDAP binding parameters: server = {self.target} / user = {self.user} / auth = password")

        if seal_and_sign:
            ldap_connection_kwargs['session_security'] = ldap3.ENCRYPT

        elif tls_channel_binding:
            ldap_connection_kwargs['channel_binding'] = ldap3.TLS_CHANNEL_BINDING

        try:
            ldap_connection = ldap3.Connection(ldap_server, **ldap_connection_kwargs)
            ldap_connection.bind()

        except ldap3.core.exceptions.LDAPSocketOpenError as e:
                logging.critical(e)

                if self._do_tls:
                    logging.critical('TLS negociation failed, this error is mostly due to your host not supporting SHA1 as signing algorithm for certificates')
                raise LDAPAuthenticationError(str(e))

        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
                logging.debug('Server returns LDAPInvalidCredentialsResult')
                # https://github.com/zyn3rgy/LdapRelayScan#ldaps-channel-binding-token-requirements
                if 'AcceptSecurityContext error, data 80090346' in ldap_connection.result['message'] and not self._tls_channel_binding_supported:
                        
                    if self.lmhash and self.nthash:
                        logging.critical('Server requires Channel Binding Token and your ldap3 install does not support it. '
                                                'Please install https://github.com/cannatag/ldap3/pull/1087, try another authentication method, '
                                                'or use a password, not a hash, to authenticate.')
                        raise LDAPAuthenticationError('Server requires Channel Binding Token not supported with hash authentication')
                    
                    else:
                        # Simple bind doesn't work with empty passwords, so only fallback if password is not empty
                        if self.ldap_pass:
                            logging.debug('Server requires Channel Binding Token but you are using password authentication,'
                                                ' falling back to SIMPLE authentication, hoping LDAPS port is open')
                            self._simple_auth('ldaps')
                            return
                        else:
                            raise LDAPAuthenticationError('Invalid Credentials')
                        
                elif self._tls_channel_binding_supported == True and not tls_channel_binding:
                    logging.debug('Falling back to TLS with channel binding')
                    self._ntlm_auth('ldaps', tls_channel_binding=True)
                    return
                
                else:
                    raise LDAPAuthenticationError('Invalid Credentials')

        except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult:
            logging.debug('Server returns LDAPStrongerAuthRequiredResult')

            if not self._sign_and_seal_supported:
                logging.debug('Sealing not available, falling back to LDAPS')
                self._ntlm_auth('ldaps')
                return
            else:
                logging.debug('Falling back to NTLM sealing')
                self._ntlm_auth(ldap_scheme, seal_and_sign=True)
                return

        except Exception as e:
            logging.debug(f"Couldn't connect to LDAP server.\n{e}")
            raise

        who_am_i = ldap_connection.extend.standard.who_am_i()
        logging.debug(f"Successfully connected to LDAP server as {who_am_i}")

        self._ldap_server = ldap_server
        self._ldap_connection = ldap_connection
        
        return ldap_server, ldap_connection

    @staticmethod
    def _compute_gss_checksum():
        """
        GSS-API authenticator checksum (RFC 4121 §4.1.1.1, cksumtype=0x8003).
        Bnd is 16 zero bytes (no channel binding needed for Kerberos — the
        ticket is already SPN-bound).  Flags: REPLAY|SEQUENCE|CONF|INTEG.
        """
        flags = 0x3C   # REPLAY=0x04 | SEQUENCE=0x08 | CONF=0x10 | INTEG=0x20
        return struct.pack('<I', 16) + b'\x00' * 16 + struct.pack('<I', flags)

    def _kerberos_auth(self, ldap_scheme, seal_and_sign=False, TGT=None, TGS=None, useCache=True):

        logging.debug(f"LDAP authentication with Kerberos: ldap_scheme = {ldap_scheme} / seal_and_sign = {seal_and_sign}")
        self.user = f"{self.ldap_user}@{self.domain.upper()}"

        if self._do_tls:
            use_ssl = True
            tls = ldap3.Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLSv1_2,
                ciphers='ALL:@SECLEVEL=0'
            )
        else:
            use_ssl = False
            tls = None

        ldap_server = ldap3.Server(
            host=self.target,
            port=self.port,
            use_ssl=use_ssl,
            get_info=ldap3.ALL,
            tls=tls
        )
        logging.debug(f"LDAP binding parameters: server = {self.target} / user = {self.user}")
        ldap_connection = ldap3.Connection(server=ldap_server)

        # Open explicitly so we can access the TLS socket before binding
        ldap_connection.open(read_server_info=False)

        ldap_connection.bind()

        if TGT is not None or TGS is not None or self.aesKey is not None:
            useCache = False

        target = f"ldap/{self.target}"
        if useCache:
            user = '' if self.ldap_user == None else self.user # Case when only -k is provided without username
            self.domain, self.user, TGT, TGS = CCache.parseFile(self.domain, user, target)

        # First of all, we need to get a TGT for the user
        userName = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:

                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.ldap_pass, self.domain, self.lmhash, self.nthash,
                                                                        self.aesKey, self.kdcHost)

        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

        if TGS is None:
            serverName = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.domain, self.kdcHost, tgt, cipher,
                                                                    sessionKey)
        else:
            tgs = TGS['KDC_REP']
            cipher = TGS['cipher']
            sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP
        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []   # No AP_OPTS_MUTUAL_REQUIRED — impacket uses none for sealing
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self.domain
        seq_set(authenticator, 'cname', userName.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        # Include GSS-API checksum when sealing is requested so the server
        # knows to enter confidentiality+integrity mode (CONF|INTEG flags).
        # KrbChecksum() needs an explicit context tag [3] to match the
        # Authenticator cksum field schema.
        if seal_and_sign:
            cksum = KrbChecksum().subtype(
                explicitTag=asn1tag.Tag(
                    asn1tag.tagClassContext, asn1tag.tagFormatConstructed, 3
                )
            )
            cksum['cksumtype'] = 0x8003
            cksum['checksum'] = self._compute_gss_checksum()
            authenticator.setComponentByName('cksum', cksum)

        # seq-number=0 is required so Windows initialises its GSSAPI sealing
        # context sequence-number tracking.  Without it, Windows may not enter
        # sealed mode and will send raw (unencrypted) LDAP responses, which our
        # SASL-frame reader misparses as a multi-gigabyte frame.
        # Impacket's kerberosLogin() always sets this to 0.
        if seal_and_sign:
            authenticator['seq-number'] = 0

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = encoder.encode(apReq)

        request = ldap3.operation.bind.bind_operation(ldap_connection.version, ldap3.SASL, self.user, None, 'GSS-SPNEGO',
                                                    blob.getData())

        # Done with the Kerberos saga, now let's get into LDAP
        if ldap_connection.closed:  # try to open connection if closed
            ldap_connection.open(read_server_info=False)

        ldap_connection.sasl_in_progress = True
        response = ldap_connection.post_send_single_response(ldap_connection.send('bindRequest', request, None))
        ldap_connection.sasl_in_progress = False

        result_code = response[0]['result']

        if result_code == 8:  # strongAuthRequired – server enforces LDAP signing
            logging.debug('Server requires LDAP signing')
            if not seal_and_sign:
                logging.debug('Retrying with Kerberos GSS-API sealing')
                self._kerberos_auth(ldap_scheme, seal_and_sign=True, useCache=useCache)
                return
            if ldap_scheme != 'ldaps':
                logging.debug('GSS-API sealing failed, falling back to LDAPS')
                self._do_tls = True
                self.port = 636
                self._kerberos_auth('ldaps', seal_and_sign=False, useCache=useCache)
                return
            raise LDAPAuthenticationError(f"Server requires LDAP signing: {response}")

        elif result_code == 49:  # invalidCredentials
            raise LDAPAuthenticationError(f"Kerberos authentication failed (invalidCredentials): {response}")

        elif result_code != 0:
            raise LDAPAuthenticationError(f"Kerberos bind failed: {response}")

        ldap_connection.bound = True
        ldap_connection.raise_exceptions = True

        if seal_and_sign:
            logging.debug('Installing Kerberos GSS-API sealing on LDAP connection')
            # Use the TGS session key directly (no AP_OPTS_MUTUAL_REQUIRED, so
            # no AP_REP subkey).  This matches impacket's own LDAP sealing
            # approach and is what Windows DC expects for SASL encryption.
            gss = GSSAPI(cipher)
            ldap_connection.socket = _KerberosSealSocket(
                ldap_connection.socket, gss, sessionKey
            )

        who_am_i = ldap_connection.extend.standard.who_am_i()

        if not who_am_i:
            logging.critical('Kerberos authentication failed')
            raise LDAPAuthenticationError('Kerberos authentication failed')
        logging.debug(f"Successfully connected to the LDAP as {who_am_i}")

        self._ldap_server = ldap_server
        self._ldap_connection = ldap_connection

    def _schannel_auth(self, ldap_scheme):
        logging.debug(f"LDAP authentication with SChannel: ldap_scheme = {ldap_scheme} with port {self.port}")
        self.user = f"{self.domain.upper()}\\{self.ldap_user}"

        key_file_name = None
        cert_file_name = None

        try:
            if self.pfx:
                with open(self.pfx, "rb") as f:
                    if self.pfx_pass:
                        key, cert = load_pfx(f.read(), self.pfx_pass.encode())
                    else:
                        key, cert = load_pfx(f.read())

                key_file = tempfile.NamedTemporaryFile(delete=False)
                key_file.write(key_to_pem(key))
                key_file.close()
                key_file_name = key_file.name

                cert_file = tempfile.NamedTemporaryFile(delete=False)
                cert_file.write(cert_to_pem(cert))
                cert_file.close()
                cert_file_name = cert_file.name

                tls = ldap3.Tls(local_private_key_file=key_file_name, local_certificate_file=cert_file_name, validate=ssl.CERT_NONE)
            else:
                tls = ldap3.Tls(local_private_key_file=self.key, local_certificate_file=self.cert, validate=ssl.CERT_NONE)

            ldap_server_kwargs = {'use_ssl': self.port == 636,
                                  'port': self.port,
                                  'get_info': ldap3.ALL,
                                  'tls': tls}

            ldap_server = ldap3.Server(self.target, **ldap_server_kwargs)

            ldap_connection_kwargs = dict()

            if self.port == 389:
                logging.debug("testing StartTLS connection")
                ldap_connection_kwargs = {'authentication': ldap3.SASL,
                                        'sasl_mechanism': ldap3.EXTERNAL,
                                        'auto_bind': ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                                        'raise_exceptions': True}

            ldap_connection = ldap3.Connection(ldap_server, **ldap_connection_kwargs)
            self._do_tls = True

            if self.port == 636:
                ldap_connection.open()

            who_am_i = ldap_connection.extend.standard.who_am_i()
            if not who_am_i:
                logging.critical('Certificate authentication failed')
                raise LDAPAuthenticationError('Certificate authentication failed')

            logging.debug(f"Successfully connected to LDAP server as {who_am_i}")
            self._ldap_server = ldap_server
            self._ldap_connection = ldap_connection

        finally:
            # Always cleanup temporary files
            if key_file_name and os.path.exists(key_file_name):
                os.unlink(key_file_name)
            if cert_file_name and os.path.exists(cert_file_name):
                os.unlink(cert_file_name)

    def _simple_auth(self, ldap_scheme):
        logging.debug(f"LDAP authentication with SIMPLE: ldap_scheme = {ldap_scheme}")
        ldap_server = ldap3.Server(f"{ldap_scheme}://{self.target}")
        self.user = f"{self.ldap_user}@{self.domain}"
        ldap_connection_kwargs = {'user': self.user, 'raise_exceptions': True, 'authentication': ldap3.SIMPLE}

        ldap_connection_kwargs['password'] = self.ldap_pass
        logging.debug(f"LDAP binding parameters: server = {self.target} / user = {self.user} / auth = password")

        try:
            ldap_connection = ldap3.Connection(ldap_server, **ldap_connection_kwargs)
            ldap_connection.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
                logging.critical(e)
                if self._do_tls:
                    logging.critical('TLS negociation failed, this error is mostly due to your host '
                                          'not supporting SHA1 as signing algorithm for certificates')
                raise LDAPAuthenticationError(str(e))
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
            raise LDAPAuthenticationError('Invalid Credentials')
        except ldap3.core.exceptions.LDAPBindError as e:
            # "password is mandatory in simple bind" when password is empty
            raise LDAPAuthenticationError('Invalid Credentials')

        who_am_i = ldap_connection.extend.standard.who_am_i()
        logging.debug(f"Successfully connected to LDAP server as {who_am_i}")

        self._ldap_server = ldap_server
        self._ldap_connection = ldap_connection
     
    def connect(self):
        if self._do_tls:
            ldap_scheme = 'ldaps'
            logging.debug('LDAPS connection forced')
        else:
            ldap_scheme = 'ldap'

        if self.use_kerberos:
            self._kerberos_auth(ldap_scheme)
        elif self._do_certificate:
            self._schannel_auth(ldap_scheme)
        else:
            try :
                self._ntlm_auth(ldap_scheme)
            except LDAPAuthenticationError:
                # Don't fallback to simple auth if password is empty (simple bind doesn't support it)
                if not self.ldap_pass:
                    raise
                logging.debug("Error while trying to connect with NTLM authentication, falling back to simple authentication")
                self._simple_auth(ldap_scheme)

    

    def start_tls(self):
        if not self._ldap_connection.tls_started and not self._ldap_connection.server.ssl:
            logging.info('Sending StartTLS command...')
            try:
                self._ldap_connection.start_tls()
                self._do_tls = True # check the code logic
                logging.info('StartTLS succeded, you are now connected through a TLS channel')
            except Exception as e:
                logging.error(f"StartTLS failed, error :{e}")
        else:
            logging.error('It seems you are already connected through a TLS channel.')

    def is_connected(self):
        """Check if the LDAP connection is still alive."""
        try:
            return (self._ldap_connection is not None and
                    self._ldap_connection.bound and
                    not self._ldap_connection.closed)
        except Exception:
            return False

    def rebind(self):
        """Attempt to rebind the LDAP connection.

        First tries a simple rebind, if that fails, creates a new connection
        with the same parameters.

        Returns:
            bool: True if rebind succeeded, False otherwise.
        """
        try:
            # Try simple rebind first
            if self._ldap_connection is not None:
                try:
                    if self._ldap_connection.bound:
                        self._ldap_connection.unbind()
                    self._ldap_connection.bind()
                    logging.info("[*] Successfully performed LDAP rebind")
                    return True
                except Exception as e:
                    logging.debug(f"Simple rebind failed: {e}, attempting full reconnection")

            # Full reconnection with same parameters
            self.connect()
            logging.info("[*] Successfully reconnected to LDAP server")
            return True

        except Exception as e:
            logging.error(f"[-] Failed to rebind LDAP connection: {e}")
            return False  

    def add(self, *args, **kwargs) -> Any:
        self._ldap_connection.add(*args, **kwargs)
        return self._ldap_connection.result

    def delete(self, *args, **kwargs) -> Any:
        self._ldap_connection.delete(*args, **kwargs)
        return self._ldap_connection.result

    def modify(self, *args, **kwargs) -> Any:
        self._ldap_connection.modify(*args, **kwargs)
        return self._ldap_connection.result

    def search(self, *args, **kwargs) -> Any:
        self._ldap_connection.search(*args, **kwargs)
        return self._ldap_connection.result
    
    def bind(self, *args, **kwargs) -> Any:
        self._ldap_connection.bind(*args, **kwargs)
        return self._ldap_connection.result    
    
    def exists(self, account):
        self._ldap_connection.search(self._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(account))
        return len(self._ldap_connection.entries) ==1

    def get(self, user_or_computer):
        self._ldap_connection.search(self._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(user_or_computer), search_scope=ldap3.SUBTREE)
        return self._ldap_connection.entries[0]
    
    def ldap_get_user(self, accountName):
        self._ldap_connection.search(self._baseDN, '(sAMAccountName=%s)' % ldap3.utils.conv.escape_filter_chars(accountName), attributes=['objectSid'])
        try:
            dn = self._ldap_connection.entries[0].entry_dn
            sid = ldap3.protocol.formatters.formatters.format_sid(self._ldap_connection.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logging.error('User not found in LDAP: %s' % accountName)
            return False, ''

    def sid_to_str(self, sid):
        # code from Netexec
        try:
            # revision
            revision = int(sid[0])
            # count of sub authorities
            sub_authorities = int(sid[1])
            # big endian
            identifier_authority = int.from_bytes(sid[2:8], byteorder="big")
            # If true then it is represented in hex
            if identifier_authority >= 2**32:
                identifier_authority = hex(identifier_authority)

            # loop over the count of small endians
            sub_authority = "-" + "-".join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder="little")) for i in range(sub_authorities)])
            return "S-" + str(revision) + "-" + str(identifier_authority) + sub_authority
        except Exception:
            pass
        return sid

    def get_domain_sid(self):
        self._ldap_connection.search(search_base=self._baseDN, 
                            search_filter="(&(objectClass=domainDNS))",
                            search_scope=ldap3.SUBTREE,
                            attributes=['objectSid'])

        if self._ldap_connection.entries:
            domain_sid = self._ldap_connection.entries[0].objectSid.value
            if self.use_kerberos:
                domain_sid = self.sid_to_str(domain_sid)
            return domain_sid
        else:
            logging.error("Unable to retrieve domain SID")

    def get_group_from_primary_group_id(self, primary_group_id, object_class):
        domain_sid = self.get_domain_sid()
        group_sid = f"{domain_sid}-{primary_group_id}"
        search_filter = f"(&(objectClass=group)(objectSid={group_sid}))"
        self._ldap_connection.search(search_base=self._baseDN, 
                                    search_filter=search_filter, 
                                    search_scope=ldap3.SUBTREE, 
                                    attributes=['sAMAccountName'])

        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].sAMAccountName.value
        else:
            logging.error(f"No group found with RID '{primary_group_id}'")

    def get_samaccountname_from_dn(self, dn, object_class):
        search_filter = f"(&(objectClass={escape_filter_chars(object_class)})(distinguishedName={escape_filter_chars(dn)}))"

        self._ldap_connection.search(search_base=self._baseDN,
                                    search_filter=search_filter,
                                    search_scope=ldap3.SUBTREE,
                                    attributes=['samaccountname'])
        
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].sAMAccountName.value
        else:
            logging.error(f"No sAMAccountName found for DN '{dn}'")

    def get_samaccountname_from_sid(self, sid):
        search_filter = f"(objectSid={escape_filter_chars(sid)})"

        self._ldap_connection.search(search_base=self._baseDN,
                                    search_filter=search_filter,
                                    search_scope=ldap3.SUBTREE,
                                    attributes=['samaccountname'])
        
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].sAMAccountName.value
        else:
            logging.error(f"No sAMAccountName found for SID '{sid}'")

    def get_dn_from_samaccountname(self, samaccountname, object_class):
        search_filter = f"(&(objectClass={escape_filter_chars(object_class)})(sAMAccountName={escape_filter_chars(samaccountname)}))"

        self._ldap_connection.search(search_base=self._baseDN,
                                    search_filter=search_filter,
                                    search_scope=ldap3.SUBTREE,
                                    attributes=['distinguishedName'])
        
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].distinguishedName.value
        else:
            logging.error(f"No DN found for sAMAccountName '{samaccountname}'")
    
    def get_dn_from_displayname(self, display_name, object_class):
        search_filter = f"(&(objectClass={escape_filter_chars(object_class)})(displayName={escape_filter_chars(display_name)}))"

        self._ldap_connection.search(search_base=self._baseDN,
                                    search_filter=search_filter,
                                    search_scope=ldap3.SUBTREE,
                                    attributes=['distinguishedName'])
        
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].distinguishedName.value
        else:
            logging.error(f"No DN found for displayName '{display_name}'")

    def get_dn_from_sid(self, sid):
        search_filter = f"(objectSid={escape_filter_chars(sid)})"

        self._ldap_connection.search(search_base=self._baseDN,
                                    search_filter=search_filter,
                                    search_scope=ldap3.SUBTREE,
                                    attributes=['distinguishedName'])
        
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].distinguishedName.value
        else:
            logging.error(f"No DN found for SID '{sid}'")

    def get_sid_info(self, sid):
            self._ldap_connection.search(self._baseDN, '(objectSid=%s)' % escape_filter_chars(sid), attributes=['samaccountname'])
            try:
                dn = self._ldap_connection.entries[0].entry_dn
                samname = self._ldap_connection.entries[0]['samaccountname']
                return dn, samname
            except IndexError:
                logging.error('SID not found in LDAP: %s' % sid)
                return False

    def domaindump(self):
        # TODO: improve code logic
        server = ldap3.Server(self.target, get_info=ldap3.ALL)
        connection = ldap3.Connection(server)
        try:
            connection.bind()
            connection.search(search_base='', search_filter='(objectClass=*)', search_scope=ldap3.BASE, attributes=['namingContexts'])
            
            self._baseDN = server.info.other["defaultNamingContext"][0]
            logging.debug(f"baseDN retrieved from anonymous bind: {self._baseDN}")
            if self.domain is None:
                self.domain = self._baseDN.replace("DC=", "").replace(",", ".")
                logging.debug(f"Domain name retrieved from anonymous bind: {self.domain}")
            self.configuration_path = server.info.other["configurationNamingContext"][0]
            logging.debug(f"Configuration path retrieved from anonymous bind: {self.configuration_path}")

        except Exception:
            logging.error("Error trying to bind anonymously, please define domain name with -d option")
            raise LDAPAuthenticationError("Failed to retrieve domain info via anonymous bind")
        


