"""
LDAP connection and authentication for pwnAD.

Responsible for:
  - Establishing LDAP/LDAPS connections (NTLM, Kerberos, SChannel, Simple)
  - CRUD wrappers over the underlying ldap3 connection
  - Domain bootstrap (anonymous bind to retrieve baseDN)

Resolver/helper methods are provided by LDAPHelpersMixin (ldap_helpers.py).
The Kerberos GSS-API sealing socket is in kerberos_seal.py.
"""
import datetime
import ldap3
from ldap3.utils.conv import escape_filter_chars
import logging
import os
import ssl
import struct
import tempfile
from typing import Any, List, Optional, Union

from pwnAD.lib.certificate import key_to_pem, cert_to_pem, load_pfx, rsa, x509
from pwnAD.lib.constants import (
    LDAP_PORT, LDAPS_PORT,
    KRB5_KEY_USAGE_AP_REQ_AUTHENTICATOR, KRB5_GSS_FLAGS,
    LDAP_RESULT_SUCCESS, LDAP_RESULT_STRONGER_AUTH_REQUIRED, LDAP_RESULT_INVALID_CREDENTIALS,
)
from pwnAD.lib.kerberos_seal import KerberosSealSocket as _KerberosSealSocket
from pwnAD.lib.ldap_helpers import LDAPHelpersMixin

# Kerberos imports
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


class LDAPAuthenticationError(Exception):
    """Raised when LDAP authentication fails"""
    pass


class LDAPConnection(LDAPHelpersMixin):
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
            pfx: str = None,
            pfx_pass=None,
            key: rsa.RSAPublicKey = None,
            cert: x509.Certificate = None,
            use_kerberos=None,
            kdcHost=None,
            _do_tls=False,
            port=None
    ):
        self.target = target
        self.domain = domain
        self._baseDN = _baseDN
        self.configuration_path = configuration_path
        self.ldap_user = ldap_user
        self.ldap_pass = ldap_pass
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.pfx = pfx
        self.pfx_pass = pfx_pass
        self.key = key
        self.cert = cert
        self.use_kerberos = use_kerberos
        self.kdcHost = kdcHost
        self._do_tls = _do_tls
        self.port = port

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
            self.port = LDAPS_PORT if self._do_tls else LDAP_PORT

    # ------------------------------------------------------------------
    # Authentication methods
    # ------------------------------------------------------------------

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
        return struct.pack('<I', 16) + b'\x00' * 16 + struct.pack('<I', KRB5_GSS_FLAGS)

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
            user = '' if self.ldap_user is None else self.user  # Case when only -k is provided without username
            self.domain, self.user, TGT, TGS = CCache.parseFile(self.domain, user, target)

        # First of all, we need to get a TGT for the user
        userName = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    userName, self.ldap_pass, self.domain,
                    self.lmhash, self.nthash, self.aesKey, self.kdcHost
                )
        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

        if TGS is None:
            serverName = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                serverName, self.domain, self.kdcHost, tgt, cipher, sessionKey
            )
        else:
            tgs = TGS['KDC_REP']
            cipher = TGS['cipher']
            sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP
        blob = SPNEGO_NegTokenInit()
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
        if seal_and_sign:
            authenticator['seq-number'] = 0

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, KRB5_KEY_USAGE_AP_REQ_AUTHENTICATOR, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = encoder.encode(apReq)

        request = ldap3.operation.bind.bind_operation(
            ldap_connection.version, ldap3.SASL, self.user, None, 'GSS-SPNEGO', blob.getData()
        )

        # Done with the Kerberos saga, now let's get into LDAP
        if ldap_connection.closed:  # try to open connection if closed
            ldap_connection.open(read_server_info=False)

        ldap_connection.sasl_in_progress = True
        response = ldap_connection.post_send_single_response(ldap_connection.send('bindRequest', request, None))
        ldap_connection.sasl_in_progress = False

        result_code = response[0]['result']

        if result_code == LDAP_RESULT_STRONGER_AUTH_REQUIRED:  # strongAuthRequired – server enforces LDAP signing
            logging.debug('Server requires LDAP signing')
            if not seal_and_sign:
                logging.debug('Retrying with Kerberos GSS-API sealing')
                self._kerberos_auth(ldap_scheme, seal_and_sign=True, useCache=useCache)
                return
            if ldap_scheme != 'ldaps':
                logging.debug('GSS-API sealing failed, falling back to LDAPS')
                self._do_tls = True
                self.port = LDAPS_PORT
                self._kerberos_auth('ldaps', seal_and_sign=False, useCache=useCache)
                return
            raise LDAPAuthenticationError(f"Server requires LDAP signing: {response}")

        elif result_code == LDAP_RESULT_INVALID_CREDENTIALS:
            raise LDAPAuthenticationError(f"Kerberos authentication failed (invalidCredentials): {response}")

        elif result_code != LDAP_RESULT_SUCCESS:
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

            ldap_server_kwargs = {
                'use_ssl': self.port == 636,
                'port': self.port,
                'get_info': ldap3.ALL,
                'tls': tls,
            }
            ldap_server = ldap3.Server(self.target, **ldap_server_kwargs)
            ldap_connection_kwargs = dict()

            if self.port == 389:
                logging.debug("testing StartTLS connection")
                ldap_connection_kwargs = {
                    'authentication': ldap3.SASL,
                    'sasl_mechanism': ldap3.EXTERNAL,
                    'auto_bind': ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                    'raise_exceptions': True,
                }

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
        ldap_connection_kwargs = {
            'user': self.user,
            'raise_exceptions': True,
            'authentication': ldap3.SIMPLE,
            'password': self.ldap_pass,
        }
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
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            raise LDAPAuthenticationError('Invalid Credentials')
        except ldap3.core.exceptions.LDAPBindError:
            # "password is mandatory in simple bind" when password is empty
            raise LDAPAuthenticationError('Invalid Credentials')

        who_am_i = ldap_connection.extend.standard.who_am_i()
        logging.debug(f"Successfully connected to LDAP server as {who_am_i}")

        self._ldap_server = ldap_server
        self._ldap_connection = ldap_connection

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
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
            try:
                self._ntlm_auth(ldap_scheme)
            except LDAPAuthenticationError:
                # Don't fallback to simple auth if password is empty (simple bind doesn't support it)
                if not self.ldap_pass:
                    raise
                logging.debug("Error while trying to connect with NTLM authentication, falling back to simple authentication")
                self._simple_auth(ldap_scheme)

    def start_tls(self) -> None:
        if not self._ldap_connection.tls_started and not self._ldap_connection.server.ssl:
            logging.info('Sending StartTLS command...')
            try:
                self._ldap_connection.start_tls()
                self._do_tls = True
                logging.info('StartTLS succeded, you are now connected through a TLS channel')
            except Exception as e:
                logging.error(f"StartTLS failed, error :{e}")
        else:
            logging.error('It seems you are already connected through a TLS channel.')

    def is_connected(self) -> bool:
        """Check if the LDAP connection is still alive."""
        try:
            return (self._ldap_connection is not None and
                    self._ldap_connection.bound and
                    not self._ldap_connection.closed)
        except Exception:
            return False

    def rebind(self) -> bool:
        """Attempt to rebind the LDAP connection.

        For NTLM/SIMPLE a bare ``bind()`` is enough. Kerberos and certificate
        (SChannel) auth cannot be replayed with ``bind()`` alone — the SASL/
        GSS-API handshake and sealed socket must be rebuilt — so those go
        straight through the full ``connect()`` dispatch.

        Returns:
            bool: True if rebind succeeded, False otherwise.
        """
        try:
            can_simple_rebind = (
                not self.use_kerberos
                and not self._do_certificate
                and self._ldap_connection is not None
            )
            if can_simple_rebind:
                try:
                    if self._ldap_connection.bound:
                        self._ldap_connection.unbind()
                    self._ldap_connection.bind()
                    logging.info("[*] Successfully performed LDAP rebind")
                    return True
                except Exception as e:
                    logging.debug(f"Simple rebind failed: {e}, attempting full reconnection")

            self.connect()
            logging.info("[*] Successfully reconnected to LDAP server")
            return True

        except Exception as e:
            logging.error(f"[-] Failed to rebind LDAP connection: {e}")
            return False

    # ------------------------------------------------------------------
    # CRUD wrappers
    # ------------------------------------------------------------------

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

    def exists(self, account: str) -> bool:
        self._ldap_connection.search(self._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(account))
        return len(self._ldap_connection.entries) == 1

    def get(self, user_or_computer: str):
        self._ldap_connection.search(
            self._baseDN,
            '(sAMAccountName=%s)' % escape_filter_chars(user_or_computer),
            search_scope=ldap3.SUBTREE,
        )
        return self._ldap_connection.entries[0]

    # ------------------------------------------------------------------
    # Domain bootstrap
    # ------------------------------------------------------------------

    def domaindump(self) -> None:
        """Determine baseDN and configuration path.

        Prefers an anonymous bind to read the authoritative naming contexts,
        but many hardened DCs refuse anonymous binds. When that fails, fall
        back to deriving both values from the supplied domain name.
        """
        try:
            server = ldap3.Server(self.target, get_info=ldap3.ALL)
            connection = ldap3.Connection(server)
            connection.bind()
            connection.search(
                search_base='',
                search_filter='(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['namingContexts'],
            )
            self._baseDN = server.info.other["defaultNamingContext"][0]
            logging.debug(f"baseDN retrieved from anonymous bind: {self._baseDN}")
            if self.domain is None:
                self.domain = self._baseDN.replace("DC=", "").replace(",", ".")
                logging.debug(f"Domain name retrieved from anonymous bind: {self.domain}")
            self.configuration_path = server.info.other["configurationNamingContext"][0]
            logging.debug(f"Configuration path retrieved from anonymous bind: {self.configuration_path}")
            return
        except Exception as e:
            logging.debug(f"Anonymous bind failed ({e}), falling back to domain-derived baseDN")

        # Fallback: derive naming contexts from the provided domain name.
        if self.domain:
            self._baseDN = ",".join(f"DC={part}" for part in self.domain.split("."))
            self.configuration_path = f"CN=Configuration,{self._baseDN}"
            logging.debug(f"baseDN derived from domain '{self.domain}': {self._baseDN}")
        else:
            logging.error("Anonymous bind refused and no domain provided; specify the domain with -d")
            raise LDAPAuthenticationError(
                "Cannot determine baseDN: anonymous bind refused and no domain specified (-d)"
            )
