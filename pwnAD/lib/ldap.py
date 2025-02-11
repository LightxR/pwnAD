import datetime 
import ldap3
from ldap3.utils.conv import escape_filter_chars
import logging
import os
import ssl
import sys
import tempfile
from typing import Any, List, Union

from pwnAD.lib.certificate import key_to_pem, cert_to_pem, load_pfx, rsa, x509

# Kerberos auth
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type.univ import noValue        
from impacket.krb5.ccache import CCache
from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
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
            logging.debug(f"LDAP binding parameters: server = {self.target} / user = {self.user} / hash = {ldap_connection_kwargs['password']}")

        else:
            ldap_connection_kwargs['password'] = self.ldap_pass
            logging.debug(f"LDAP binding parameters: server = {self.target} / user = {self.user} / password = {ldap_connection_kwargs['password']}")

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
                sys.exit(-1)

        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
                logging.warning('Server returns LDAPInvalidCredentialsResult')
                # https://github.com/zyn3rgy/LdapRelayScan#ldaps-channel-binding-token-requirements
                if 'AcceptSecurityContext error, data 80090346' in ldap_connection.result['message'] and not self._tls_channel_binding_supported:
                        
                    if self.lmhash and self.nthash:
                        logging.critical('Server requires Channel Binding Token and your ldap3 install does not support it. '
                                                'Please install https://github.com/cannatag/ldap3/pull/1087, try another authentication method, '
                                                'or use a password, not a hash, to authenticate.')
                        sys.exit(-1)
                    
                    else:
                        logging.debug('Server requires Channel Binding Token but you are using password authentication,'
                                            ' falling back to SIMPLE authentication, hoping LDAPS port is open')
                        self._simple_auth('ldaps')
                        return
                        
                elif self._tls_channel_binding_supported == True and not tls_channel_binding:
                    logging.warning('Falling back to TLS with channel binding')
                    self._ntlm_auth(ldap_scheme, tls_channel_binding=True)
                    return
                
                else:
                    logging.critical('Invalid Credentials')
                    sys.exit(-1)

        except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult:
            logging.warning('Server returns LDAPStrongerAuthRequiredResult')
            
            if not self._sign_and_seal_supported:
                logging.warning('Sealing not available, falling back to LDAPS')
                self._ntlm_auth('ldaps')
                return
            else:
                logging.warning('Falling back to NTLM sealing')
                self._ntlm_auth(ldap_scheme, seal_and_sign=True)
                return

        who_am_i = ldap_connection.extend.standard.who_am_i()
        logging.debug(f"Successfully connected to LDAP server as {who_am_i}")

        self._ldap_server = ldap_server
        self._ldap_connection = ldap_connection
        
        return ldap_server, ldap_connection

    def _kerberos_auth(self, ldap_scheme, seal_and_sign=False, TGT=None, TGS=None, useCache=True):

        logging.debug(f"LDAP authentication with Kerberos: ldap_scheme = {ldap_scheme} / seal_and_sign = {seal_and_sign}")
        self.user = f"{self.ldap_user}@{self.domain.upper()}"
        ldap_connection_kwargs = {'user': self.user}

        if seal_and_sign:
            ldap_connection_kwargs['session_security'] = ldap3.ENCRYPT

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

        opts = []
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self.domain
        seq_set(authenticator, 'cname', userName.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

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
        if response[0]['result'] != 0:
            raise Exception(response)

        ldap_connection.bound = True
        ldap_connection.raise_exceptions = True

        who_am_i = ldap_connection.extend.standard.who_am_i()

        if not who_am_i:
            logging.critical('Kerberos authentication failed')
            sys.exit(-1)
        logging.debug(f"Successfully connected to the LDAP as {who_am_i}")

        self._ldap_server = ldap_server
        self._ldap_connection = ldap_connection

    def _schannel_auth(self, ldap_scheme):
        logging.debug(f"LDAP authentication with SChannel: ldap_scheme = {ldap_scheme} with port {self.port}")

        if self.pfx:
            with open(self.pfx, "rb") as f:
                if self.pfx_pass:
                    key, cert = load_pfx(f.read(), self.pfx_pass.encode())
                else:
                    key, cert = load_pfx(f.read())

            key_file = tempfile.NamedTemporaryFile(delete=False)
            key_file.write(key_to_pem(key))
            key_file.close()

            cert_file = tempfile.NamedTemporaryFile(delete=False)
            cert_file.write(cert_to_pem(cert))
            cert_file.close()        
            
            tls = ldap3.Tls(local_private_key_file=key_file.name, local_certificate_file=cert_file.name, validate=ssl.CERT_NONE)
        else:
            tls = ldap3.Tls(local_private_key_file=self.key, local_certificate_file=self.cert, validate=ssl.CERT_NONE)

        ldap_server_kwargs = {'use_ssl': self.port == 636,
                              'port': self.port,
                              'get_info': ldap3.ALL,
                              'tls': tls}

        ldap_server = ldap3.Server(self.target, **ldap_server_kwargs)

        ldap_connection_kwargs = dict()

        try: 
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
        except Exception as e:
            return
        
        who_am_i = ldap_connection.extend.standard.who_am_i()
        self.user = who_am_i
        if not who_am_i:
            logging.critical('Certificate authentication failed')
            sys.exit(-1)

        logging.debug(f"Successfully connected to LDAP server as {who_am_i}")
        self._ldap_server = ldap_server
        self._ldap_connection = ldap_connection


        if self.pfx:
            os.unlink(key_file.name)
            os.unlink(cert_file.name)

    def _simple_auth(self, ldap_scheme):
        logging.debug(f"LDAP authentication with SIMPLE: ldap_scheme = {ldap_scheme}")
        ldap_server = ldap3.Server(f"{ldap_scheme}://{self.target}")
        self.user = f"{self.ldap_user}@{self.domain}"
        ldap_connection_kwargs = {'user': self.user, 'raise_exceptions': True, 'authentication': ldap3.SIMPLE}

        ldap_connection_kwargs['password'] = self.ldap_pass
        logging.debug(f"LDAP binding parameters: server = {self.target} / user = {self.user} / password = {ldap_connection_kwargs['password']}")

        try:
            ldap_connection = ldap3.Connection(ldap_server, **ldap_connection_kwargs)
            ldap_connection.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
                logging.critical(e)
                if self._do_tls:
                    logging.critical('TLS negociation failed, this error is mostly due to your host '
                                          'not supporting SHA1 as signing algorithm for certificates')
                sys.exit(-1)
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
            logging.critical('Invalid Credentials')
            sys.exit(-1)

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
            except:
                logging.error("Error while trying to connect with NTLM authentication, falling back to simple authentication")
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
        self._ldap_connection.search(self._baseDN, '(sAMAccountName=%s)' % account)
        return len(self._ldap_connection.entries) ==1
    
    def get(self, user_or_computer):
        self._ldap_connection.search(self._baseDN, '(sAMAccountName=%s)' % user_or_computer, search_scope=ldap3.SUBTREE)
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
        search_filter = f"(&(objectClass={object_class})(distinguishedName={dn}))"

        self._ldap_connection.search(search_base=self._baseDN, 
                                    search_filter=search_filter, 
                                    search_scope=ldap3.SUBTREE, 
                                    attributes=['samaccountname'])
        
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].sAMAccountName.value
        else:
            logging.error(f"No sAMAccountName found for DN '{dn}'")

    def get_samaccountname_from_sid(self, sid):
        search_filter = f"(objectSid={sid})"

        self._ldap_connection.search(search_base=self._baseDN, 
                                    search_filter=search_filter, 
                                    search_scope=ldap3.SUBTREE, 
                                    attributes=['samaccountname'])
        
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].sAMAccountName.value
        else:
            logging.error(f"No sAMAccountName found for SID '{sid}'")

    def get_dn_from_samaccountname(self, samaccountname, object_class):
        search_filter = f"(&(objectClass={object_class})(sAMAccountName={samaccountname}))"

        self._ldap_connection.search(search_base=self._baseDN, 
                                    search_filter=search_filter, 
                                    search_scope=ldap3.SUBTREE, 
                                    attributes=['distinguishedName'])
        
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].distinguishedName.value
        else:
            logging.error(f"No DN found for sAMAccountName '{samaccountname}'")
    
    def get_dn_from_displayname(self, display_name, object_class):
        search_filter = f"(&(objectClass={object_class})(displayName={display_name}))"

        self._ldap_connection.search(search_base=self._baseDN, 
                                    search_filter=search_filter, 
                                    search_scope=ldap3.SUBTREE, 
                                    attributes=['distinguishedName'])
        
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].distinguishedName.value
        else:
            logging.error(f"No DN found for displayName '{display_name}'")

    def get_dn_from_sid(self, sid):
        search_filter = f"(objectSid={sid})"

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
        #todo : improve code logic
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
            sys.exit(-1)
        


