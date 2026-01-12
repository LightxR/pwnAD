import logging
from impacket.krb5 import constants

from pwnAD.lib.utils import parse_lm_nt_hashes
from pwnAD.lib.ldap import LDAPConnection
from pwnAD.lib.certificate import (  
    load_pfx,
    rsa,
    x509,
    pem_to_cert,
    pem_to_key
)


class Authenticate:
    def __init__(
            self, 
            domain=None, 
            dc_ip=None, 
            username=None, 
            password=None, 
            hashes=None, 
            aesKey=None, 
            pfx=None, 
            pfx_pass=None, 
            cert: x509.Certificate=None,
            key: rsa.RSAPublicKey=None,
            use_kerberos=None, 
            kdcHost=None, 
            port=None,
            no_hash=None,
            _do_tls=False,
            principalType=constants.PrincipalNameType.NT_PRINCIPAL,
            spn=None,
            altservice=None,
            impersonate=None,
            additional_ticket=None,
            u2u=None,
            no_s4u2proxy=None,
            force_forwardable=None,
            renew=None
    ):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.hashes = hashes
        self.aesKey = aesKey
        self.pfx = pfx
        self.pfx_pass = pfx_pass
        self.key = key
        self.cert = cert
        self.use_kerberos = use_kerberos
        self.kdcHost = kdcHost
        self.port=port
        self.no_hash=no_hash
        self._do_tls = _do_tls
        self.principalType = principalType
        self.spn=spn
        self.altservice=altservice
        self.impersonate=impersonate
        self.additional_ticket=additional_ticket
        self.u2u=u2u
        self.no_s4u2proxy=no_s4u2proxy
        self.force_forwardable=force_forwardable
        self.renew=renew

        self.lmhash, self.nthash = None, None
        if self.hashes is not None:
            if ":" not in self.hashes:
                self.hashes = ":" + self.hashes
            self.lmhash, self.nthash = parse_lm_nt_hashes(self.hashes)

        if self.aesKey is not None:
            self.use_kerberos = True
        if self.use_kerberos is True and self.kdcHost is None:
            logging.warning("Specify KDC's Hostname of FQDN using the argument --kdcHost")
            raise ValueError("KDC hostname must be specified when using Kerberos")

    def ldap_authentication(self):

        logging.debug("Authentication with LDAP")

        if self.use_kerberos:
            target_dc = self.kdcHost
        else:
            target_dc = (self.dc_ip if self.dc_ip is not None else self.domain)

        connection = LDAPConnection(
            target=target_dc,
            domain=self.domain,
            ldap_user=self.username,
            ldap_pass=self.password,
            lmhash=self.lmhash,
            nthash=self.nthash,
            aesKey=self.aesKey,
            pfx=self.pfx,
            pfx_pass=self.pfx_pass,
            key=self.key,
            cert=self.cert,
            use_kerberos=self.use_kerberos,
            kdcHost=self.kdcHost,
            _do_tls=self._do_tls,
            port=self.port
            ) 
        
        connection.connect()
        return connection
        
    def kerberos_authentication(self):

        if self.cert is not None and self.key is not None:
            with open(self.cert, "rb") as f:
                self.cert = f.read()
                self.cert= pem_to_cert(self.cert)
            with open(self.key, "rb") as f:
                self.key = f.read()
                self.key= pem_to_key(self.key)
        elif self.pfx is not None:
            with open(self.pfx, "rb") as f:
                self.key, self.cert = load_pfx(f.read())      
