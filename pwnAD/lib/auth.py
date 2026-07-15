import logging
from typing import Optional
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
            domain: Optional[str] = None,
            dc_ip: Optional[str] = None,
            username: Optional[str] = None,
            password: Optional[str] = None,
            hashes: Optional[str] = None,
            aesKey: Optional[str] = None,
            pfx: Optional[str] = None,
            pfx_pass: Optional[str] = None,
            cert: Optional[x509.Certificate] = None,
            key: Optional[rsa.RSAPublicKey] = None,
            use_kerberos: Optional[bool] = None,
            kdcHost: Optional[str] = None,
            port: Optional[int] = None,
            no_hash: Optional[bool] = None,
            _do_tls: bool = False,
            principalType: constants.PrincipalNameType = constants.PrincipalNameType.NT_PRINCIPAL,
            spn: Optional[str] = None,
            altservice: Optional[str] = None,
            impersonate: Optional[str] = None,
            additional_ticket: Optional[str] = None,
            u2u: Optional[bool] = None,
            no_s4u2proxy: Optional[bool] = None,
            force_forwardable: Optional[bool] = None,
            renew: Optional[bool] = None,
            dmsa: Optional[bool] = None,
    ) -> None:
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
        self.dmsa=dmsa

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

    def ldap_authentication(self) -> LDAPConnection:

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
        
    def _extract_username_from_cert(self, cert):
        """Extract username from certificate SAN UPN or subject CN."""
        # Try SAN UPN first (most reliable for user certs)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san.value:
                if isinstance(name, x509.OtherName) and name.type_id.dotted_string == '1.3.6.1.4.1.311.20.2.3':
                    upn = name.value[2:].decode(errors='replace')
                    return upn.split('@')[0]
        except (x509.ExtensionNotFound, Exception):
            pass
        # Fall back to subject CN
        try:
            for attr in cert.subject:
                if attr.oid == x509.oid.NameOID.COMMON_NAME:
                    cn = attr.value
                    if '.' in cn:
                        return cn.split('.')[0] + '$'
                    return cn
        except Exception:
            pass
        return None

    def kerberos_authentication(self) -> None:

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

        if self.cert is not None and self.username is None:
            extracted = self._extract_username_from_cert(self.cert)
            if extracted:
                self.username = extracted
                logging.info(f'[*] Username extracted from certificate: {self.username}')
            else:
                raise ValueError('No username provided and could not extract from certificate. Use -u to specify.')      
