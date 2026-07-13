"""Analysis routes for pwnAD - ACL abuse, privesc paths, ADCS scanner, delegation map, misconfigurations."""

import logging

import ldap3
from flask import Blueprint, render_template, request
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from impacket.ldap import ldaptypes

from pwnAD.lib.accesscontrol import (
    DACL_RIGHTS, WELL_KNOWN_SIDS, parse_ace, resolve_sid_to_name,
    get_rights_from_mask, ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_OBJECT,
)
from pwnAD.lib.adcs import analyze_adcs, get_user_sids, ESC_DEFINITIONS
from pwnAD.web.context import get_conn, base_context
from pwnAD.web.utils import LDAP_CONNECTION_ERRORS, ldap_search as _ldap_search

analysis_bp = Blueprint('analysis', __name__)

# Dangerous rights for ACL abuse detection
DANGEROUS_RIGHTS = [
    'GenericAll', 'FullControl', 'WriteDacl', 'WriteOwner', 'GenericWrite',
    'AllExtendedRights', 'DCSync', 'WriteMembers', 'AddMember',
    'ResetPassword', 'WriteSPN', 'WriteKeyCredentialLink', 'ReadGMSAPassword',
    'ReadLAPSPassword',
]

# Default SID prefixes to ignore (well-known high-privilege principals)
IGNORED_SID_SUFFIXES = ['-500', '-512', '-516', '-518', '-519', '-498']
IGNORED_SIDS = {'S-1-5-18', 'S-1-5-10', 'S-1-3-0'}



def _get_domain_sid(conn):
    results = _ldap_search(conn, '(objectClass=domain)', ['objectSid'], search_base=conn._baseDN)
    if results:
        sid = results[0]['attributes'].get('objectSid')
        if sid:
            return sid
    return None


def _is_default_principal(sid, domain_sid):
    if sid in IGNORED_SIDS:
        return True
    if sid in WELL_KNOWN_SIDS:
        return True
    if domain_sid:
        for suffix in IGNORED_SID_SUFFIXES:
            if sid == domain_sid + suffix:
                return True
    return False


def _get_security_descriptor(conn, target_dn):
    controls = security_descriptor_control(sdflags=0x04)
    conn._ldap_connection.search(
        search_base=target_dn,
        search_filter=f'(distinguishedName={escape_filter_chars(target_dn)})',
        attributes=['nTSecurityDescriptor'],
        controls=controls
    )
    if not conn._ldap_connection.entries:
        return None
    raw_attrs = conn._ldap_connection.entries[0].entry_raw_attributes
    if 'nTSecurityDescriptor' not in raw_attrs or not raw_attrs['nTSecurityDescriptor']:
        return None
    return ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_attrs['nTSecurityDescriptor'][0])


def _parse_dangerous_aces(conn, sd, domain_sid):
    findings = []
    if not sd or not sd['Dacl'] or not sd['Dacl'].aces:
        return findings
    for ace in sd['Dacl'].aces:
        if ace['AceType'] not in (ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_OBJECT):
            continue
        if ace['AceFlags'] & 0x10:  # INHERITED_ACE
            continue
        ace_info = parse_ace(ace)
        sid = ace_info['sid']
        if _is_default_principal(sid, domain_sid):
            continue
        object_type_guid = ace_info.get('object_type')
        rights = get_rights_from_mask(ace_info['access_mask'], object_type_guid)
        dangerous = [r for r in rights if r in DANGEROUS_RIGHTS]
        if not dangerous:
            mask = ace_info['access_mask']
            if mask & 0x10000000:
                dangerous = ['GenericAll']
            elif mask & 0x40000000:
                dangerous = ['GenericWrite']
            elif mask == 0x000F01FF:
                dangerous = ['FullControl']
            elif mask & 0x00040000:
                dangerous = ['WriteDacl']
            elif mask & 0x00080000:
                dangerous = ['WriteOwner']
        if dangerous:
            findings.append({
                'sid': sid,
                'trustee': resolve_sid_to_name(conn, sid),
                'rights': dangerous,
            })
    return findings


# ─── PAGE ROUTES ─────────────────────────────────────────────────────────────

@analysis_bp.route('/analysis/acl-abuse')
def acl_abuse_view():
    ctx = base_context('acl-abuse')
    return render_template('analysis_acl.html', **ctx)


@analysis_bp.route('/analysis/privesc')
def privesc_view():
    ctx = base_context('privesc')
    return render_template('analysis_privesc.html', **ctx)


@analysis_bp.route('/analysis/adcs-scan')
def adcs_scan_view():
    ctx = base_context('adcs-scan')
    return render_template('analysis_adcs_scan.html', **ctx)


@analysis_bp.route('/analysis/delegation')
def delegation_view():
    ctx = base_context('delegation')
    return render_template('analysis_delegation.html', **ctx)


@analysis_bp.route('/analysis/misconfig')
def misconfig_view():
    ctx = base_context('misconfig')
    return render_template('analysis_misconfig.html', **ctx)


# ─── HTMX API ENDPOINTS ─────────────────────────────────────────────────────

@analysis_bp.route('/analysis/api/acl-abuse')
def api_acl_abuse():
    conn = get_conn()
    scope = request.args.get('scope', 'all')

    scope_filters = {
        'users': '(&(objectCategory=person)(objectClass=user))',
        'computers': '(objectCategory=computer)',
        'groups': '(objectCategory=group)',
        'all': '(|(objectCategory=person)(objectCategory=computer)(objectCategory=group))',
    }
    ldap_filter = scope_filters.get(scope, scope_filters['all'])

    try:
        domain_sid = _get_domain_sid(conn)
        controls = security_descriptor_control(sdflags=0x04)
        objects = _ldap_search(conn, ldap_filter,
                              ['sAMAccountName', 'distinguishedName', 'objectClass', 'nTSecurityDescriptor'],
                              controls=controls)

        results = []
        for obj in objects:
            dn = obj['dn']
            sam = obj['attributes'].get('sAMAccountName', dn.split(',')[0])
            raw_sd = obj['attributes'].get('nTSecurityDescriptor')
            if not raw_sd:
                continue
            if isinstance(raw_sd, list):
                raw_sd = raw_sd[0]
            if isinstance(raw_sd, str):
                raw_sd = raw_sd.encode('latin-1')
            try:
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
            except Exception:
                continue

            findings = _parse_dangerous_aces(conn, sd, domain_sid)
            if findings:
                obj_classes = obj['attributes'].get('objectClass', [])
                if 'computer' in obj_classes:
                    obj_type = 'computer'
                elif 'group' in obj_classes:
                    obj_type = 'group'
                else:
                    obj_type = 'user'
                results.append({
                    'target': sam,
                    'target_dn': dn,
                    'target_type': obj_type,
                    'aces': findings,
                })

        return render_template('partials/analysis_acl_results.html', results=results, total_scanned=len(objects))

    except Exception as e:
        logging.error(f"ACL abuse scan error: {e}")
        return render_template('partials/analysis_acl_results.html', results=[], error=str(e), total_scanned=0)


@analysis_bp.route('/analysis/api/privesc')
def api_privesc():
    conn = get_conn()

    try:
        user_sids = get_user_sids(conn)
        domain_sid = _get_domain_sid(conn)
        current_user = (conn.ldap_user or '').lower()
        paths = []

        # 1. Get privileged group members (memberOf + primaryGroupID)
        priv_groups = {
            'Domain Admins': {
                'memberof': f'(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,{conn._baseDN})',
                'primary_gid': '(primaryGroupID=512)',
            },
            'Enterprise Admins': {
                'memberof': f'(memberOf:1.2.840.113556.1.4.1941:=CN=Enterprise Admins,CN=Users,{conn._baseDN})',
                'primary_gid': '(primaryGroupID=519)',
            },
            'Administrators': {
                'memberof': f'(memberOf:1.2.840.113556.1.4.1941:=CN=Administrators,CN=Builtin,{conn._baseDN})',
                'primary_gid': '(primaryGroupID=544)',
            },
        }

        admin_dns = set()
        admin_sams = {}
        for group_name, filters in priv_groups.items():
            for fltr in filters.values():
                try:
                    members = _ldap_search(conn, f'(&(objectCategory=person)(objectClass=user){fltr})',
                                           ['sAMAccountName', 'distinguishedName'])
                    for m in members:
                        dn = m['dn']
                        if dn not in admin_sams:
                            admin_dns.add(dn)
                            admin_sams[dn] = {'sam': m['attributes'].get('sAMAccountName', ''), 'group': group_name}
                except Exception as e:
                    logging.debug(f"Privesc group query error for {group_name}: {e}")

        # Also catch any adminCount=1 accounts not found above
        try:
            admin_count_results = _ldap_search(
                conn, '(&(objectClass=user)(adminCount=1)(!(sAMAccountName=krbtgt)))',
                ['sAMAccountName', 'distinguishedName'])
            for m in admin_count_results:
                dn = m['dn']
                if dn not in admin_sams:
                    admin_dns.add(dn)
                    admin_sams[dn] = {'sam': m['attributes'].get('sAMAccountName', ''), 'group': 'Privileged (adminCount=1)'}
        except Exception as e:
            logging.debug(f"Privesc adminCount query error: {e}")

        # 2. Find Kerberoastable admins
        kerb_admins = _ldap_search(
            conn,
            f'(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(adminCount=1))',
            ['sAMAccountName', 'servicePrincipalName', 'distinguishedName']
        )
        for ka in kerb_admins:
            ka_sam = ka['attributes'].get('sAMAccountName', '')
            if ka_sam.lower() == current_user:
                continue
            spn = ka['attributes'].get('servicePrincipalName', '')
            if isinstance(spn, list):
                spn = spn[0] if spn else ''
            paths.append({
                'type': 'kerberoast',
                'severity': 'critical',
                'target': ka['attributes'].get('sAMAccountName', ''),
                'target_dn': ka['dn'],
                'description': f"Kerberoastable admin account with SPN: {spn}",
                'exploit': 'Kerberoast the SPN, crack offline, authenticate as admin',
            })

        # 3. Find AS-REP roastable admins
        asrep_admins = _ldap_search(
            conn,
            f'(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(adminCount=1))',
            ['sAMAccountName', 'distinguishedName']
        )
        for aa in asrep_admins:
            if (aa['attributes'].get('sAMAccountName', '')).lower() == current_user:
                continue
            paths.append({
                'type': 'asreproast',
                'severity': 'critical',
                'target': aa['attributes'].get('sAMAccountName', ''),
                'target_dn': aa['dn'],
                'description': 'AS-REP roastable admin (DONT_REQUIRE_PREAUTH set)',
                'exploit': 'Request AS-REP without pre-authentication, crack offline',
            })

        # 4. ACL-based paths from current user to admins (exclude self)
        if user_sids:
            controls = security_descriptor_control(sdflags=0x04)
            for admin_dn, admin_info in admin_sams.items():
                if admin_info['sam'].lower() == current_user:
                    continue
                try:
                    sd = _get_security_descriptor(conn, admin_dn)
                    if not sd:
                        continue
                    if not sd['Dacl'] or not sd['Dacl'].aces:
                        continue
                    for ace in sd['Dacl'].aces:
                        if ace['AceType'] not in (ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_OBJECT):
                            continue
                        ace_sid = ace['Ace']['Sid'].formatCanonical()
                        if ace_sid in user_sids:
                            ace_info = parse_ace(ace)
                            obj_type = ace_info.get('object_type')
                            rights = get_rights_from_mask(ace_info['access_mask'], obj_type)
                            dangerous = [r for r in rights if r in DANGEROUS_RIGHTS]
                            if not dangerous:
                                mask = ace_info['access_mask']
                                if mask & 0x10000000:
                                    dangerous = ['GenericAll']
                                elif mask & 0x40000000:
                                    dangerous = ['GenericWrite']
                                elif mask & 0x00040000:
                                    dangerous = ['WriteDacl']
                                elif mask & 0x00080000:
                                    dangerous = ['WriteOwner']
                            if dangerous:
                                paths.append({
                                    'type': 'acl',
                                    'severity': 'critical',
                                    'target': admin_info['sam'],
                                    'target_dn': admin_dn,
                                    'description': f"You have {', '.join(dangerous)} over {admin_info['sam']} (member of {admin_info['group']})",
                                    'exploit': f"Use {dangerous[0]} to take over account",
                                })
                                break
                except Exception as e:
                    logging.debug(f"Privesc SD read error on {admin_dn}: {e}")
                    continue

        # 5. Unconstrained delegation (non-DC)
        unconstrained = _ldap_search(
            conn,
            '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
            ['sAMAccountName', 'distinguishedName']
        )
        for u in unconstrained:
            paths.append({
                'type': 'delegation',
                'severity': 'high',
                'target': u['attributes'].get('sAMAccountName', ''),
                'target_dn': u['dn'],
                'description': 'Unconstrained delegation - can capture TGTs of connecting users',
                'exploit': 'Coerce authentication from DC/admin, capture TGT via Rubeus/krbrelayx',
            })

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        paths.sort(key=lambda p: severity_order.get(p['severity'], 99))

        return render_template('partials/analysis_privesc_results.html', paths=paths, user_sids_count=len(user_sids))

    except Exception as e:
        logging.error(f"Privesc analysis error: {e}")
        return render_template('partials/analysis_privesc_results.html', paths=[], error=str(e), user_sids_count=0)


@analysis_bp.route('/analysis/api/adcs-scan')
def api_adcs_scan():
    conn = get_conn()

    try:
        result = analyze_adcs(conn, vulnerable_only=True, get_ca_config=False)
        templates = result.get('templates', [])
        cas = result.get('cas', [])
        summary = result.get('summary', {})

        vuln_templates = []
        for t in templates:
            if not t.is_vulnerable:
                continue
            vulns = []
            for v in t.vulnerabilities:
                esc_id = v.get('id', '')
                severity = 'critical' if esc_id in ('ESC1', 'ESC4') else 'high' if esc_id in ('ESC2', 'ESC3', 'ESC9') else 'medium'
                esc_def = ESC_DEFINITIONS.get(esc_id, {})
                vulns.append({
                    'id': esc_id,
                    'name': esc_def.get('name', esc_id),
                    'severity': severity,
                    'description': esc_def.get('description', v.get('description', '')),
                    'conditions': v.get('conditions', []),
                    'remediation': esc_def.get('remediation', ''),
                })
            vuln_templates.append({
                'name': t.name,
                'enabled': t.enabled,
                'can_enroll': t.can_enroll,
                'cas': t.enabled_on_cas,
                'vulnerabilities': vulns,
                'highest_severity': t.highest_severity,
            })

        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        vuln_templates.sort(key=lambda t: severity_order.get(t['highest_severity'], 99))

        return render_template('partials/analysis_adcs_results.html',
                               templates=vuln_templates, cas=cas, summary=summary)

    except Exception as e:
        logging.error(f"ADCS scan error: {e}")
        return render_template('partials/analysis_adcs_results.html',
                               templates=[], cas=[], summary={}, error=str(e))


@analysis_bp.route('/analysis/api/delegation')
def api_delegation():
    conn = get_conn()

    try:
        # Unconstrained (excluding DCs)
        unconstrained = _ldap_search(
            conn,
            '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
            ['sAMAccountName', 'distinguishedName', 'dNSHostName', 'objectClass']
        )

        # Constrained
        constrained = _ldap_search(
            conn,
            '(msDS-AllowedToDelegateTo=*)',
            ['sAMAccountName', 'distinguishedName', 'msDS-AllowedToDelegateTo',
             'userAccountControl', 'objectClass']
        )

        # RBCD
        rbcd = _ldap_search(
            conn,
            '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
            ['sAMAccountName', 'distinguishedName', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'objectClass']
        )

        # Process constrained delegation
        constrained_results = []
        for obj in constrained:
            attrs = obj['attributes']
            sam = attrs.get('sAMAccountName', '')
            spns = attrs.get('msDS-AllowedToDelegateTo', [])
            if isinstance(spns, str):
                spns = [spns]
            uac = attrs.get('userAccountControl', 0)
            if isinstance(uac, list):
                uac = uac[0] if uac else 0
            try:
                uac = int(uac)
            except (ValueError, TypeError):
                uac = 0
            protocol_transition = bool(uac & 0x1000000)  # TRUSTED_TO_AUTH_FOR_DELEGATION
            constrained_results.append({
                'sam': sam,
                'dn': obj['dn'],
                'targets': spns,
                'protocol_transition': protocol_transition,
                'type': 'computer' if 'computer' in attrs.get('objectClass', []) else 'user',
            })

        # Process RBCD
        rbcd_results = []
        for obj in rbcd:
            attrs = obj['attributes']
            sam = attrs.get('sAMAccountName', '')
            raw_sd = attrs.get('msDS-AllowedToActOnBehalfOfOtherIdentity')
            if isinstance(raw_sd, list):
                raw_sd = raw_sd[0]
            allowed_principals = []
            if raw_sd:
                if isinstance(raw_sd, str):
                    raw_sd = raw_sd.encode('latin-1')
                try:
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
                    if sd['Dacl'] and sd['Dacl'].aces:
                        for ace in sd['Dacl'].aces:
                            sid = ace['Ace']['Sid'].formatCanonical()
                            name = resolve_sid_to_name(conn, sid)
                            allowed_principals.append({'sid': sid, 'name': name})
                except Exception:
                    pass
            rbcd_results.append({
                'sam': sam,
                'dn': obj['dn'],
                'allowed_principals': allowed_principals,
                'type': 'computer' if 'computer' in attrs.get('objectClass', []) else 'user',
            })

        # Process unconstrained
        unconstrained_results = []
        for obj in unconstrained:
            attrs = obj['attributes']
            unconstrained_results.append({
                'sam': attrs.get('sAMAccountName', ''),
                'dn': obj['dn'],
                'dns': attrs.get('dNSHostName', ''),
                'type': 'computer' if 'computer' in attrs.get('objectClass', []) else 'user',
            })

        return render_template('partials/analysis_delegation_results.html',
                               unconstrained=unconstrained_results,
                               constrained=constrained_results,
                               rbcd=rbcd_results)

    except Exception as e:
        logging.error(f"Delegation map error: {e}")
        return render_template('partials/analysis_delegation_results.html',
                               unconstrained=[], constrained=[], rbcd=[], error=str(e))


@analysis_bp.route('/analysis/api/misconfig')
def api_misconfig():
    conn = get_conn()
    checks = []

    try:
        # 1. Machine Account Quota
        domain_results = _ldap_search(conn, '(objectClass=domain)',
                                      ['ms-DS-MachineAccountQuota'], search_base=conn._baseDN)
        maq = 0
        if domain_results:
            maq = domain_results[0]['attributes'].get('ms-DS-MachineAccountQuota', 0)
            if isinstance(maq, list):
                maq = maq[0] if maq else 0
            try:
                maq = int(maq)
            except (ValueError, TypeError):
                maq = 0
        checks.append({
            'name': 'Machine Account Quota',
            'description': 'ms-DS-MachineAccountQuota allows users to join computers to the domain',
            'severity': 'high' if maq > 0 else 'ok',
            'value': str(maq),
            'detail': f'Quota is {maq} — any user can create {maq} machine accounts' if maq > 0 else 'Quota is 0 (secure)',
            'remediation': 'Set ms-DS-MachineAccountQuota to 0 on the domain root',
        })

        # 2. AS-REP Roastable
        asrep = _ldap_search(conn,
                             '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                             ['sAMAccountName'])
        checks.append({
            'name': 'AS-REP Roastable Accounts',
            'description': 'Accounts with DONT_REQUIRE_PREAUTH can be roasted offline',
            'severity': 'high' if asrep else 'ok',
            'value': str(len(asrep)),
            'detail': f'{len(asrep)} accounts with DONT_REQUIRE_PREAUTH',
            'affected': [a['attributes'].get('sAMAccountName', '') for a in asrep[:20]],
            'remediation': 'Remove DONT_REQUIRE_PREAUTH flag unless absolutely necessary',
        })

        # 3. PASSWD_NOTREQD
        passwd_notr = _ldap_search(conn,
                                   '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))',
                                   ['sAMAccountName'])
        checks.append({
            'name': 'PASSWD_NOTREQD Accounts',
            'description': 'Accounts that can have an empty password',
            'severity': 'medium' if passwd_notr else 'ok',
            'value': str(len(passwd_notr)),
            'detail': f'{len(passwd_notr)} accounts with PASSWD_NOTREQD flag',
            'affected': [a['attributes'].get('sAMAccountName', '') for a in passwd_notr[:20]],
            'remediation': 'Remove PASSWD_NOTREQD flag from all accounts',
        })

        # 4. SID History
        sid_hist = _ldap_search(conn,
                                '(&(objectCategory=Person)(objectClass=User)(sidHistory=*))',
                                ['sAMAccountName'])
        checks.append({
            'name': 'Accounts with SID History',
            'description': 'SID History can be abused for privilege escalation across trusts',
            'severity': 'medium' if sid_hist else 'ok',
            'value': str(len(sid_hist)),
            'detail': f'{len(sid_hist)} accounts with SID History attribute',
            'affected': [a['attributes'].get('sAMAccountName', '') for a in sid_hist[:20]],
            'remediation': 'Remove SID History unless required for migration',
        })

        # 5. Reversible Encryption
        rev_enc = _ldap_search(conn,
                               '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=128))',
                               ['sAMAccountName'])
        checks.append({
            'name': 'Reversible Encryption',
            'description': 'Passwords stored with reversible encryption can be recovered in cleartext',
            'severity': 'high' if rev_enc else 'ok',
            'value': str(len(rev_enc)),
            'detail': f'{len(rev_enc)} accounts storing passwords with reversible encryption',
            'affected': [a['attributes'].get('sAMAccountName', '') for a in rev_enc[:20]],
            'remediation': 'Remove ENCRYPTED_TEXT_PWD_ALLOWED flag',
        })

        # 6. Unconstrained Delegation (non-DC)
        unconstrained = _ldap_search(conn,
                                     '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
                                     ['sAMAccountName'])
        checks.append({
            'name': 'Unconstrained Delegation',
            'description': 'Non-DC computers with unconstrained delegation can capture TGTs',
            'severity': 'critical' if unconstrained else 'ok',
            'value': str(len(unconstrained)),
            'detail': f'{len(unconstrained)} non-DC objects with unconstrained delegation',
            'affected': [a['attributes'].get('sAMAccountName', '') for a in unconstrained[:20]],
            'remediation': 'Replace with constrained delegation or RBCD where possible',
        })

        # 7. AdminCount without Protected Users
        admin_count_users = _ldap_search(conn,
                                         '(&(objectClass=user)(adminCount=1)(!(sAMAccountName=krbtgt)))',
                                         ['sAMAccountName', 'memberOf'])
        protected_users_dn = f'CN=Protected Users,CN=Users,{conn._baseDN}'
        unprotected_admins = []
        for u in admin_count_users:
            member_of = u['attributes'].get('memberOf', [])
            if isinstance(member_of, str):
                member_of = [member_of]
            if protected_users_dn not in member_of:
                unprotected_admins.append(u['attributes'].get('sAMAccountName', ''))
        checks.append({
            'name': 'Admins not in Protected Users',
            'description': 'Admin accounts not in Protected Users group lack credential theft mitigations',
            'severity': 'medium' if unprotected_admins else 'ok',
            'value': f'{len(unprotected_admins)}/{len(admin_count_users)}',
            'detail': f'{len(unprotected_admins)} admin accounts not in Protected Users group',
            'affected': unprotected_admins[:20],
            'remediation': 'Add privileged accounts to the Protected Users group',
        })

        # 8. LAPS not deployed (try both Legacy LAPS and Windows LAPS separately)
        all_computers = _ldap_search(conn, '(objectCategory=computer)', ['sAMAccountName'])
        laps_dns = set()
        for laps_filter in [
            '(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))',
            '(&(objectCategory=computer)(msLAPS-Password=*))',
        ]:
            try:
                for r in _ldap_search(conn, laps_filter, ['distinguishedName']):
                    laps_dns.add(r['dn'])
            except Exception:
                pass
        no_laps = len(all_computers) - len(laps_dns)
        checks.append({
            'name': 'LAPS Coverage',
            'description': 'Computers without LAPS have shared/static local admin passwords',
            'severity': 'medium' if no_laps > 0 else 'ok',
            'value': f'{len(laps_dns)}/{len(all_computers)}',
            'detail': f'{no_laps} computers without LAPS ({len(laps_dns)} with LAPS)'
                      + (' — LAPS may not be deployed' if not laps_dns else ''),
            'remediation': 'Deploy LAPS to all domain-joined computers',
        })

        # 9. Password Never Expires
        pwd_never_exp = _ldap_search(conn,
                                     '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                                     ['sAMAccountName'])
        checks.append({
            'name': 'Password Never Expires',
            'description': 'Accounts with non-expiring passwords increase exposure window',
            'severity': 'low' if pwd_never_exp else 'ok',
            'value': str(len(pwd_never_exp)),
            'detail': f'{len(pwd_never_exp)} enabled accounts with non-expiring passwords',
            'affected': [a['attributes'].get('sAMAccountName', '') for a in pwd_never_exp[:20]],
            'remediation': 'Implement password rotation policy for all accounts',
        })

        # 10. Kerberoastable privileged accounts
        kerb_admins = _ldap_search(conn,
                                   '(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(adminCount=1)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
                                   ['sAMAccountName'])
        checks.append({
            'name': 'Kerberoastable Admins',
            'description': 'Privileged accounts with SPNs can be Kerberoasted',
            'severity': 'critical' if kerb_admins else 'ok',
            'value': str(len(kerb_admins)),
            'detail': f'{len(kerb_admins)} privileged accounts vulnerable to Kerberoasting',
            'affected': [a['attributes'].get('sAMAccountName', '') for a in kerb_admins[:20]],
            'remediation': 'Remove SPNs from privileged accounts or use gMSA',
        })

        # 11. ADCS Vulnerable Templates
        try:
            adcs_result = analyze_adcs(conn, vulnerable_only=True, get_ca_config=False)
            vuln_templates = [t for t in adcs_result.get('templates', []) if t.is_vulnerable]
            vuln_names = [t.name for t in vuln_templates[:20]]
            checks.append({
                'name': 'ADCS Vulnerable Templates',
                'description': 'Certificate templates with exploitable misconfigurations (ESC1-ESC15)',
                'severity': 'critical' if vuln_templates else 'ok',
                'value': str(len(vuln_templates)),
                'detail': f'{len(vuln_templates)} certificate templates with known vulnerabilities',
                'affected': vuln_names,
                'remediation': 'Review and fix template permissions, EKU settings, and enrollment flags',
            })
        except Exception:
            checks.append({
                'name': 'ADCS Vulnerable Templates',
                'description': 'Certificate templates with exploitable misconfigurations',
                'severity': 'ok',
                'value': '?',
                'detail': 'Could not scan ADCS (no CA found or access denied)',
            })

        # 12. LAPS Readable by current user (try both Legacy and Windows LAPS separately)
        readable = []
        for laps_q, laps_attr in [
            ('(&(objectCategory=computer)(ms-MCS-AdmPwd=*))', 'ms-Mcs-AdmPwd'),
            ('(&(objectCategory=computer)(msLAPS-Password=*))', 'msLAPS-Password'),
        ]:
            try:
                results = _ldap_search(conn, laps_q, ['sAMAccountName', laps_attr])
                for r in results:
                    if r['attributes'].get(laps_attr):
                        readable.append(r['attributes'].get('sAMAccountName', ''))
            except Exception:
                pass
        checks.append({
            'name': 'LAPS Passwords Readable',
            'description': 'Computers where the current user can read LAPS local admin passwords',
            'severity': 'high' if readable else 'ok',
            'value': str(len(readable)),
            'detail': f'{len(readable)} computers with LAPS passwords readable by current user',
            'affected': readable[:20],
            'remediation': 'Review LAPS ACLs — restrict ms-Mcs-AdmPwd read access to designated admin groups',
        })

        # 13. Writable Objects
        try:
            writable_results = _ldap_search(conn,
                '(|(sAMAccountType=805306368)(sAMAccountType=805306369)(objectClass=group))',
                ['distinguishedName', 'allowedAttributesEffective', 'sDRightsEffective'])
            writable_objects = []
            for r in writable_results:
                attrs = r['attributes']
                has_perm = False
                sd_val = attrs.get('sDRightsEffective')
                if sd_val:
                    try:
                        if int(sd_val) & 0x05:
                            has_perm = True
                    except (ValueError, TypeError):
                        pass
                if not has_perm and attrs.get('allowedAttributesEffective'):
                    has_perm = True
                if has_perm:
                    dn = r.get('dn', '')
                    cn = dn.split(',')[0].replace('CN=', '') if dn else '?'
                    writable_objects.append(cn)
            checks.append({
                'name': 'Writable Objects',
                'description': 'AD objects (users/computers/groups) the current user can modify',
                'severity': 'medium' if len(writable_objects) > 10 else 'low' if writable_objects else 'ok',
                'value': str(len(writable_objects)),
                'detail': f'{len(writable_objects)} objects writable by current user',
                'affected': writable_objects[:20],
                'remediation': 'Audit DACLs and remove unnecessary write permissions',
            })
        except Exception:
            checks.append({
                'name': 'Writable Objects',
                'description': 'AD objects the current user can modify',
                'severity': 'ok',
                'value': '?',
                'detail': 'Could not enumerate writable objects',
            })

        # Sort: issues first, then ok
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'ok': 4}
        checks.sort(key=lambda c: severity_order.get(c['severity'], 99))

        issues_count = sum(1 for c in checks if c['severity'] != 'ok')
        return render_template('partials/analysis_misconfig_results.html',
                               checks=checks, issues_count=issues_count)

    except Exception as e:
        logging.error(f"Misconfig scan error: {e}")
        return render_template('partials/analysis_misconfig_results.html',
                               checks=[], issues_count=0, error=str(e))
