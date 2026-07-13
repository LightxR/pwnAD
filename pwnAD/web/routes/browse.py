import logging
import os

import ldap3
import csv
import io

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, Response
from ldap3.utils.conv import escape_filter_chars

from pwnAD.web.context import get_conn, base_context, paginate
from pwnAD.web.utils import (
    LDAP_CONNECTION_ERRORS, LDAP_SERVER_SHOW_DELETED_OID,
    ldap_search_with_retry, ldap_search, ldap_search_deleted,
)

browse_bp = Blueprint('browse', __name__)

OBJECT_TYPES = {
    'users': {
        'label': 'Users',
        'icon': 'fas fa-user',
        'filter': '(&(objectCategory=person)(objectClass=user))',
        'attributes': ['sAMAccountName', 'cn', 'memberOf', 'userAccountControl', 'distinguishedName', 'servicePrincipalName', 'adminCount'],
        'columns': [
            {'attr': 'sAMAccountName', 'label': 'Username'},
            {'attr': 'cn', 'label': 'Common Name'},
            {'attr': 'distinguishedName', 'label': 'Distinguished Name'},
        ],
        'filters': [
            {'key': 'enabled', 'label': 'Enabled', 'ldap': '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'},
            {'key': 'disabled', 'label': 'Disabled', 'ldap': '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'},
            {'key': 'admin', 'label': 'AdminCount=1', 'ldap': '(&(objectCategory=person)(objectClass=user)(adminCount=1))'},
            {'key': 'spn', 'label': 'Has SPN', 'ldap': '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'},
        ],
    },
    'groups': {
        'label': 'Groups',
        'icon': 'fas fa-users',
        'filter': '(objectCategory=group)',
        'attributes': ['sAMAccountName', 'description', 'member', 'distinguishedName'],
        'columns': [
            {'attr': 'sAMAccountName', 'label': 'Group Name'},
            {'attr': 'description', 'label': 'Description'},
            {'attr': 'member', 'label': 'Members'},
        ],
        'filters': [],
    },
    'computers': {
        'label': 'Computers',
        'icon': 'fas fa-desktop',
        'filter': '(objectCategory=computer)',
        'attributes': ['sAMAccountName', 'dNSHostName', 'operatingSystem', 'distinguishedName', 'userAccountControl', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
        'columns': [
            {'attr': 'sAMAccountName', 'label': 'Name'},
            {'attr': 'dNSHostName', 'label': 'DNS Hostname'},
            {'attr': 'operatingSystem', 'label': 'OS'},
        ],
        'filters': [
            {'key': 'servers', 'label': 'Servers', 'ldap': '(&(objectCategory=computer)(operatingSystem=*server*))'},
            {'key': 'dc', 'label': 'Domain Controllers', 'ldap': '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'},
            {'key': 'ws', 'label': 'Workstations', 'ldap': '(&(objectCategory=computer)(!(operatingSystem=*server*)))'},
        ],
    },
    'ous': {
        'label': 'OUs',
        'icon': 'fas fa-sitemap',
        'filter': '(objectCategory=organizationalUnit)',
        'attributes': ['name', 'description', 'distinguishedName'],
        'columns': [
            {'attr': 'name', 'label': 'Name'},
            {'attr': 'description', 'label': 'Description'},
            {'attr': 'distinguishedName', 'label': 'DN'},
        ],
        'filters': [],
    },
}

# Predefined queries for the sidebar and dashboard
QUERIES = {
    'kerberoastables': {
        'title': 'Kerberoastable Accounts',
        'icon': 'fas fa-fire',
        'filter': '(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
        'columns': ['sAMAccountName', 'servicePrincipalName', 'distinguishedName'],
        'attributes': ['sAMAccountName', 'servicePrincipalName', 'distinguishedName'],
    },
    'asreproastables': {
        'title': 'AS-REP Roastable Accounts',
        'icon': 'fas fa-bolt',
        'filter': '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
        'columns': ['sAMAccountName', 'distinguishedName'],
        'attributes': ['sAMAccountName', 'distinguishedName'],
    },
    'unconstrained': {
        'title': 'Unconstrained Delegation',
        'icon': 'fas fa-unlock',
        'filter': '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
        'columns': ['sAMAccountName', 'servicePrincipalName'],
        'attributes': ['sAMAccountName', 'servicePrincipalName', 'distinguishedName'],
    },
    'constrained': {
        'title': 'Constrained Delegation',
        'icon': 'fas fa-link',
        'filter': '(&(objectClass=user)(msDS-AllowedToDelegateTo=*))',
        'columns': ['sAMAccountName', 'msDS-AllowedToDelegateTo'],
        'attributes': ['sAMAccountName', 'msDS-AllowedToDelegateTo', 'distinguishedName'],
    },
    'admin_count': {
        'title': 'AdminCount=1',
        'icon': 'fas fa-shield-halved',
        'filter': '(&(objectClass=user)(adminCount=1)(!(sAMAccountName=krbtgt)))',
        'columns': ['sAMAccountName', 'displayName', 'distinguishedName'],
        'attributes': ['sAMAccountName', 'displayName', 'distinguishedName'],
    },
    'password_not_required': {
        'title': 'PASSWD_NOTREQD',
        'icon': 'fas fa-key',
        'filter': '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))',
        'columns': ['sAMAccountName', 'distinguishedName'],
        'attributes': ['sAMAccountName', 'distinguishedName'],
    },
    'rbcd': {
        'title': 'RBCD Configured',
        'icon': 'fas fa-arrows-turn-to-dots',
        'filter': '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
        'columns': ['sAMAccountName'],
        'attributes': ['sAMAccountName', 'distinguishedName'],
    },
    'protected_users': {
        'title': 'Protected Users',
        'icon': 'fas fa-user-shield',
        'filter': '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Protected Users,CN=Users,{base_dn}))',
        'columns': ['sAMAccountName'],
        'attributes': ['sAMAccountName', 'distinguishedName'],
    },
    'passwords_dont_expire': {
        'title': 'Pwd Never Expires',
        'icon': 'fas fa-hourglass',
        'filter': '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
        'columns': ['sAMAccountName'],
        'attributes': ['sAMAccountName', 'distinguishedName'],
    },
    'sid_history': {
        'title': 'SID History',
        'icon': 'fas fa-clock-rotate-left',
        'filter': '(&(objectCategory=Person)(objectClass=User)(sidHistory=*))',
        'columns': ['sAMAccountName'],
        'attributes': ['sAMAccountName', 'distinguishedName'],
    },
    'users_description': {
        'title': 'User Descriptions',
        'icon': 'fas fa-comment',
        'filter': '(&(objectCategory=user)(description=*))',
        'columns': ['sAMAccountName', 'description'],
        'attributes': ['sAMAccountName', 'description', 'distinguishedName'],
    },
    'machine_accounts': {
        'title': 'Machine Accounts',
        'icon': 'fas fa-server',
        'filter': '(objectCategory=computer)',
        'columns': ['sAMAccountName', 'dNSHostName', 'operatingSystem'],
        'attributes': ['sAMAccountName', 'dNSHostName', 'operatingSystem', 'distinguishedName'],
    },
}



_ldap_search = ldap_search
_ldap_search_deleted = ldap_search_deleted


def _count(conn, search_filter):
    """Quick count of objects matching a filter."""
    try:
        return len(_ldap_search(conn, search_filter, ['cn']))
    except Exception:
        return '?'


def _build_laps_filter(conn):
    """Build LAPS filter by probing which LAPS schema attributes exist."""
    parts = []
    for attr_filter in ['(ms-MCS-AdmPwd=*)', '(msLAPS-Password=*)', '(msLAPS-EncryptedPassword=*)']:
        try:
            _ldap_search(conn, f'(&(objectCategory=computer){attr_filter})', ['cn'], size_limit=1)
            parts.append(attr_filter)
        except Exception:
            pass
    if not parts:
        return '(&(objectCategory=computer)(ms-MCS-AdmPwd=*))'
    if len(parts) == 1:
        return f'(&(objectCategory=computer){parts[0]})'
    return f'(&(objectCategory=computer)(|{"".join(parts)}))'


def _ft_to_days(val):
    if val is None:
        return '?'
    try:
        total = abs(int(str(val)))
        days = total // (10_000_000 * 60 * 60 * 24)
        return days if days else '<1'
    except Exception:
        return '?'


def _ft_to_minutes(val):
    if val is None:
        return '?'
    try:
        total = abs(int(str(val)))
        minutes = total // (10_000_000 * 60)
        return minutes if minutes else '<1'
    except Exception:
        return '?'


@browse_bp.route('/')
def index():
    conn = get_conn()
    ctx = base_context('dashboard')
    ctx['base_dn'] = conn._baseDN
    ctx['domain'] = conn.domain
    return render_template('index.html', **ctx)


@browse_bp.route('/api/dashboard/counts')
def dashboard_counts():
    conn = get_conn()
    counts = {}
    for key, cfg in OBJECT_TYPES.items():
        counts[key] = _count(conn, cfg['filter'])
    ou_results = _ldap_search(conn, '(objectCategory=organizationalUnit)', ['distinguishedName'])
    counts['ous'] = len(ou_results)
    counts['privileged'] = _count(conn, '(&(objectClass=user)(adminCount=1)(!(sAMAccountName=krbtgt)))')
    return render_template('partials/dashboard_counts.html', counts=counts)


@browse_bp.route('/api/dashboard/queries')
def dashboard_queries():
    conn = get_conn()
    query_counts = {}
    for key, qcfg in QUERIES.items():
        query_counts[key] = _count(conn, qcfg['filter'].format(base_dn=conn._baseDN))
    return render_template('partials/dashboard_queries.html', query_counts=query_counts)


@browse_bp.route('/api/dashboard/domain-info')
def dashboard_domain_info():
    conn = get_conn()
    machine_quota = '?'
    password_policy = {}
    try:
        conn._ldap_connection.search(
            search_base=conn._baseDN,
            search_filter='(objectClass=*)',
            search_scope=ldap3.BASE,
            attributes=[
                'ms-DS-MachineAccountQuota',
                'minPwdLength', 'maxPwdAge', 'minPwdAge',
                'lockoutThreshold', 'lockoutDuration',
                'lockOutObservationWindow', 'pwdHistoryLength', 'pwdProperties',
            ],
        )
        if conn._ldap_connection.entries:
            entry = conn._ldap_connection.entries[0]
            machine_quota = entry['ms-DS-MachineAccountQuota'].value

            pwd_props = entry['pwdProperties'].value if 'pwdProperties' in entry else None
            password_policy = {
                'min_length': entry['minPwdLength'].value if 'minPwdLength' in entry else '?',
                'max_age_days': _ft_to_days(entry['maxPwdAge'].value if 'maxPwdAge' in entry else None),
                'min_age_days': _ft_to_days(entry['minPwdAge'].value if 'minPwdAge' in entry else None),
                'history_length': entry['pwdHistoryLength'].value if 'pwdHistoryLength' in entry else '?',
                'lockout_threshold': entry['lockoutThreshold'].value if 'lockoutThreshold' in entry else '?',
                'lockout_duration_min': _ft_to_minutes(entry['lockoutDuration'].value if 'lockoutDuration' in entry else None),
                'lockout_window_min': _ft_to_minutes(entry['lockOutObservationWindow'].value if 'lockOutObservationWindow' in entry else None),
                'complexity': bool(pwd_props and int(str(pwd_props)) & 1) if pwd_props is not None else '?',
            }
    except Exception:
        pass
    return render_template('partials/dashboard_domain_info.html', machine_quota=machine_quota, password_policy=password_policy, base_dn=get_conn()._baseDN, domain=get_conn().domain)


@browse_bp.route('/api/dashboard/policy')
def dashboard_policy():
    conn = get_conn()
    password_policy = {}
    try:
        conn._ldap_connection.search(
            search_base=conn._baseDN,
            search_filter='(objectClass=*)',
            search_scope=ldap3.BASE,
            attributes=[
                'minPwdLength', 'maxPwdAge',
                'lockoutThreshold', 'lockoutDuration',
                'pwdHistoryLength', 'pwdProperties',
            ],
        )
        if conn._ldap_connection.entries:
            entry = conn._ldap_connection.entries[0]
            pwd_props = entry['pwdProperties'].value if 'pwdProperties' in entry else None
            password_policy = {
                'min_length': entry['minPwdLength'].value if 'minPwdLength' in entry else '?',
                'max_age_days': _ft_to_days(entry['maxPwdAge'].value if 'maxPwdAge' in entry else None),
                'history_length': entry['pwdHistoryLength'].value if 'pwdHistoryLength' in entry else '?',
                'lockout_threshold': entry['lockoutThreshold'].value if 'lockoutThreshold' in entry else '?',
                'lockout_duration_min': _ft_to_minutes(entry['lockoutDuration'].value if 'lockoutDuration' in entry else None),
                'complexity': bool(pwd_props and int(str(pwd_props)) & 1) if pwd_props is not None else '?',
            }
    except Exception:
        pass
    return render_template('partials/dashboard_policy.html', password_policy=password_policy)


@browse_bp.route('/api/dashboard/attack-surface')
def dashboard_attack_surface():
    conn = get_conn()
    surface = {
        'kerberoastable': _count(conn, QUERIES['kerberoastables']['filter'].format(base_dn=conn._baseDN)),
        'asreproastable': _count(conn, QUERIES['asreproastables']['filter'].format(base_dn=conn._baseDN)),
        'unconstrained': _count(conn, QUERIES['unconstrained']['filter'].format(base_dn=conn._baseDN)),
        'constrained': _count(conn, QUERIES['constrained']['filter'].format(base_dn=conn._baseDN)),
        'rbcd': _count(conn, QUERIES['rbcd']['filter'].format(base_dn=conn._baseDN)),
        'passwd_notreqd': _count(conn, QUERIES['password_not_required']['filter'].format(base_dn=conn._baseDN)),
    }
    return render_template('partials/dashboard_attack_surface.html', surface=surface)


@browse_bp.route('/api/dashboard/tables')
def dashboard_tables():
    conn = get_conn()
    dc_results = _ldap_search(
        conn,
        '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
        ['sAMAccountName', 'servicePrincipalName']
    )
    domain_controllers = [
        {'name': r['attributes'].get('sAMAccountName', ''), 'spn': r['attributes'].get('servicePrincipalName', [])}
        for r in dc_results
    ]

    ca_list = []
    try:
        config_path = conn.configuration_path
        ca_results = _ldap_search(
            conn,
            '(&(objectClass=pKIEnrollmentService))',
            ['cn', 'dNSHostName', 'certificateTemplates'],
            search_base=f'CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_path}',
        )
        for r in ca_results:
            attrs = r.get('attributes', {})
            templates = attrs.get('certificateTemplates', [])
            if isinstance(templates, str):
                templates = [templates]
            ca_list.append({
                'name': attrs.get('cn', ''),
                'dns_host': attrs.get('dNSHostName', '-'),
                'templates_count': len(templates),
            })
    except Exception:
        pass

    return render_template('partials/dashboard_tables.html', domain_controllers=domain_controllers, certificate_authorities=ca_list)


@browse_bp.route('/api/dashboard/security-score')
def dashboard_security_score():
    conn = get_conn()
    issues = []
    total_checks = 0

    try:
        # Privileged accounts count
        admin_count = _count(conn, '(&(objectClass=user)(adminCount=1)(!(sAMAccountName=krbtgt)))')

        # Run checks and compute score
        checks = [
            ('Machine Account Quota > 0', lambda: int(_ldap_search(conn, '(objectClass=domain)', ['ms-DS-MachineAccountQuota'], search_base=conn._baseDN)[0]['attributes'].get('ms-DS-MachineAccountQuota', 0) or 0) > 0, 'high'),
            ('AS-REP Roastable accounts', lambda: _count(conn, '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))') > 0, 'high'),
            ('PASSWD_NOTREQD accounts', lambda: _count(conn, '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))') > 0, 'medium'),
            ('Unconstrained delegation (non-DC)', lambda: _count(conn, '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))') > 0, 'critical'),
            ('Kerberoastable admins', lambda: _count(conn, '(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(adminCount=1)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))') > 0, 'critical'),
            ('Reversible encryption', lambda: _count(conn, '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=128))') > 0, 'high'),
            ('SID History present', lambda: _count(conn, '(&(objectCategory=Person)(objectClass=User)(sidHistory=*))') > 0, 'medium'),
        ]

        severity_weight = {'critical': 20, 'high': 12, 'medium': 6}
        total_weight = sum(severity_weight[s] for _, _, s in checks)
        lost = 0

        for name, check_fn, severity in checks:
            total_checks += 1
            try:
                if check_fn():
                    issues.append({'name': name, 'severity': severity})
                    lost += severity_weight[severity]
            except Exception:
                pass

        score = max(0, 100 - int(lost * 100 / total_weight)) if total_weight > 0 else 100

        return render_template('partials/dashboard_security_score.html',
                               score=score, issues=issues, total_checks=total_checks,
                               admin_count=admin_count)
    except Exception as e:
        return render_template('partials/dashboard_security_score.html',
                               score=0, issues=[], total_checks=0, admin_count=0, error=str(e))


@browse_bp.route('/trusts')
def trusts_view():
    conn = get_conn()
    ctx = base_context('trusts')
    ctx['trusts'] = []

    try:
        results = _ldap_search(conn,
            '(objectClass=trustedDomain)',
            ['cn', 'flatName', 'trustPartner', 'trustDirection', 'trustType',
             'trustAttributes', 'securityIdentifier', 'whenCreated'])

        TRUST_DIRECTION = {0: 'Disabled', 1: 'Inbound', 2: 'Outbound', 3: 'Bidirectional'}
        TRUST_TYPE = {1: 'Non-AD', 2: 'Active Directory', 3: 'MIT Kerberos'}

        for r in results:
            attrs = r['attributes']
            direction_val = attrs.get('trustDirection', 0)
            type_val = attrs.get('trustType', 0)
            trust_attrs = attrs.get('trustAttributes', 0)
            try:
                direction_val = int(direction_val)
            except (ValueError, TypeError):
                direction_val = 0
            try:
                type_val = int(type_val)
            except (ValueError, TypeError):
                type_val = 0
            try:
                trust_attrs = int(trust_attrs)
            except (ValueError, TypeError):
                trust_attrs = 0

            flags = []
            if trust_attrs & 0x1: flags.append('NON_TRANSITIVE')
            if trust_attrs & 0x2: flags.append('UPLEVEL_ONLY')
            if trust_attrs & 0x4: flags.append('SID_FILTERING')
            if trust_attrs & 0x8: flags.append('FOREST_TRANSITIVE')
            if trust_attrs & 0x10: flags.append('CROSS_ORGANIZATION')
            if trust_attrs & 0x20: flags.append('WITHIN_FOREST')
            if trust_attrs & 0x40: flags.append('TREAT_AS_EXTERNAL')
            if trust_attrs & 0x200: flags.append('PIM_TRUST')

            sid_raw = attrs.get('securityIdentifier', '')
            if isinstance(sid_raw, bytes):
                try:
                    from ldap3.protocol.formatters.formatters import format_sid
                    sid_raw = format_sid(sid_raw)
                except Exception:
                    sid_raw = str(sid_raw)

            ctx['trusts'].append({
                'name': attrs.get('cn', ''),
                'partner': attrs.get('trustPartner', ''),
                'flat_name': attrs.get('flatName', ''),
                'direction': TRUST_DIRECTION.get(direction_val, f'Unknown ({direction_val})'),
                'direction_val': direction_val,
                'type': TRUST_TYPE.get(type_val, f'Unknown ({type_val})'),
                'sid': sid_raw or '',
                'flags': flags,
                'sid_filtering': bool(trust_attrs & 0x4),
                'within_forest': bool(trust_attrs & 0x20),
                'created': str(attrs.get('whenCreated', ''))[:10],
            })
    except Exception as e:
        ctx['error'] = str(e)

    return render_template('trusts.html', **ctx)


@browse_bp.route('/gpos')
def gpos_view():
    conn = get_conn()
    ctx = base_context('gpos')
    ctx['gpos'] = []

    try:
        results = _ldap_search(conn,
            '(objectClass=groupPolicyContainer)',
            ['displayName', 'cn', 'gPCFileSysPath', 'flags', 'whenCreated', 'whenChanged'])

        ou_results = _ldap_search(conn,
            '(gPLink=*)',
            ['distinguishedName', 'gPLink', 'name'])

        import re
        gpo_links = {}
        for ou in ou_results:
            gp_link = ou['attributes'].get('gPLink', '')
            if isinstance(gp_link, list):
                gp_link = gp_link[0] if gp_link else ''
            links = re.findall(r'\[LDAP://([^\]]+);(\d+)\]', str(gp_link), re.IGNORECASE)
            for link_dn, enforcement in links:
                link_dn_lower = link_dn.lower()
                if link_dn_lower not in gpo_links:
                    gpo_links[link_dn_lower] = []
                ou_name = ou['attributes'].get('name', '') or ou['dn'].split(',')[0]
                gpo_links[link_dn_lower].append({
                    'ou': ou_name,
                    'dn': ou['dn'],
                    'enforced': enforcement == '2',
                })

        for r in results:
            attrs = r['attributes']
            flags_val = attrs.get('flags', 0)
            try:
                flags_val = int(flags_val)
            except (ValueError, TypeError):
                flags_val = 0
            gpo_dn_lower = r['dn'].lower()
            ctx['gpos'].append({
                'name': attrs.get('displayName', '') or attrs.get('cn', ''),
                'guid': attrs.get('cn', ''),
                'dn': r['dn'],
                'sysvol_path': attrs.get('gPCFileSysPath', ''),
                'user_disabled': bool(flags_val & 1),
                'computer_disabled': bool(flags_val & 2),
                'links': gpo_links.get(gpo_dn_lower, []),
                'created': str(attrs.get('whenCreated', ''))[:10],
                'modified': str(attrs.get('whenChanged', ''))[:10],
            })

        ctx['gpos'].sort(key=lambda g: g['name'].lower())
    except Exception as e:
        ctx['error'] = str(e)

    return render_template('gpos.html', **ctx)


@browse_bp.route('/foreign-members')
def foreign_members_view():
    conn = get_conn()
    ctx = base_context('foreign-members')
    ctx['foreign_users'] = []
    ctx['cross_domain_members'] = []

    try:
        domain_sid = None
        domain_results = _ldap_search(conn, '(objectClass=domain)', ['objectSid'],
                                       search_base=conn._baseDN, size_limit=1)
        if domain_results:
            sid_raw = domain_results[0]['attributes'].get('objectSid', '')
            if isinstance(sid_raw, bytes):
                try:
                    from ldap3.protocol.formatters.formatters import format_sid
                    sid_raw = format_sid(sid_raw)
                except Exception:
                    sid_raw = str(sid_raw)
            domain_sid = str(sid_raw)

        if domain_sid:
            foreign_filter = '(&(objectClass=foreignSecurityPrincipal)(objectSid=*))'
            foreign_results = _ldap_search(conn, foreign_filter,
                ['cn', 'objectSid', 'memberOf', 'distinguishedName'])

            for r in foreign_results:
                attrs = r['attributes']
                sid = attrs.get('cn', '') or ''
                if isinstance(sid, list):
                    sid = sid[0] if sid else ''
                if not str(sid).startswith('S-1-5-21-') or str(sid).startswith(domain_sid):
                    continue
                member_of = attrs.get('memberOf', [])
                if isinstance(member_of, str):
                    member_of = [member_of]
                ctx['foreign_users'].append({
                    'sid': str(sid),
                    'dn': r['dn'],
                    'member_of': member_of,
                })

        groups = _ldap_search(conn, '(objectCategory=group)',
            ['sAMAccountName', 'member', 'distinguishedName'])

        for g in groups:
            members = g['attributes'].get('member', [])
            if isinstance(members, str):
                members = [members]
            for m in members:
                m_lower = m.lower()
                base_dn_lower = conn._baseDN.lower()
                if not m_lower.endswith(base_dn_lower):
                    ctx['cross_domain_members'].append({
                        'group_name': g['attributes'].get('sAMAccountName', ''),
                        'group_dn': g['dn'],
                        'member_dn': m,
                    })

    except Exception as e:
        ctx['error'] = str(e)

    return render_template('foreign_members.html', **ctx)


@browse_bp.route('/api/dashboard/hero')
def dashboard_hero():
    conn = get_conn()

    # Domain info + policy
    domain = conn.domain
    base_dn = conn._baseDN
    machine_quota = '?'
    password_policy = {}
    try:
        conn._ldap_connection.search(
            search_base=base_dn,
            search_filter='(objectClass=*)',
            search_scope=ldap3.BASE,
            attributes=[
                'ms-DS-MachineAccountQuota',
                'minPwdLength', 'maxPwdAge',
                'lockoutThreshold', 'pwdHistoryLength', 'pwdProperties',
            ],
        )
        if conn._ldap_connection.entries:
            entry = conn._ldap_connection.entries[0]
            machine_quota = entry['ms-DS-MachineAccountQuota'].value
            pwd_props = entry['pwdProperties'].value if 'pwdProperties' in entry else None
            password_policy = {
                'min_length': entry['minPwdLength'].value if 'minPwdLength' in entry else '?',
                'history_length': entry['pwdHistoryLength'].value if 'pwdHistoryLength' in entry else '?',
                'lockout_threshold': entry['lockoutThreshold'].value if 'lockoutThreshold' in entry else '?',
                'complexity': bool(pwd_props and int(str(pwd_props)) & 1) if pwd_props is not None else '?',
                'max_age_days': _ft_to_days(entry['maxPwdAge'].value if 'maxPwdAge' in entry else None),
            }
    except Exception:
        pass

    # Security score
    findings = []
    total_checks = 0
    score_checks = [
        ('Machine Account Quota > 0', lambda: int(machine_quota or 0) > 0, 'high'),
        ('Weak password policy (< 12 chars)', lambda: password_policy.get('min_length', 99) not in ('?',) and int(password_policy.get('min_length', 99)) < 12, 'medium'),
        ('No lockout threshold', lambda: password_policy.get('lockout_threshold') not in ('?',) and int(password_policy.get('lockout_threshold', 1)) == 0, 'high'),
        ('AS-REP Roastable accounts', lambda: _count(conn, '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))') > 0, 'high'),
        ('PASSWD_NOTREQD accounts', lambda: _count(conn, '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))') > 0, 'medium'),
        ('Unconstrained delegation', lambda: _count(conn, '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))') > 0, 'critical'),
        ('Kerberoastable privileged accounts', lambda: _count(conn, '(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(adminCount=1)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))') > 0, 'critical'),
        ('Reversible encryption enabled', lambda: _count(conn, '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=128))') > 0, 'high'),
    ]
    severity_weight = {'critical': 20, 'high': 12, 'medium': 6}
    total_weight = sum(severity_weight[s] for _, _, s in score_checks)
    lost = 0
    for name, check_fn, severity in score_checks:
        total_checks += 1
        try:
            if check_fn():
                findings.append({'name': name, 'severity': severity})
                lost += severity_weight[severity]
        except Exception:
            pass
    score = max(0, 100 - int(lost * 100 / total_weight)) if total_weight > 0 else 100

    # Counts
    counts = {}
    for key, cfg in OBJECT_TYPES.items():
        counts[key] = _count(conn, cfg['filter'])
    ou_results = _ldap_search(conn, '(objectCategory=organizationalUnit)', ['distinguishedName'])
    counts['ous'] = len(ou_results)
    counts['privileged'] = _count(conn, '(&(objectClass=user)(adminCount=1)(!(sAMAccountName=krbtgt)))')

    # DCs + CAs
    dc_results = _ldap_search(
        conn,
        '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
        ['sAMAccountName', 'dNSHostName']
    )
    dcs = [{'name': r['attributes'].get('sAMAccountName', ''), 'dns': r['attributes'].get('dNSHostName', '')} for r in dc_results]

    ca_list = []
    try:
        config_path = conn.configuration_path
        ca_results = _ldap_search(
            conn, '(&(objectClass=pKIEnrollmentService))',
            ['cn', 'dNSHostName', 'certificateTemplates'],
            search_base=f'CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_path}',
        )
        for r in ca_results:
            attrs = r.get('attributes', {})
            templates = attrs.get('certificateTemplates', [])
            if isinstance(templates, str):
                templates = [templates]
            ca_list.append({'name': attrs.get('cn', ''), 'dns_host': attrs.get('dNSHostName', '-'), 'templates_count': len(templates)})
    except Exception:
        pass

    # Attack surface
    surface = {
        'kerberoastable': _count(conn, QUERIES['kerberoastables']['filter'].format(base_dn=base_dn)),
        'asreproastable': _count(conn, QUERIES['asreproastables']['filter'].format(base_dn=base_dn)),
        'unconstrained': _count(conn, QUERIES['unconstrained']['filter'].format(base_dn=base_dn)),
        'constrained': _count(conn, QUERIES['constrained']['filter'].format(base_dn=base_dn)),
        'rbcd': _count(conn, QUERIES['rbcd']['filter'].format(base_dn=base_dn)),
        'passwd_notreqd': _count(conn, QUERIES['password_not_required']['filter'].format(base_dn=base_dn)),
    }

    # LAPS readable by current user (try Legacy and Windows LAPS separately)
    laps_count = 0
    for laps_q, laps_attr in [
        ('(&(objectCategory=computer)(ms-MCS-AdmPwd=*))', 'ms-Mcs-AdmPwd'),
        ('(&(objectCategory=computer)(msLAPS-Password=*))', 'msLAPS-Password'),
    ]:
        try:
            results = _ldap_search(conn, laps_q, ['sAMAccountName', laps_attr])
            laps_count += sum(1 for r in results if r['attributes'].get(laps_attr))
        except Exception:
            pass
    surface['laps_readable'] = laps_count

    # ADCS vulnerable templates
    try:
        from pwnAD.lib.adcs import analyze_adcs
        adcs_result = analyze_adcs(conn, vulnerable_only=True, get_ca_config=False)
        surface['adcs_vulnerable'] = sum(1 for t in adcs_result.get('templates', []) if t.is_vulnerable)
    except Exception:
        surface['adcs_vulnerable'] = 0

    # Writable objects (current user effective permissions on domain objects)
    try:
        writable_results = _ldap_search(conn,
            '(|(sAMAccountType=805306368)(sAMAccountType=805306369)(objectClass=group))',
            ['allowedAttributesEffective', 'sDRightsEffective'])
        writable_count = 0
        for r in writable_results:
            attrs = r['attributes']
            if attrs.get('allowedAttributesEffective') or attrs.get('sDRightsEffective'):
                sd_val = attrs.get('sDRightsEffective')
                if sd_val:
                    try:
                        if int(sd_val) & 0x05:
                            writable_count += 1
                            continue
                    except (ValueError, TypeError):
                        pass
                if attrs.get('allowedAttributesEffective'):
                    writable_count += 1
        surface['writable'] = writable_count
    except Exception:
        surface['writable'] = 0

    return render_template('partials/dashboard_hero.html',
        domain=domain, base_dn=base_dn, machine_quota=machine_quota,
        password_policy=password_policy,
        score=score, findings=findings, total_checks=total_checks,
        counts=counts, surface=surface, dcs=dcs, cas=ca_list)


@browse_bp.route('/browse/<object_type>')
def browse(object_type):
    if object_type not in OBJECT_TYPES:
        return "Unknown object type", 404

    conn = get_conn()
    cfg = OBJECT_TYPES[object_type]
    search = request.args.get('q', '').strip()
    preset = request.args.get('preset', '').strip()

    # Determine filter
    if preset:
        preset_cfg = next((f for f in cfg.get('filters', []) if f['key'] == preset), None)
        if preset_cfg:
            search_filter = preset_cfg['ldap']
        else:
            search_filter = cfg['filter']
    elif search:
        escaped = escape_filter_chars(search)
        search_filter = f'(&{cfg["filter"]}(|(sAMAccountName=*{escaped}*)(cn=*{escaped}*)(displayName=*{escaped}*)(distinguishedName=*{escaped}*)))'
    else:
        search_filter = cfg['filter']

    all_results = _ldap_search(conn, search_filter, cfg['attributes'])
    pagination = paginate(all_results)

    ctx = base_context(object_type)
    ctx.update({
        'results': pagination['items'],
        'object_type': object_type,
        'cfg': cfg,
        'search': search,
        'preset': preset,
        'pagination': pagination,
    })

    if request.headers.get('HX-Request'):
        return render_template('partials/object_list.html', **ctx)

    return render_template('browse.html', **ctx)


@browse_bp.route('/browse/<object_type>/export')
def browse_export(object_type):
    if object_type not in OBJECT_TYPES:
        return "Unknown object type", 404

    fmt = request.args.get('format', 'csv')
    conn = get_conn()
    cfg = OBJECT_TYPES[object_type]
    search = request.args.get('q', '').strip()
    preset = request.args.get('preset', '').strip()

    if preset:
        preset_cfg = next((f for f in cfg.get('filters', []) if f['key'] == preset), None)
        search_filter = preset_cfg['ldap'] if preset_cfg else cfg['filter']
    elif search:
        escaped = escape_filter_chars(search)
        search_filter = f'(&{cfg["filter"]}(|(sAMAccountName=*{escaped}*)(cn=*{escaped}*)(displayName=*{escaped}*)(distinguishedName=*{escaped}*)))'
    else:
        search_filter = cfg['filter']

    results = _ldap_search(conn, search_filter, cfg['attributes'])
    columns = [c['attr'] for c in cfg['columns']] + ['distinguishedName']

    if fmt == 'json':
        rows = []
        for r in results:
            row = {}
            for col in columns:
                val = r['attributes'].get(col, '')
                if isinstance(val, list):
                    val = '; '.join(str(v) for v in val)
                row[col] = str(val) if val else ''
            rows.append(row)
        return jsonify(rows)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for r in results:
        row = []
        for col in columns:
            val = r['attributes'].get(col, '')
            if isinstance(val, list):
                val = '; '.join(str(v) for v in val)
            row.append(str(val) if val else '')
        writer.writerow(row)
    return Response(buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={object_type}.csv'})


@browse_bp.route('/object')
def object_detail():
    dn = request.args.get('dn', '')
    if not dn:
        return "Missing DN parameter", 400

    conn = get_conn()

    # Check if this is a deleted object (DN contains "CN=Deleted Objects")
    is_deleted_object = 'CN=Deleted Objects' in dn or '\\0ADEL:' in dn

    # Search by DN - use the DN as search base with BASE scope
    try:
        if is_deleted_object:
            # Use show deleted control for deleted objects
            show_deleted_control = (LDAP_SERVER_SHOW_DELETED_OID, True, None)
            conn._ldap_connection.search(
                search_base=dn,
                search_filter='(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['*', 'msDS-LastKnownRDN', 'lastKnownParent', 'isDeleted'],
                controls=[show_deleted_control]
            )
            response = conn._ldap_connection.response
        else:
            response, _ = ldap_search_with_retry(conn, dn, '(objectClass=*)', ['*'], ldap3.BASE)

        results = []
        for entry in response:
            if entry.get('type') != 'searchResEntry':
                continue
            results.append({
                'dn': entry['dn'],
                'attributes': entry['attributes'],
            })
    except Exception as e:
        logging.debug(f"Error fetching object: {e}")
        results = []

    if not results:
        return "Object not found", 404

    ctx = base_context('object')
    ctx['obj'] = results[0]
    ctx['is_deleted'] = is_deleted_object or results[0]['attributes'].get('isDeleted') == True

    # Fetch owner info from security descriptor
    owner_info = None
    try:
        from impacket.ldap import ldaptypes
        from ldap3.protocol.microsoft import security_descriptor_control
        from ldap3.protocol.formatters.formatters import format_sid

        controls = security_descriptor_control(sdflags=0x01)
        # This search needs controls, so we use direct call but wrap in try/except for connection errors
        try:
            conn._ldap_connection.search(
                search_base=dn,
                search_filter='(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['nTSecurityDescriptor'],
                controls=controls,
            )
        except LDAP_CONNECTION_ERRORS:
            conn.rebind()
            conn._ldap_connection.search(
                search_base=dn,
                search_filter='(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['nTSecurityDescriptor'],
                controls=controls,
            )
        if conn._ldap_connection.entries:
            raw_sd = conn._ldap_connection.entries[0]['nTSecurityDescriptor'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
            owner_sid = sd['OwnerSid'].formatCanonical()
            owner_name = conn.get_samaccountname_from_sid(owner_sid)
            owner_info = {
                'sid': owner_sid,
                'name': owner_name or owner_sid,
            }
    except Exception as e:
        logging.debug(f"Could not fetch owner: {e}")

    ctx['owner_info'] = owner_info

    if request.headers.get('HX-Request'):
        return render_template('partials/object_detail.html', **ctx)

    return render_template('object.html', **ctx)


QUERY_META = {
    'kerberoastables': {'icon': 'fa-fire', 'color': 'text-orange-500', 'title': 'Kerberoastable Accounts'},
    'asreproastables': {'icon': 'fa-bolt', 'color': 'text-yellow-500', 'title': 'AS-REP Roastable Accounts'},
    'unconstrained': {'icon': 'fa-unlock', 'color': 'text-red-400', 'title': 'Unconstrained Delegation'},
    'constrained': {'icon': 'fa-link', 'color': 'text-blue-400', 'title': 'Constrained Delegation'},
    'rbcd': {'icon': 'fa-arrows-turn-to-dots', 'color': 'text-purple-400', 'title': 'RBCD Configured'},
    'admin_count': {'icon': 'fa-shield-halved', 'color': 'text-amber-500', 'title': 'AdminCount=1'},
    'protected_users': {'icon': 'fa-user-shield', 'color': 'text-green-500', 'title': 'Protected Users'},
    'passwords_dont_expire': {'icon': 'fa-hourglass', 'color': 'text-cyan-400', 'title': 'Password Never Expires'},
    'users_description': {'icon': 'fa-comment', 'color': 'text-neutral-400', 'title': 'User Descriptions'},
    'sid_history': {'icon': 'fa-clock-rotate-left', 'color': 'text-indigo-400', 'title': 'SID History'},
    'laps': {'icon': 'fa-key', 'color': 'text-green-400', 'title': 'LAPS Passwords'},
    'gmsa': {'icon': 'fa-robot', 'color': 'text-blue-400', 'title': 'gMSA Accounts'},
}

# Special queries not in QUERIES dict (handled separately)
SPECIAL_QUERIES = {
    'laps': {
        'filter': '(&(objectCategory=computer)(|(ms-MCS-AdmPwd=*)(msLAPS-Password=*)))',
        'attributes': ['sAMAccountName', 'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-PasswordExpirationTime'],
    },
    'gmsa': {
        'filter': '(&(ObjectClass=msDS-GroupManagedServiceAccount))',
        'attributes': ['sAMAccountName', 'msDS-GroupMSAMembership'],
    },
}


@browse_bp.route('/queries')
def queries_page():
    """
    Unified AD objects view with toggle filters.
    By default, shows all users, computers, and groups.
    Filters can be toggled to refine results.
    """
    conn = get_conn()
    ctx = base_context('queries')

    # Parse active filters from query string
    filters_param = request.args.get('filters', '')
    search = request.args.get('search', '').strip()
    active_filters = [f.strip() for f in filters_param.split(',') if f.strip()]

    ctx['active_filters'] = active_filters
    ctx['search'] = search
    ctx['results'] = []
    ctx['error'] = None
    ctx['can_read_passwords'] = False

    filter_counts = {}
    count_filters = {
        'kerberoastables': QUERIES['kerberoastables']['filter'],
        'asreproastables': QUERIES['asreproastables']['filter'],
        'unconstrained': QUERIES['unconstrained']['filter'],
        'constrained': QUERIES['constrained']['filter'],
        'rbcd': QUERIES['rbcd']['filter'],
        'admin_count': QUERIES['admin_count']['filter'],
        'protected_users': QUERIES['protected_users']['filter'],
    }
    for k, f in count_filters.items():
        filter_counts[k] = _count(conn, f.format(base_dn=conn._baseDN))
    ctx['filter_counts'] = filter_counts
    ctx['laps_readable'] = []
    ctx['gmsa_readable'] = []

    # Get current session user for highlighting
    session_user = ctx.get('session_user', '').lower()
    # Extract just the username part if it's in domain\user format
    if '\\' in session_user:
        session_user = session_user.split('\\')[-1].lower()
    if '@' in session_user:
        session_user = session_user.split('@')[0].lower()

    # Define filter queries mapping
    filter_queries = {
        'users': '(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))',
        'computers': '(objectCategory=computer)',
        'groups': '(objectCategory=group)',
        'kerberoastables': '(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
        'asreproastables': '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
        'unconstrained': '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
        'constrained': '(&(objectClass=user)(msDS-AllowedToDelegateTo=*))',
        'rbcd': '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
        'admin_count': '(&(objectClass=user)(adminCount=1)(!(sAMAccountName=krbtgt)))',
        'protected_users': f'(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Protected Users,CN=Users,{conn._baseDN}))',
        'laps': _build_laps_filter(conn),
        'gmsa': '(&(ObjectClass=msDS-GroupManagedServiceAccount))',
        'deleted': '(isDeleted=TRUE)',  # Special filter for deleted objects
    }

    # Build the LDAP filter based on active filters
    if not active_filters:
        # Default: show all users, computers, groups
        ldap_filter = '(|(objectCategory=person)(objectCategory=computer)(objectCategory=group))'
    else:
        # Check if we have object type filters
        type_filters = [f for f in active_filters if f in ('users', 'computers', 'groups')]
        query_filters = [f for f in active_filters if f not in ('users', 'computers', 'groups')]

        if type_filters and not query_filters:
            type_parts = [filter_queries[f] for f in type_filters]
            ldap_filter = f'(|{"".join(type_parts)})'
        elif query_filters and not type_filters:
            query_parts = [filter_queries[f] for f in query_filters if f in filter_queries]
            if query_parts:
                ldap_filter = f'(|{"".join(query_parts)})'
            else:
                ldap_filter = '(|(objectCategory=person)(objectCategory=computer)(objectCategory=group))'
        else:
            # Both: type filters AND query filters
            # Type restricts which object types are shown, queries restrict which properties match
            type_parts = [filter_queries[f] for f in type_filters]
            query_parts = [filter_queries[f] for f in query_filters if f in filter_queries]
            type_filter = f'(|{"".join(type_parts)})' if len(type_parts) > 1 else type_parts[0]
            if query_parts:
                query_filter = f'(|{"".join(query_parts)})' if len(query_parts) > 1 else query_parts[0]
                ldap_filter = f'(&{type_filter}{query_filter})'
            else:
                ldap_filter = type_filter

    # Add search filter if provided
    if search:
        escaped = escape_filter_chars(search)
        ldap_filter = f'(&{ldap_filter}(|(sAMAccountName=*{escaped}*)(cn=*{escaped}*)(distinguishedName=*{escaped}*)))'

    # Determine attributes to fetch based on active filters
    base_attrs = ['sAMAccountName', 'cn', 'distinguishedName', 'objectClass', 'userAccountControl', 'adminCount', 'servicePrincipalName', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'memberOf']

    # Add LAPS attributes if laps filter is active
    if 'laps' in active_filters:
        base_attrs.extend(['ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword'])

    # Add gMSA attributes if gmsa filter is active
    if 'gmsa' in active_filters:
        base_attrs.extend(['msDS-GroupMSAMembership', 'msDS-ManagedPassword'])

    # Add deleted object attributes if deleted filter is active
    if 'deleted' in active_filters:
        base_attrs.extend(['isDeleted', 'msDS-LastKnownRDN', 'lastKnownParent', 'whenChanged'])

    try:
        raw_results = _ldap_search(conn, ldap_filter, list(set(base_attrs)))
    except Exception as e:
        error_msg = str(e)
        if 'invalid attribute type' in error_msg.lower():
            ctx['error'] = 'Some attributes are not available on this domain'
        else:
            ctx['error'] = f'Query error: {error_msg}'
        raw_results = []

    # If 'deleted' filter is active, also search deleted objects
    deleted_dns = set()
    if 'deleted' in active_filters:
        try:
            deleted_filter = '(isDeleted=TRUE)'
            if search:
                escaped = escape_filter_chars(search)
                deleted_filter = f'(&(isDeleted=TRUE)(|(sAMAccountName=*{escaped}*)(cn=*{escaped}*)(name=*{escaped}*)))'

            deleted_attrs = ['sAMAccountName', 'cn', 'distinguishedName', 'objectClass', 'name',
                           'msDS-LastKnownRDN', 'lastKnownParent', 'whenChanged', 'isDeleted', 'objectSid']
            deleted_results = _ldap_search_deleted(conn, deleted_filter, deleted_attrs)

            for r in deleted_results:
                deleted_dns.add(r['dn'].lower())
                raw_results.append(r)
        except Exception as e:
            logging.debug(f"Error searching deleted objects: {e}")

    # Pre-fetch data for special queries to tag objects
    special_data = {}
    for query_name in ['kerberoastables', 'asreproastables', 'unconstrained', 'constrained', 'rbcd', 'admin_count', 'protected_users']:
        if query_name in QUERIES:
            try:
                query_results = _ldap_search(conn, QUERIES[query_name]['filter'].format(base_dn=conn._baseDN), ['distinguishedName'])
                special_data[query_name] = {r['dn'].lower() for r in query_results}
            except Exception:
                special_data[query_name] = set()

    # Check LAPS readable computers
    laps_readable_dns = set()
    if 'laps' in active_filters:
        try:
            laps_results = _ldap_search(conn, filter_queries['laps'], ['distinguishedName', 'sAMAccountName', 'ms-Mcs-AdmPwd', 'msLAPS-Password'])
            for r in laps_results:
                attrs = r.get('attributes', {})
                pwd = attrs.get('ms-Mcs-AdmPwd', '') or attrs.get('msLAPS-Password', '')
                if pwd:
                    laps_readable_dns.add(r['dn'].lower())
                    ctx['laps_readable'].append({
                        'dn': r['dn'],
                        'name': attrs.get('sAMAccountName', ''),
                        'password': pwd if isinstance(pwd, str) else (pwd[0] if pwd else '')
                    })
        except Exception:
            pass

    # Check gMSA readable accounts
    gmsa_readable_dns = set()
    if 'gmsa' in active_filters:
        try:
            gmsa_results = _ldap_search(conn, filter_queries['gmsa'], ['distinguishedName', 'sAMAccountName', 'msDS-ManagedPassword'])
            for r in gmsa_results:
                attrs = r.get('attributes', {})
                pwd = attrs.get('msDS-ManagedPassword', '')
                if pwd:
                    gmsa_readable_dns.add(r['dn'].lower())
                    ctx['gmsa_readable'].append({
                        'dn': r['dn'],
                        'name': attrs.get('sAMAccountName', ''),
                        'password': '[Binary - requires processing]'
                    })
        except Exception:
            pass

    ctx['can_read_passwords'] = bool(ctx['laps_readable'] or ctx['gmsa_readable'])

    # Transform results
    results = []
    for r in raw_results:
        attrs = r.get('attributes', {})
        obj_classes = attrs.get('objectClass', [])
        if isinstance(obj_classes, str):
            obj_classes = [obj_classes]
        obj_classes_lower = [c.lower() for c in obj_classes]
        dn_lower = r.get('dn', '').lower()

        # Determine object type
        obj_type = 'object'
        if 'computer' in obj_classes_lower:
            obj_type = 'computer'
        elif 'group' in obj_classes_lower:
            obj_type = 'group'
        elif 'msds-groupmanagedserviceaccount' in obj_classes_lower:
            obj_type = 'gmsa'
        elif 'user' in obj_classes_lower or 'person' in obj_classes_lower:
            obj_type = 'user'

        # Build tags for the object
        tags = []
        if dn_lower in special_data.get('kerberoastables', set()):
            tags.append('Kerberoastable')
        if dn_lower in special_data.get('asreproastables', set()):
            tags.append('AS-REP')
        if dn_lower in special_data.get('unconstrained', set()):
            tags.append('Unconstrained')
        if dn_lower in special_data.get('constrained', set()):
            tags.append('Constrained')
        if dn_lower in special_data.get('rbcd', set()):
            tags.append('RBCD')
        if dn_lower in special_data.get('admin_count', set()):
            tags.append('AdminCount')
        if dn_lower in special_data.get('protected_users', set()):
            tags.append('Protected')

        # LAPS tag
        has_laps = False
        can_read_laps = False
        if obj_type == 'computer':
            laps_pwd = attrs.get('ms-Mcs-AdmPwd', '') or attrs.get('msLAPS-Password', '') or attrs.get('msLAPS-EncryptedPassword', '')
            if laps_pwd:
                has_laps = True
                can_read_laps = True
                tags.append('LAPS')

        # gMSA tag
        can_read_gmsa = False
        if obj_type == 'gmsa' or 'msds-groupmanagedserviceaccount' in obj_classes_lower:
            obj_type = 'gmsa'
            tags.append('gMSA')
            if attrs.get('msDS-ManagedPassword'):
                can_read_gmsa = True

        # Check if this object is deleted
        is_deleted = dn_lower in deleted_dns or attrs.get('isDeleted') == True
        if is_deleted:
            tags.insert(0, 'Deleted')  # Add 'Deleted' tag at the beginning

        # Check if this is the current session user
        sam = attrs.get('sAMAccountName', '')
        # For deleted objects, the name might be in msDS-LastKnownRDN
        display_name = sam or attrs.get('msDS-LastKnownRDN', '') or attrs.get('cn', '') or attrs.get('name', '')
        # Exact comparison - don't strip $ to avoid highlighting machine accounts (e.g. test$ when user is test)
        is_current_user = sam.lower() == session_user.lower() if sam else False

        results.append({
            'dn': r.get('dn', ''),
            'sam': sam,
            'name': display_name,
            'type': obj_type,
            'tags': tags,
            'spn': attrs.get('servicePrincipalName', ''),
            'allowed_to': attrs.get('msDS-AllowedToDelegateTo', ''),
            'has_laps': has_laps,
            'can_read_laps': can_read_laps,
            'can_read_gmsa': can_read_gmsa,
            'is_current_user': is_current_user,
            'is_deleted': is_deleted,
            'last_known_parent': attrs.get('lastKnownParent', '') if is_deleted else '',
        })

    # Sort results: current user first, then by name
    results.sort(key=lambda x: (not x['is_current_user'], x['sam'].lower() if x['sam'] else x['name'].lower()))

    pagination = paginate(results)
    ctx['results'] = pagination['items']
    ctx['pagination'] = pagination
    return render_template('queries.html', **ctx)


@browse_bp.route('/queries/export')
def queries_export():
    fmt = request.args.get('format', 'csv')
    conn = get_conn()
    filters_param = request.args.get('filters', '')
    search = request.args.get('search', '').strip()
    active_filters = [f.strip() for f in filters_param.split(',') if f.strip()]

    filter_queries = {
        'users': '(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))',
        'computers': '(objectCategory=computer)',
        'groups': '(objectCategory=group)',
        'kerberoastables': QUERIES.get('kerberoastables', {}).get('filter', ''),
        'asreproastables': QUERIES.get('asreproastables', {}).get('filter', ''),
        'unconstrained': QUERIES.get('unconstrained', {}).get('filter', ''),
        'constrained': QUERIES.get('constrained', {}).get('filter', ''),
        'rbcd': QUERIES.get('rbcd', {}).get('filter', ''),
        'admin_count': QUERIES.get('admin_count', {}).get('filter', ''),
        'protected_users': QUERIES.get('protected_users', {}).get('filter', '').format(base_dn=conn._baseDN),
        'laps': '(&(objectCategory=computer)(|(ms-MCS-AdmPwd=*)(msLAPS-Password=*)))',
        'gmsa': '(&(ObjectClass=msDS-GroupManagedServiceAccount))',
    }

    if not active_filters:
        ldap_filter = '(|(objectCategory=person)(objectCategory=computer)(objectCategory=group))'
    else:
        parts = [filter_queries[f] for f in active_filters if f in filter_queries]
        ldap_filter = f'(|{"".join(parts)})' if parts else '(objectClass=*)'

    if search:
        escaped = escape_filter_chars(search)
        ldap_filter = f'(&{ldap_filter}(|(sAMAccountName=*{escaped}*)(cn=*{escaped}*)(distinguishedName=*{escaped}*)))'

    attrs = ['sAMAccountName', 'distinguishedName', 'objectClass']
    results = _ldap_search(conn, ldap_filter, attrs)
    columns = ['sAMAccountName', 'objectClass', 'distinguishedName']

    if fmt == 'json':
        rows = []
        for r in results:
            row = {}
            for col in columns:
                val = r['attributes'].get(col, '')
                if isinstance(val, list):
                    val = '; '.join(str(v) for v in val)
                row[col] = str(val) if val else ''
            rows.append(row)
        return jsonify(rows)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for r in results:
        row = []
        for col in columns:
            val = r['attributes'].get(col, '')
            if isinstance(val, list):
                val = '; '.join(str(v) for v in val)
            row.append(str(val) if val else '')
        writer.writerow(row)
    name = '_'.join(active_filters) if active_filters else 'queries'
    return Response(buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={name}.csv'})


@browse_bp.route('/api/readable-passwords')
def api_readable_passwords():
    """
    API endpoint to fetch readable LAPS and gMSA passwords.
    Returns JSON with lists of readable passwords.
    """
    conn = get_conn()
    result = {
        'laps': [],
        'gmsa': [],
        'error': None
    }

    # Fetch LAPS passwords (try Legacy and Windows LAPS separately)
    for laps_q, laps_attr in [
        ('(&(objectCategory=computer)(ms-MCS-AdmPwd=*))', 'ms-Mcs-AdmPwd'),
        ('(&(objectCategory=computer)(msLAPS-Password=*))', 'msLAPS-Password'),
    ]:
        try:
            laps_results = _ldap_search(conn, laps_q, ['sAMAccountName', 'distinguishedName', laps_attr])
            for r in laps_results:
                attrs = r.get('attributes', {})
                pwd = attrs.get(laps_attr, '')
                if isinstance(pwd, list):
                    pwd = pwd[0] if pwd else ''
                if pwd:
                    result['laps'].append({
                        'name': attrs.get('sAMAccountName', ''),
                        'dn': r.get('dn', ''),
                        'password': pwd
                    })
        except Exception:
            pass

    # Fetch gMSA accounts (password requires special handling)
    try:
        gmsa_filter = '(&(ObjectClass=msDS-GroupManagedServiceAccount))'
        gmsa_results = _ldap_search(conn, gmsa_filter, ['sAMAccountName', 'distinguishedName', 'msDS-ManagedPassword'])
        for r in gmsa_results:
            attrs = r.get('attributes', {})
            pwd = attrs.get('msDS-ManagedPassword', '')
            result['gmsa'].append({
                'name': attrs.get('sAMAccountName', ''),
                'dn': r.get('dn', ''),
                'password': '[Requires TLS and special processing]' if not pwd else '[Binary data - hash extraction needed]'
            })
    except Exception as e:
        pass  # gMSA errors are non-critical

    return jsonify(result)


@browse_bp.route('/query/<query_name>')
def query(query_name):
    if query_name == 'custom':
        return _custom_query()

    if query_name in QUERIES or query_name in SPECIAL_QUERIES:
        return redirect(f'/queries?filters={query_name}')

    return "Unknown query", 404


@browse_bp.route('/laps')
def laps_view():
    return redirect('/queries?filters=laps')


@browse_bp.route('/gmsa')
def gmsa_view():
    return redirect('/queries?filters=gmsa')


@browse_bp.route('/writable')
def writable_view():
    conn = get_conn()
    ctx = base_context('writable')
    ctx['otype'] = request.args.get('otype', '*').strip()
    ctx['right'] = request.args.get('right', 'ALL').strip()
    ctx['partition'] = request.args.get('partition', 'DOMAIN').strip()
    ctx['results'] = None

    # Always run the writable search on load
    try:
        otype = ctx['otype']
        right = ctx['right']
        partition = ctx['partition']

        if otype == '*':
            ldap_filter = '(objectClass=*)'
        elif otype == 'useronly':
            ldap_filter = '(sAMAccountType=805306368)'
        elif otype == 'ou':
            ldap_filter = '(|(objectClass=container)(objectClass=organizationalUnit))'
        elif otype == 'gpo':
            ldap_filter = '(objectClass=groupPolicyContainer)'
        else:
            ldap_filter = f'(objectClass={escape_filter_chars(otype)})'

        search_bases = []
        if partition == 'DOMAIN':
            search_bases.append(conn._baseDN)
        elif partition == 'CONFIGURATION':
            search_bases.append(conn.configuration_path)
        elif partition == 'SCHEMA':
            search_bases.append(f'CN=Schema,{conn.configuration_path}')
        elif partition == 'DNS':
            search_bases.extend([
                f'DC=DomainDnsZones,{conn._baseDN}',
                f'DC=ForestDnsZones,{conn._baseDN}'
            ])
        elif partition == 'ALL':
            search_bases.extend([
                conn._baseDN,
                conn.configuration_path,
                f'CN=Schema,{conn.configuration_path}',
                f'DC=DomainDnsZones,{conn._baseDN}',
                f'DC=ForestDnsZones,{conn._baseDN}'
            ])

        all_results = []

        # Computed-attributes mode for current user
        attributes = ['distinguishedName']
        if right in ('WRITE', 'ALL'):
            attributes.extend(['allowedAttributesEffective', 'sDRightsEffective'])
        if right in ('CHILD', 'ALL'):
            attributes.append('allowedChildClassesEffective')

        for base in search_bases:
            results = _ldap_search(conn, ldap_filter, attributes, search_base=base)
            for r in results:
                attrs = r['attributes']
                permissions = []
                sd_rights = {}

                # Check write permissions
                has_write = bool(attrs.get('allowedAttributesEffective'))
                if has_write and right in ('WRITE', 'ALL'):
                    permissions.append('WRITE')

                # Check child creation permissions
                has_child = bool(attrs.get('allowedChildClassesEffective'))
                if has_child and right in ('CHILD', 'ALL'):
                    permissions.append('CREATE_CHILD')

                # Parse sDRightsEffective for OWNER/DACL/SACL write permissions
                sd_rights_value = attrs.get('sDRightsEffective')
                if sd_rights_value:
                    try:
                        value = int(sd_rights_value)
                        if value & 0x01:
                            sd_rights['OWNER'] = 'WRITE'
                        if value & 0x04:
                            sd_rights['DACL'] = 'WRITE'
                        if value & 0x08:
                            sd_rights['SACL'] = 'WRITE'
                    except (ValueError, TypeError):
                        pass

                if permissions or sd_rights:
                    all_results.append({
                        'dn': r['dn'],
                        'permissions': permissions,
                        'sd_rights': sd_rights,
                    })

        ctx['results'] = all_results
    except Exception as e:
        ctx['error'] = f'Error: {e}'

    if request.headers.get('HX-Request') and ctx['results'] is not None:
        return render_template('partials/writable_results.html', results=ctx['results'])

    return render_template('writable.html', **ctx)


@browse_bp.route('/members/<group>')
def members_view(group):
    conn = get_conn()
    escaped = escape_filter_chars(group)
    results = _ldap_search(
        conn,
        f'(&(objectClass=group)(sAMAccountName={escaped}))',
        ['member', 'objectSid'],
    )
    if not results:
        return '<div class="p-4 text-red-400">Group not found</div>'

    members_list = results[0]['attributes'].get('member', [])
    if isinstance(members_list, str):
        members_list = [members_list]

    member_names = []
    for dn in members_list:
        try:
            response, _ = ldap_search_with_retry(conn, dn, '(objectClass=*)', ['sAMAccountName'], ldap3.BASE)
            for entry in response:
                if entry.get('type') == 'searchResEntry':
                    member_names.append(entry['attributes'].get('sAMAccountName', dn))
        except Exception:
            member_names.append(dn)

    ctx = {'members': sorted(member_names), 'group': group}
    return render_template('partials/member_list.html', **ctx)


@browse_bp.route('/membership/<account>')
def membership_view(account):
    conn = get_conn()
    recurse = request.args.get('recurse', '').lower() == 'true'

    if not conn.exists(account):
        return '<div class="p-4 text-red-400">Account not found</div>'

    def get_groups(conn, acct, max_depth, depth=1):
        if depth > max_depth:
            return
        try:
            response, _ = ldap_search_with_retry(
                conn, conn._baseDN,
                f'(sAMAccountName={escape_filter_chars(acct)})',
                ['memberOf', 'primaryGroupID'],
                ldap3.SUBTREE
            )
        except Exception:
            return
        if not response:
            return
        # Find first searchResEntry
        entry_data = None
        for entry in response:
            if entry.get('type') == 'searchResEntry':
                entry_data = entry['attributes']
                break
        if not entry_data:
            return
        member_of = entry_data.get('memberOf', [])
        if isinstance(member_of, str):
            member_of = [member_of]
        for grp_dn in member_of:
            sam = conn.get_samaccountname_from_dn(grp_dn, '*')
            if sam and sam not in groups:
                groups.append(sam)
                get_groups(conn, sam, max_depth, depth + 1)

    groups = []
    try:
        get_groups(conn, account, 5 if recurse else 1)
    except Exception as e:
        logging.error(f"membership error: {e}")

    groups.sort()
    ctx = {'groups': groups, 'account': account, 'recurse': recurse}
    return render_template('partials/membership_list.html', **ctx)



@browse_bp.route('/ca')
def ca_view():
    return redirect('/adcs')



def _custom_query():
    conn = get_conn()
    filter_str = request.args.get('filter', '').strip()
    attrs_str = request.args.get('attrs', 'sAMAccountName,distinguishedName').strip()

    results = []
    columns = [a.strip() for a in attrs_str.split(',') if a.strip()]

    if filter_str:
        try:
            results = _ldap_search(conn, filter_str, columns)
        except Exception as e:
            logging.error(f"[!] Custom query error: {e} - filter: {repr(filter_str)}")

    display_columns = [c for c in columns if c != 'distinguishedName']

    ctx = base_context('custom')
    ctx.update({
        'title': 'Custom LDAP Query',
        'icon': 'fas fa-terminal',
        'columns': display_columns,
        'results': results,
        'custom': True,
        'filter_str': filter_str,
        'attrs_str': attrs_str,
    })

    return render_template('query.html', **ctx)


@browse_bp.route('/bloodhound')
def bloodhound_view():
    """BloodHound CE export page."""
    ctx = base_context('bloodhound')
    return render_template('bloodhound.html', **ctx)


@browse_bp.route('/api/export/bloodhound', methods=['POST'])
def export_bloodhound():
    """Export domain data as BloodHound CE zip (download)."""
    import tempfile
    from flask import send_file
    conn = get_conn()

    methods_str = request.form.get('methods', '').strip()
    workers = int(request.form.get('workers', 10) or 10)
    prefix = request.form.get('prefix', '').strip()
    exclude_dcs = bool(request.form.get('exclude_dcs'))
    nameserver = request.form.get('nameserver', '').strip() or None

    collect = None
    if methods_str:
        collect = set(m.strip() for m in methods_str.split(',') if m.strip())

    try:
        from pwnAD.lib.bloodhound import _run_collection
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _run_collection(
                conn, output_dir=tmpdir, prefix=prefix,
                collect=collect, num_workers=workers,
                exclude_dcs=exclude_dcs, nameserver=nameserver,
            )
            return send_file(
                zip_path,
                mimetype='application/zip',
                as_attachment=True,
                download_name=os.path.basename(zip_path),
            )
    except ImportError:
        return jsonify(success=False, message='bloodhound-ce package not installed. Run: pip install bloodhound-ce'), 500
    except Exception as e:
        logging.error(f"BloodHound export error: {e}")
        return jsonify(success=False, message=str(e)), 500
