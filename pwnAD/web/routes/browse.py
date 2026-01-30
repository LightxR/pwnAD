import logging

import ldap3
from flask import Blueprint, render_template, request, current_app, jsonify
from ldap3.utils.conv import escape_filter_chars

from pwnAD.web.utils import LDAP_CONNECTION_ERRORS, ldap_search_with_retry

browse_bp = Blueprint('browse', __name__)

OBJECT_TYPES = {
    'users': {
        'label': 'Users',
        'icon': 'fas fa-user',
        'filter': '(&(objectCategory=person)(objectClass=user))',
        'attributes': ['sAMAccountName', 'displayName', 'mail', 'memberOf', 'userAccountControl', 'distinguishedName'],
        'columns': [
            {'attr': 'sAMAccountName', 'label': 'Username'},
            {'attr': 'displayName', 'label': 'Display Name'},
            {'attr': 'mail', 'label': 'Email'},
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
        'attributes': ['sAMAccountName', 'dNSHostName', 'operatingSystem', 'distinguishedName'],
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


def _get_conn():
    return current_app.config['LDAP_CONNECTION']


def _ensure_connected(conn):
    """Check connection and rebind if necessary."""
    if not conn.is_connected():
        logging.warning("[*] LDAP connection lost, attempting rebind...")
        if not conn.rebind():
            raise LDAPSocketOpenError("Failed to rebind LDAP connection")


def _ldap_search_single(conn, search_base, search_filter, attributes, search_scope=ldap3.BASE, _retry=True):
    """Execute a single LDAP search with auto-rebind on connection loss.

    Used for non-paged searches (e.g., fetching a single object by DN).
    """
    try:
        conn._ldap_connection.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=search_scope,
            attributes=attributes,
        )
        return conn._ldap_connection.response, conn._ldap_connection.result

    except LDAP_CONNECTION_ERRORS as e:
        if _retry:
            logging.warning(f"[*] LDAP connection error: {e}, attempting rebind...")
            if conn.rebind():
                return _ldap_search_single(conn, search_base, search_filter, attributes, search_scope, _retry=False)
        raise


def _ldap_search(conn, search_filter, attributes, search_base=None, size_limit=0, _retry=True):
    """Execute an LDAP search and return list of result dicts.

    Automatically attempts to rebind if the connection is lost.
    """
    if search_base is None:
        search_base = conn._baseDN

    results = []
    paged_cookie = None

    try:
        while True:
            conn._ldap_connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                paged_size=1000,
                paged_cookie=paged_cookie,
                size_limit=size_limit,
            )
            for entry in conn._ldap_connection.response:
                if entry.get('type') != 'searchResEntry':
                    continue
                results.append({
                    'dn': entry['dn'],
                    'attributes': entry['attributes'],
                })

            controls = conn._ldap_connection.result.get('controls', {})
            page_control = controls.get('1.2.840.113556.1.4.319')
            if page_control:
                cookie = page_control['value']['cookie']
                if cookie:
                    paged_cookie = cookie
                    continue
            break

    except LDAP_CONNECTION_ERRORS as e:
        if _retry:
            logging.warning(f"[*] LDAP connection error: {e}, attempting rebind...")
            if conn.rebind():
                # Retry the search once after rebind
                return _ldap_search(conn, search_filter, attributes, search_base, size_limit, _retry=False)
        raise

    return results


def _count(conn, search_filter):
    """Quick count of objects matching a filter."""
    try:
        return len(_ldap_search(conn, search_filter, ['cn']))
    except Exception:
        return '?'


def _base_context(active_page=''):
    """Common template context."""
    conn = _get_conn()
    return {
        'domain': conn.domain,
        'dc_ip': conn.target,
        'session_user': getattr(conn, 'ldap_user', '') or getattr(conn, 'user', ''),
        'active_page': active_page,
    }


@browse_bp.route('/')
def index():
    conn = _get_conn()
    ctx = _base_context('dashboard')

    # Object counts
    counts = {}
    for key, cfg in OBJECT_TYPES.items():
        counts[key] = _count(conn, cfg['filter'])
    ctx['counts'] = counts
    ctx['base_dn'] = conn._baseDN

    # Query counts for dashboard
    query_counts = {}
    for key, qcfg in QUERIES.items():
        query_counts[key] = _count(conn, qcfg['filter'].format(base_dn=conn._baseDN))
    ctx['query_counts'] = query_counts

    # Domain Controllers
    dc_results = _ldap_search(
        conn,
        '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
        ['sAMAccountName', 'servicePrincipalName']
    )
    ctx['domain_controllers'] = [
        {'name': r['attributes'].get('sAMAccountName', ''), 'spn': r['attributes'].get('servicePrincipalName', [])}
        for r in dc_results
    ]

    # Certificate Authorities
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
    ctx['certificate_authorities'] = ca_list

    # Domain info: machine quota + password policy
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

            def _ft_to_days(val):
                """Convert negative FILETIME (100ns intervals) to days."""
                if val is None:
                    return '?'
                try:
                    total = abs(int(str(val)))
                    days = total // (10_000_000 * 60 * 60 * 24)
                    return days if days else '<1'
                except Exception:
                    return '?'

            def _ft_to_minutes(val):
                """Convert negative FILETIME (100ns intervals) to minutes."""
                if val is None:
                    return '?'
                try:
                    total = abs(int(str(val)))
                    minutes = total // (10_000_000 * 60)
                    return minutes if minutes else '<1'
                except Exception:
                    return '?'

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
    ctx['machine_quota'] = machine_quota
    ctx['password_policy'] = password_policy

    # OUs
    ou_results = _ldap_search(conn, '(objectCategory=organizationalUnit)', ['distinguishedName'])
    ctx['ous'] = [r['dn'] for r in ou_results]

    return render_template('index.html', **ctx)


@browse_bp.route('/browse/<object_type>')
def browse(object_type):
    if object_type not in OBJECT_TYPES:
        return "Unknown object type", 404

    conn = _get_conn()
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

    results = _ldap_search(conn, search_filter, cfg['attributes'])

    ctx = _base_context(object_type)
    ctx.update({
        'results': results,
        'object_type': object_type,
        'cfg': cfg,
        'search': search,
        'preset': preset,
    })

    if request.headers.get('HX-Request'):
        return render_template('partials/object_list.html', **ctx)

    return render_template('browse.html', **ctx)


@browse_bp.route('/object')
def object_detail():
    dn = request.args.get('dn', '')
    if not dn:
        return "Missing DN parameter", 400

    conn = _get_conn()

    # Search by DN - use the DN as search base with BASE scope
    try:
        response, _ = _ldap_search_single(conn, dn, '(objectClass=*)', ['*'], ldap3.BASE)
        results = []
        for entry in response:
            if entry.get('type') != 'searchResEntry':
                continue
            results.append({
                'dn': entry['dn'],
                'attributes': entry['attributes'],
            })
    except Exception:
        results = []

    if not results:
        return "Object not found", 404

    ctx = _base_context('object')
    ctx['obj'] = results[0]

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
    query_name = request.args.get('q', '')
    ctx = _base_context('queries')
    ctx['current_query'] = query_name
    ctx['results'] = []
    ctx['query_title'] = ''
    ctx['query_icon'] = ''
    ctx['query_color'] = ''

    if query_name and (query_name in QUERIES or query_name in SPECIAL_QUERIES):
        conn = _get_conn()
        meta = QUERY_META.get(query_name, {})

        # Get query config from either QUERIES or SPECIAL_QUERIES
        if query_name in QUERIES:
            qcfg = QUERIES[query_name]
        else:
            qcfg = SPECIAL_QUERIES[query_name]

        try:
            raw_results = _ldap_search(conn, qcfg['filter'].format(base_dn=conn._baseDN), qcfg['attributes'] + ['objectClass'])
        except Exception as e:
            error_msg = str(e)
            if query_name == 'laps' and 'invalid attribute type' in error_msg.lower():
                ctx['error'] = 'LAPS is not configured on this domain'
            else:
                ctx['error'] = f'Query error: {error_msg}'
            raw_results = []

        # Transform results for the new template
        results = []
        for r in raw_results:
            attrs = r.get('attributes', {})
            obj_classes = attrs.get('objectClass', [])
            obj_type = 'object'
            if 'computer' in obj_classes:
                obj_type = 'computer'
            elif 'group' in obj_classes:
                obj_type = 'group'
            elif 'msDS-GroupManagedServiceAccount' in obj_classes:
                obj_type = 'gmsa'
            elif 'user' in obj_classes or 'person' in obj_classes:
                obj_type = 'user'

            # Handle description which can be a list
            desc = attrs.get('description', '')
            if isinstance(desc, list):
                desc = desc[0] if desc else ''

            # Handle LAPS password (legacy or new)
            laps_pwd = attrs.get('ms-Mcs-AdmPwd', '') or attrs.get('msLAPS-Password', '')
            if isinstance(laps_pwd, list):
                laps_pwd = laps_pwd[0] if laps_pwd else ''

            results.append({
                'dn': r.get('dn', ''),
                'sam': attrs.get('sAMAccountName', ''),
                'name': attrs.get('sAMAccountName', attrs.get('cn', '')),
                'type': obj_type,
                'spn': attrs.get('servicePrincipalName', ''),
                'allowed_to': attrs.get('msDS-AllowedToDelegateTo', ''),
                'description': desc,
                'laps_password': laps_pwd,
            })

        ctx['results'] = results
        ctx['query_title'] = meta.get('title', qcfg.get('title', query_name))
        ctx['query_icon'] = meta.get('icon', 'fa-database')
        ctx['query_color'] = meta.get('color', 'text-neutral-400')

    return render_template('queries.html', **ctx)


@browse_bp.route('/query/<query_name>')
def query(query_name):
    if query_name == 'custom':
        return _custom_query()

    if query_name not in QUERIES:
        return "Unknown query", 404

    conn = _get_conn()
    qcfg = QUERIES[query_name]

    results = _ldap_search(conn, qcfg['filter'].format(base_dn=conn._baseDN), qcfg['attributes'])

    ctx = _base_context(query_name)
    ctx.update({
        'title': qcfg['title'],
        'icon': qcfg['icon'],
        'columns': [c for c in qcfg['columns'] if c != 'distinguishedName'],
        'results': results,
        'custom': False,
    })

    return render_template('query.html', **ctx)


@browse_bp.route('/laps')
def laps_view():
    conn = _get_conn()
    ctx = _base_context('laps')
    ctx['results'] = []
    ctx['error'] = None

    try:
        results = _ldap_search(
            conn,
            '(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',
            ['sAMAccountName', 'ms-Mcs-AdmPwd'],
        )
        ctx['results'] = results
    except Exception as e:
        error_msg = str(e)
        if 'invalid attribute type ms-Mcs-AdmPwd' in error_msg:
            ctx['error'] = 'This domain does not have LAPS configured'
        else:
            ctx['error'] = f'Error retrieving LAPS passwords: {error_msg}'

    return render_template('laps.html', **ctx)


@browse_bp.route('/gmsa')
def gmsa_view():
    conn = _get_conn()
    ctx = _base_context('gmsa')
    ctx['results'] = []
    ctx['error'] = None

    try:
        results = _ldap_search(
            conn,
            '(&(ObjectClass=msDS-GroupManagedServiceAccount))',
            ['sAMAccountName', 'msDS-GroupMSAMembership'],
        )
        ctx['results'] = results
    except Exception as e:
        ctx['error'] = f'Error retrieving gMSA accounts: {e}'

    return render_template('gmsa.html', **ctx)


@browse_bp.route('/writable')
def writable_view():
    conn = _get_conn()
    ctx = _base_context('writable')
    ctx['otype'] = request.args.get('otype', '*').strip()
    ctx['right'] = request.args.get('right', 'ALL').strip()
    ctx['partition'] = request.args.get('partition', 'DOMAIN').strip()
    ctx['results'] = None

    if request.args.get('search'):
        try:
            otype = ctx['otype']
            right = ctx['right']
            partition = ctx['partition']

            if otype == 'useronly':
                ldap_filter = '(sAMAccountType=805306368)'
            elif otype == 'ou':
                ldap_filter = '(|(objectClass=container)(objectClass=organizationalUnit))'
            elif otype == 'gpo':
                ldap_filter = '(objectClass=groupPolicyContainer)'
            else:
                ldap_filter = f'(objectClass={otype})'

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
    conn = _get_conn()
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
            response, _ = _ldap_search_single(conn, dn, '(objectClass=*)', ['sAMAccountName'], ldap3.BASE)
            for entry in response:
                if entry.get('type') == 'searchResEntry':
                    member_names.append(entry['attributes'].get('sAMAccountName', dn))
        except Exception:
            member_names.append(dn)

    ctx = {'members': sorted(member_names), 'group': group}
    return render_template('partials/member_list.html', **ctx)


@browse_bp.route('/membership/<account>')
def membership_view(account):
    conn = _get_conn()
    recurse = request.args.get('recurse', '').lower() == 'true'

    if not conn.exists(account):
        return '<div class="p-4 text-red-400">Account not found</div>'

    def get_groups(conn, acct, max_depth, depth=1):
        if depth > max_depth:
            return
        try:
            response, _ = _ldap_search_single(
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
    conn = _get_conn()
    ctx = _base_context('ca')
    ctx['results'] = []

    try:
        config_path = conn.configuration_path
        results = _ldap_search(
            conn,
            '(&(objectClass=pKIEnrollmentService))',
            ['cn', 'name', 'dNSHostName', 'cACertificateDN', 'certificateTemplates'],
            search_base=f'CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_path}',
        )
        ctx['results'] = results
    except Exception as e:
        ctx['error'] = f'Error retrieving CAs: {e}'

    return render_template('ca.html', **ctx)



def _custom_query():
    conn = _get_conn()
    filter_str = request.args.get('filter', '').strip()
    attrs_str = request.args.get('attrs', 'sAMAccountName,distinguishedName').strip()

    results = []
    columns = [a.strip() for a in attrs_str.split(',') if a.strip()]

    if filter_str:
        try:
            results = _ldap_search(conn, filter_str, columns)
        except Exception as e:
            pass

    display_columns = [c for c in columns if c != 'distinguishedName']

    ctx = _base_context('custom')
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
