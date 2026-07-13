import json
import logging

import ldap3
from flask import Blueprint, request, jsonify, render_template
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars

from pwnAD.lib.utils import resolve_target, encode_ldap_value, check_error
from pwnAD.lib.accesscontrol import UAC_NORMAL_ACCOUNT_ENABLED, UAC_WORKSTATION_TRUST
from pwnAD.web.utils import LDAP_CONNECTION_ERRORS, ldap_search_with_retry

from pwnAD.web.context import get_conn

actions_bp = Blueprint('actions', __name__, url_prefix='/api')


def _json_response(success, message, status=200, **extra):
    data = {'success': success, 'message': message}
    data.update(extra)
    return jsonify(data), status


def _ensure_tls(conn):
    lc = conn._ldap_connection
    if lc.server.ssl or lc.tls_started:
        return True
    try:
        conn.start_tls()
        return True
    except Exception as e:
        logging.error(f"StartTLS failed: {e}")
        return False


@actions_bp.route('/attribute/add', methods=['POST'])
def attribute_add():
    conn = get_conn()
    dn = request.form.get('dn', '').strip()
    attr = request.form.get('attr', '').strip()
    value = request.form.get('value', '').strip()

    if not dn or not attr or not value:
        return _json_response(False, 'Missing required fields', 400)

    try:
        encoded = encode_ldap_value(attr, value)
        if encoded is None:
            return _json_response(False, 'Failed to encode value')
        conn.modify(dn, {attr: [(MODIFY_ADD, [encoded])]})
        return _json_response(True, f'Added value to {attr}')
    except Exception as e:
        logging.error(f"attribute add error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/attribute/modify', methods=['POST'])
def attribute_modify():
    conn = get_conn()
    dn = request.form.get('dn', '').strip()
    attr = request.form.get('attr', '').strip()
    old_value = request.form.get('old_value', '').strip()
    new_value = request.form.get('new_value', '').strip()

    if not dn or not attr or not new_value:
        return _json_response(False, 'Missing required fields', 400)

    try:
        encoded_new = encode_ldap_value(attr, new_value)
        if encoded_new is None:
            return _json_response(False, 'Failed to encode value')

        if old_value:
            encoded_old = encode_ldap_value(attr, old_value)
            conn.modify(dn, {attr: [(MODIFY_DELETE, [encoded_old]), (MODIFY_ADD, [encoded_new])]})
        else:
            conn.modify(dn, {attr: [(MODIFY_REPLACE, [encoded_new])]})
        return _json_response(True, f'Modified {attr}')
    except Exception as e:
        logging.error(f"attribute modify error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/attribute/remove', methods=['POST'])
def attribute_remove():
    conn = get_conn()
    dn = request.form.get('dn', '').strip()
    attr = request.form.get('attr', '').strip()
    value = request.form.get('value', '').strip()

    if not dn or not attr:
        return _json_response(False, 'Missing required fields', 400)

    try:
        if value:
            encoded = encode_ldap_value(attr, value)
            conn.modify(dn, {attr: [(MODIFY_DELETE, [encoded])]})
        else:
            conn.modify(dn, {attr: [(MODIFY_REPLACE, [])]})
        return _json_response(True, f'Removed value from {attr}')
    except Exception as e:
        logging.error(f"attribute remove error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/object/delete', methods=['POST'])
def object_delete():
    conn = get_conn()
    dn = request.form.get('dn', '').strip()

    if not dn:
        return _json_response(False, 'Missing DN', 400)

    try:
        conn.delete(dn)
        return _json_response(True, 'Object deleted')
    except Exception as e:
        logging.error(f"object delete error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/user/create', methods=['POST'])
def user_create():
    conn = get_conn()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    ou = request.form.get('ou', '').strip()

    if not username or not password:
        return _json_response(False, 'Username and password required', 400)

    if not _ensure_tls(conn):
        return _json_response(False, 'Setting a password requires a secure channel (LDAPS or StartTLS) and StartTLS negotiation failed')

    if ou:
        container = ou if ou.lower().startswith('ou=') or ou.lower().startswith('cn=') else f"OU={ou},{conn._baseDN}"
    else:
        container = f"CN=Users,{conn._baseDN}"

    user_dn = f"CN={username},{container}"
    password_value = f'"{password}"'.encode('utf-16-le')

    attrs = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "distinguishedName": user_dn,
        "sAMAccountName": username,
        "userAccountControl": UAC_NORMAL_ACCOUNT_ENABLED,
        "unicodePwd": password_value,
    }

    try:
        if conn.exists(username):
            return _json_response(False, f'User {username} already exists')
        conn.add(user_dn, attributes=attrs)
        return _json_response(True, f'User {username} created', dn=user_dn)
    except Exception as e:
        logging.error(f"user create error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/computer/create', methods=['POST'])
def computer_create():
    conn = get_conn()
    import random
    import string

    name = request.form.get('name', '').strip()
    password = request.form.get('password', '').strip()

    if not name:
        name = ''.join(random.choice(string.ascii_uppercase) for _ in range(8))
    if not name.endswith('$'):
        name = name + '$'
    hostname = name[:-1]

    if not password:
        password = ''.join(random.choice(string.ascii_letters + string.digits + '!@#$%') for _ in range(15))

    if not _ensure_tls(conn):
        return _json_response(False, 'Setting a password requires a secure channel (LDAPS or StartTLS) and StartTLS negotiation failed')

    computer_dn = f"CN={hostname},CN=Computers,{conn._baseDN}"
    spns = [
        f'HOST/{hostname}',
        f'HOST/{hostname}.{conn.domain}',
        f'RestrictedKrbHost/{hostname}',
        f'RestrictedKrbHost/{hostname}.{conn.domain}',
    ]

    attrs = {
        'dnsHostName': f'{hostname}.{conn.domain}',
        'userAccountControl': UAC_WORKSTATION_TRUST,
        'servicePrincipalName': spns,
        'sAMAccountName': name,
        'unicodePwd': f'"{password}"'.encode('utf-16-le'),
    }

    try:
        if conn.exists(name):
            return _json_response(False, f'Computer {name} already exists')
        conn.add(computer_dn, ['top', 'person', 'organizationalPerson', 'user', 'computer'], attrs)
        return _json_response(True, f'Computer {name} created', dn=computer_dn)
    except Exception as e:
        logging.error(f"computer create error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/group/add-member', methods=['POST'])
def group_add_member():
    conn = get_conn()
    group_dn = request.form.get('group_dn', '').strip()
    member = request.form.get('member', '').strip()

    if not group_dn or not member:
        return _json_response(False, 'Missing required fields', 400)

    try:
        member_dn = resolve_target(conn, member)
        if not member_dn:
            return _json_response(False, f'Could not resolve member: {member}')
        conn.modify(group_dn, {'member': [(MODIFY_ADD, [member_dn])]})
        return _json_response(True, f'{member} added to group')
    except Exception as e:
        logging.error(f"group add member error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/group/add-member-by-name', methods=['POST'])
def group_add_member_by_name():
    """Add a member to a group using group sAMAccountName instead of DN."""
    conn = get_conn()
    group = request.form.get('group', '').strip()
    member = request.form.get('member', '').strip()

    if not group or not member:
        return _json_response(False, 'Missing required fields', 400)

    try:
        group_dn = resolve_target(conn, group)
        if not group_dn:
            return _json_response(False, f'Could not resolve group: {group}')
        member_dn = resolve_target(conn, member)
        if not member_dn:
            return _json_response(False, f'Could not resolve member: {member}')
        conn.modify(group_dn, {'member': [(MODIFY_ADD, [member_dn])]})
        return _json_response(True, f'{member} added to {group}')
    except Exception as e:
        logging.error(f"group add member by name error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/group/remove-member', methods=['POST'])
def group_remove_member():
    conn = get_conn()
    group_dn = request.form.get('group_dn', '').strip()
    member = request.form.get('member', '').strip()

    if not group_dn or not member:
        return _json_response(False, 'Missing required fields', 400)

    try:
        member_dn = resolve_target(conn, member)
        if not member_dn:
            return _json_response(False, f'Could not resolve member: {member}')
        conn.modify(group_dn, {'member': [(MODIFY_DELETE, [member_dn])]})
        return _json_response(True, f'{member} removed from group')
    except Exception as e:
        logging.error(f"group remove member error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/user/password', methods=['POST'])
def user_password():
    conn = get_conn()
    dn = request.form.get('dn', '').strip()
    new_password = request.form.get('new_password', '').strip()

    if not dn or not new_password:
        return _json_response(False, 'Missing required fields', 400)

    if not _ensure_tls(conn):
        return _json_response(False, 'Changing a password requires a secure channel (LDAPS or StartTLS) and StartTLS negotiation failed')

    try:
        password_value = f'"{new_password}"'.encode('utf-16-le')
        result = conn.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [password_value])]})
        if result['result'] != 0:
            return _json_response(False, result.get('message', 'LDAP error'))
        return _json_response(True, 'Password changed')
    except Exception as e:
        logging.error(f"password change error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/user/toggle-state', methods=['POST'])
def user_toggle_state():
    conn = get_conn()
    dn = request.form.get('dn', '').strip()
    action = request.form.get('action', '').strip()

    if not dn or action not in ('enable', 'disable'):
        return _json_response(False, 'Invalid parameters', 400)

    UF_ACCOUNT_DISABLE = 2

    try:
        response, _ = ldap_search_with_retry(
            conn, dn, '(objectClass=*)', ['userAccountControl'], ldap3.BASE
        )
        # Find the entry in response
        entry_attrs = None
        for entry in response:
            if entry.get('type') == 'searchResEntry':
                entry_attrs = entry.get('attributes', {})
                break
        if not entry_attrs:
            return _json_response(False, 'Object not found')

        uac = entry_attrs.get('userAccountControl')
        if isinstance(uac, list):
            uac = uac[0] if uac else 0

        if action == 'enable':
            new_uac = uac & ~UF_ACCOUNT_DISABLE
        else:
            new_uac = uac | UF_ACCOUNT_DISABLE

        result = conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
        if result['result'] != 0:
            return _json_response(False, result.get('message', 'LDAP error'))
        return _json_response(True, f'Account {"enabled" if action == "enable" else "disabled"}')
    except Exception as e:
        logging.error(f"toggle state error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/owner/modify', methods=['POST'])
def owner_modify():
    conn = get_conn()
    target = request.form.get('target', '').strip()
    new_owner = request.form.get('new_owner', '').strip()

    if not target or not new_owner:
        return _json_response(False, 'Missing target or new_owner', 400)

    try:
        from pwnAD.commands.modify import owner
        owner(conn, target, new_owner)
        return _json_response(True, f'Owner of {target} changed to {new_owner}')
    except Exception as e:
        logging.error(f"owner modify error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/computer/rename', methods=['POST'])
def computer_rename():
    conn = get_conn()
    current_name = request.form.get('current_name', '').strip()
    new_name = request.form.get('new_name', '').strip()

    if not current_name or not new_name:
        return _json_response(False, 'Missing current_name or new_name', 400)

    try:
        from pwnAD.commands.modify import computer_name
        computer_name(conn, current_name, new_name)
        return _json_response(True, f'Computer renamed from {current_name} to {new_name}')
    except Exception as e:
        logging.error(f"computer rename error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/user/dontreqpreauth', methods=['POST'])
def user_dontreqpreauth():
    conn = get_conn()
    account = request.form.get('account', '').strip()
    flag = request.form.get('flag', 'True').strip()

    if not account:
        return _json_response(False, 'Missing account', 400)

    try:
        from pwnAD.commands.modify import dontreqpreauth
        dontreqpreauth(conn, account, flag)
        action = 'set' if flag == 'True' else 'unset'
        return _json_response(True, f'DONT_REQUIRE_PREAUTH {action} for {account}')
    except Exception as e:
        logging.error(f"dontreqpreauth error: {e}")
        return _json_response(False, str(e))


@actions_bp.route('/principals/search')
def principals_search():
    conn = get_conn()
    query = request.args.get('q', '').strip()
    type_filter = request.args.get('type', '').strip()  # Optional: user, group, computer
    if not query or len(query) < 2:
        return jsonify([])

    try:
        escaped = escape_filter_chars(query)
        # Build object category filter based on type parameter
        if type_filter == 'group':
            category_filter = '(objectCategory=group)'
        elif type_filter == 'user':
            category_filter = '(objectCategory=person)'
        elif type_filter == 'computer':
            category_filter = '(objectCategory=computer)'
        else:
            category_filter = '(|(objectCategory=person)(objectCategory=group)(objectCategory=computer))'
        search_filter = f'(&{category_filter}(sAMAccountName=*{escaped}*))'
        response, _ = ldap_search_with_retry(
            conn, conn._baseDN, search_filter,
            ['sAMAccountName', 'distinguishedName', 'objectClass'],
            ldap3.SUBTREE, size_limit=20
        )
        results = []
        for entry in response:
            if entry.get('type') != 'searchResEntry':
                continue
            obj_classes = entry['attributes'].get('objectClass', [])
            obj_type = 'object'
            if 'computer' in obj_classes:
                obj_type = 'computer'
            elif 'group' in obj_classes:
                obj_type = 'group'
            elif 'user' in obj_classes or 'person' in obj_classes:
                obj_type = 'user'
            results.append({
                'sam': entry['attributes'].get('sAMAccountName', ''),
                'dn': entry['dn'],
                'type': obj_type,
            })
        return jsonify(results)
    except Exception as e:
        logging.error(f"principals search error: {e}")
        return jsonify([])


@actions_bp.route('/create-form/<object_type>')
def create_form(object_type):
    conn = get_conn()
    ctx = {
        'object_type': object_type,
        'domain': conn.domain,
        'base_dn': conn._baseDN,
    }
    return render_template('partials/create_form.html', **ctx)


@actions_bp.route('/object/restore', methods=['POST'])
def object_restore():
    """Restore a deleted object from the AD Recycle Bin."""
    conn = get_conn()
    dn = request.form.get('dn', '').strip()
    new_name = request.form.get('new_name', '').strip() or None
    new_parent = request.form.get('new_parent', '').strip() or None

    if not dn:
        return _json_response(False, 'Missing DN', 400)

    # LDAP control to show/modify deleted objects
    LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
    show_deleted_control = (LDAP_SERVER_SHOW_DELETED_OID, True, None)

    try:
        # Fetch the deleted object attributes
        conn._ldap_connection.search(
            search_base=dn,
            search_filter='(objectClass=*)',
            search_scope=ldap3.BASE,
            attributes=['sAMAccountName', 'msDS-LastKnownRDN', 'lastKnownParent', 'name',
                       'servicePrincipalName', 'userPrincipalName', 'dNSHostName', 'displayName'],
            controls=[show_deleted_control]
        )

        if not conn._ldap_connection.entries:
            return _json_response(False, 'Deleted object not found')

        entry = conn._ldap_connection.entries[0]
        attrs = {attr: entry[attr].value for attr in entry.entry_attributes}

        # Determine the RDN and parent for restoration
        sam_account_name = attrs.get('sAMAccountName', '')
        last_known_rdn = attrs.get('msDS-LastKnownRDN', '')
        last_known_parent = attrs.get('lastKnownParent', '')
        name = attrs.get('name', '')

        # Determine restored RDN
        if new_name:
            restored_rdn = new_name
        elif last_known_rdn:
            restored_rdn = last_known_rdn
        elif name and '\x0a' in name:
            restored_rdn = name.split('\x0a')[0]
        elif name:
            restored_rdn = name
        else:
            return _json_response(False, 'Cannot determine RDN for restoration')

        # Determine parent container
        if new_parent:
            restored_parent = new_parent
        elif last_known_parent:
            restored_parent = last_known_parent
        else:
            return _json_response(False, 'Cannot determine parent container. Specify new_parent.')

        # Build the new DN
        restored_dn = f"CN={restored_rdn},{restored_parent}"

        # Build modifications
        modifications = {
            'isDeleted': [(MODIFY_DELETE, [])],
            'distinguishedName': [(MODIFY_REPLACE, [restored_dn])]
        }

        # Update related attributes if renaming
        if new_name and new_name != last_known_rdn:
            display_name = attrs.get('displayName', '')
            if display_name:
                old_name_part = name.split('\x0a')[0] if '\x0a' in name else name
                modifications['displayName'] = [(MODIFY_REPLACE, [display_name.replace(old_name_part, new_name)])]

            if sam_account_name:
                new_sam = new_name + '$' if sam_account_name.endswith('$') else new_name
                modifications['sAMAccountName'] = [(MODIFY_REPLACE, [new_sam])]

            spn_list = attrs.get('servicePrincipalName', [])
            if spn_list:
                if not isinstance(spn_list, list):
                    spn_list = [spn_list]
                old_name_part = name.split('\x0a')[0] if '\x0a' in name else name
                new_spns = [spn.replace(old_name_part, new_name) for spn in spn_list]
                modifications['servicePrincipalName'] = [(MODIFY_REPLACE, new_spns)]

            upn = attrs.get('userPrincipalName', '')
            if upn and '@' in upn:
                domain_part = upn.split('@')[-1]
                modifications['userPrincipalName'] = [(MODIFY_REPLACE, [f"{new_name}@{domain_part}"])]

            dns_hostname = attrs.get('dNSHostName', '')
            if dns_hostname and '.' in dns_hostname:
                domain_suffix = dns_hostname.split('.', 1)[-1]
                modifications['dNSHostName'] = [(MODIFY_REPLACE, [f"{new_name}.{domain_suffix}"])]

        # Perform the restore
        conn._ldap_connection.modify(
            dn,
            modifications,
            controls=[show_deleted_control]
        )

        result = conn._ldap_connection.result
        if result['result'] == 0:
            return _json_response(True, f'Object restored to {restored_dn}', restored_dn=restored_dn)
        else:
            error_msg = result.get('message', 'Unknown error')
            desc = result.get('description', '')
            return _json_response(False, f'Failed to restore: {desc} - {error_msg}')

    except Exception as e:
        logging.error(f"object restore error: {e}")
        return _json_response(False, str(e))
