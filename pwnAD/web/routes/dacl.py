import copy
import json
import logging
import datetime
from binascii import hexlify, unhexlify
from io import BytesIO

import ldap3
from flask import Blueprint, request, render_template, jsonify, send_file
from impacket.ldap import ldaptypes
from ldap3 import MODIFY_REPLACE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from pwnAD.lib.accesscontrol import (
    ACCESS_FLAGS, DACL_RIGHTS, WELL_KNOWN_SIDS,
    ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_DENIED,
    ACE_TYPE_ACCESS_ALLOWED_OBJECT, ACE_TYPE_ACCESS_DENIED_OBJECT,
    create_ace, parse_ace, guid_to_string, resolve_sid_to_name,
)
from pwnAD.lib.utils import resolve_target
from pwnAD.web.context import get_conn, base_context

dacl_bp = Blueprint('dacl', __name__)


def _get_security_descriptor(conn, target_dn):
    controls = security_descriptor_control(sdflags=0x04)
    conn.search(
        search_base=target_dn,
        search_filter=f'(distinguishedName={escape_filter_chars(target_dn)})',
        attributes=['nTSecurityDescriptor'],
        controls=controls
    )
    if not conn._ldap_connection.entries:
        return None, None
    raw_attrs = conn._ldap_connection.entries[0].entry_raw_attributes
    if 'nTSecurityDescriptor' not in raw_attrs or not raw_attrs['nTSecurityDescriptor']:
        return None, None
    raw_sd = raw_attrs['nTSecurityDescriptor'][0]
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
    return raw_sd, sd


def _set_security_descriptor(conn, target_dn, sd):
    controls = security_descriptor_control(sdflags=0x04)
    try:
        conn.modify(
            target_dn,
            {'nTSecurityDescriptor': [MODIFY_REPLACE, [sd.getData()]]},
            controls=controls
        )
        return True
    except Exception as e:
        logging.error(f"Failed to set security descriptor: {e}")
        return False


def _resolve_principal(conn, principal):
    if principal.upper().startswith("S-1-"):
        dn = conn.get_dn_from_sid(principal)
        return dn, principal
    dn, sid = conn.ldap_get_user(principal)
    return dn, sid


def _parse_aces(conn, sd, principal_filter=None):
    aces = []
    if not sd['Dacl'] or not sd['Dacl'].aces:
        return aces
    for i, ace in enumerate(sd['Dacl'].aces):
        ace_info = parse_ace(ace)
        if principal_filter and ace_info['sid'].upper() != principal_filter.upper():
            continue
        # Resolve SID to name
        ace_info['trustee_name'] = resolve_sid_to_name(conn, ace_info['sid'])
        ace_info['index'] = i
        # Determine inherited
        ace_info['inherited'] = bool(ace_info['ace_flags'] & 0x10)
        aces.append(ace_info)
    return aces


@dacl_bp.route('/dacl')
def dacl_view():
    dn = request.args.get('dn', '').strip()
    ctx = base_context('dacl')
    ctx['target_dn'] = dn
    ctx['dacl_rights'] = DACL_RIGHTS

    if dn:
        conn = get_conn()
        resolved_dn = resolve_target(conn, dn)
        if not resolved_dn:
            ctx['aces'] = []
            ctx['ace_count'] = 0
            ctx['error'] = f'Could not resolve target: {dn}'
            return render_template('dacl_view.html', **ctx)
        dn = resolved_dn
        ctx['target_dn'] = dn
        raw_sd, sd = _get_security_descriptor(conn, dn)
        if sd:
            principal = request.args.get('principal', '').strip()
            principal_sid = None
            if principal:
                try:
                    _, principal_sid = _resolve_principal(conn, principal)
                except Exception:
                    principal_sid = None
                if not principal_sid:
                    ctx['aces'] = []
                    ctx['ace_count'] = 0
                    ctx['error'] = f'Could not resolve principal: {principal}'
                    return render_template('dacl_view.html', **ctx)
            ctx['aces'] = _parse_aces(conn, sd, principal_sid)
            ctx['ace_count'] = len(sd['Dacl'].aces) if sd['Dacl'] else 0
        else:
            ctx['aces'] = []
            ctx['ace_count'] = 0
            ctx['error'] = 'Could not read security descriptor (insufficient permissions?)'
    else:
        ctx['aces'] = None

    return render_template('dacl_view.html', **ctx)


@dacl_bp.route('/dacl/aces')
def dacl_aces():
    conn = get_conn()
    dn = request.args.get('dn', '').strip()
    principal = request.args.get('principal', '').strip()

    if not dn:
        return 'Missing DN', 400

    resolved_dn = resolve_target(conn, dn)
    if not resolved_dn:
        return f'<tr><td colspan="6" class="px-4 py-8 text-center text-neutral-500">Could not resolve target: {dn}</td></tr>'
    dn = resolved_dn

    raw_sd, sd = _get_security_descriptor(conn, dn)
    if not sd:
        return '<tr><td colspan="6" class="px-4 py-8 text-center text-neutral-500">Cannot read DACL</td></tr>'

    principal_sid = None
    if principal:
        try:
            _, principal_sid = _resolve_principal(conn, principal)
        except Exception:
            pass

    aces = _parse_aces(conn, sd, principal_sid)
    return render_template('partials/dacl_table.html', aces=aces, target_dn=dn)


@dacl_bp.route('/dacl/write', methods=['POST'])
def dacl_write():
    conn = get_conn()
    dn = request.form.get('dn', '').strip()
    principal = request.form.get('principal', '').strip()
    right = request.form.get('right', '').strip()
    ace_type = request.form.get('ace_type', 'allowed').strip()

    if not dn or not principal or not right:
        return jsonify(success=False, message='Missing required fields'), 400

    if right not in DACL_RIGHTS:
        return jsonify(success=False, message=f'Unknown right: {right}')

    try:
        _, principal_sid = _resolve_principal(conn, principal)
        if not principal_sid:
            return jsonify(success=False, message=f'Could not resolve principal: {principal}')
    except Exception as e:
        return jsonify(success=False, message=str(e))

    right_config = DACL_RIGHTS[right]
    access_mask = right_config['access_mask']
    object_types = right_config['object_type']

    raw_sd, sd = _get_security_descriptor(conn, dn)
    if not sd:
        return jsonify(success=False, message='Cannot read security descriptor')

    new_sd = copy.deepcopy(sd)

    if isinstance(object_types, list):
        for obj_type in object_types:
            new_ace = create_ace(sid=principal_sid, access_mask=access_mask, object_type=obj_type, ace_type=ace_type)
            new_sd['Dacl'].aces.append(new_ace)
    else:
        new_ace = create_ace(sid=principal_sid, access_mask=access_mask, object_type=object_types, ace_type=ace_type)
        new_sd['Dacl'].aces.append(new_ace)

    if _set_security_descriptor(conn, dn, new_sd):
        return jsonify(success=True, message=f'ACE added: {right} for {principal}')
    return jsonify(success=False, message='Failed to write security descriptor')


@dacl_bp.route('/dacl/remove', methods=['POST'])
def dacl_remove():
    conn = get_conn()
    dn = request.form.get('dn', '').strip()
    ace_index = request.form.get('ace_index', '').strip()

    if not dn:
        return jsonify(success=False, message='Missing DN'), 400

    raw_sd, sd = _get_security_descriptor(conn, dn)
    if not sd:
        return jsonify(success=False, message='Cannot read security descriptor')

    new_sd = copy.deepcopy(sd)

    if ace_index:
        try:
            idx = int(ace_index)
            if 0 <= idx < len(new_sd['Dacl'].aces):
                del new_sd['Dacl'].aces[idx]
            else:
                return jsonify(success=False, message='Invalid ACE index')
        except ValueError:
            return jsonify(success=False, message='Invalid ACE index')
    else:
        return jsonify(success=False, message='Missing ace_index'), 400

    if _set_security_descriptor(conn, dn, new_sd):
        return jsonify(success=True, message='ACE removed')
    return jsonify(success=False, message='Failed to write security descriptor')


@dacl_bp.route('/dacl/backup')
def dacl_backup():
    conn = get_conn()
    dn = request.args.get('dn', '').strip()

    if not dn:
        return 'Missing DN', 400

    raw_sd, sd = _get_security_descriptor(conn, dn)
    if not raw_sd:
        return 'Cannot read security descriptor', 500

    backup_data = {
        "target_dn": dn,
        "security_descriptor": hexlify(raw_sd).decode('utf-8'),
        "backup_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "domain": conn.domain,
    }

    content = json.dumps(backup_data, indent=2)
    safe_name = dn.split(',')[0].replace('=', '_')
    filename = f"{safe_name}_dacl_backup.json"

    return send_file(
        BytesIO(content.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=filename
    )


@dacl_bp.route('/dacl/restore', methods=['POST'])
def dacl_restore():
    conn = get_conn()

    if 'file' not in request.files:
        return jsonify(success=False, message='No file uploaded'), 400

    f = request.files['file']
    try:
        backup_data = json.load(f)
    except json.JSONDecodeError:
        return jsonify(success=False, message='Invalid JSON file')

    required = ['target_dn', 'security_descriptor']
    for field in required:
        if field not in backup_data:
            return jsonify(success=False, message=f'Missing field: {field}')

    target_dn = backup_data['target_dn']
    try:
        raw_sd = unhexlify(backup_data['security_descriptor'])
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
    except Exception as e:
        return jsonify(success=False, message=f'Invalid security descriptor: {e}')

    if _set_security_descriptor(conn, target_dn, sd):
        return jsonify(success=True, message=f'DACL restored for {target_dn}')
    return jsonify(success=False, message='Failed to restore DACL')
