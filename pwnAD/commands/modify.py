import copy
import ldap3
import random
import string
import logging
from impacket.ldap import ldaptypes
from ldap3 import MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.protocol.formatters.formatters import format_sid

from pwnAD.lib.utils import check_error, resolve_target, encode_ldap_value


def password(conn, account, new_password):
    """
    Change the password of a user account.

    Args:
        conn: LDAP connection object
        account: sAMAccountName of the user
        new_password: New password (random 32 chars if False)
    """
    if new_password is False:
        new_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

    targetDN, _ = conn.ldap_get_user(account)

    try:
        conn.modify(targetDN, {'unicodePwd': [(ldap3.MODIFY_REPLACE, ['"{}"'.format(new_password).encode('utf-16-le')])]})
        logging.info("Successfully changed %s password to: %s" % (account, new_password))
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def owner(conn, target: str, new_owner: str):
    """
    Change the owner of a target object.

    Args:
        conn: LDAP connection object
        target: sAMAccountName of the target object
        new_owner: sAMAccountName of the new owner
    """
    target_dn, _ = conn.ldap_get_user(target)
    controls = security_descriptor_control(sdflags=0x01)
    conn.search(search_base=conn._baseDN, search_filter=f'(distinguishedName={target_dn})', attributes=['nTSecurityDescriptor'], controls=controls)
    try:
        target_principal = conn._ldap_connection.entries[0]
        logging.debug(f'Target principal found in LDAP : {target}')
    except IndexError:
        logging.error(f'Target principal not found in LDAP : {target}')
        return
    
    target_principal_raw_security_descriptor = target_principal['nTSecurityDescriptor'].raw_values[0]
    target_principal_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target_principal_raw_security_descriptor)

    conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(new_owner), attributes=['objectSid'])
    try:
        new_owner_SID = format_sid(conn._ldap_connection.entries[0]['objectSid'].raw_values[0])
        logging.debug("Found new owner SID: %s" % new_owner_SID)
    except IndexError:
        logging.error('New owner SID not found in LDAP (%s)' % target)
        return

    current_owner_SID = format_sid(target_principal_security_descriptor['OwnerSid']).formatCanonical()
    logging.info("Current owner information below")
    logging.info("- SID: %s" % current_owner_SID)
    logging.info("- sAMAccountName: %s" % conn.get_samaccountname_from_sid(current_owner_SID))
    conn._ldap_connection.search(conn._baseDN, '(objectSid=%s)' % current_owner_SID, attributes=['distinguishedName'])
    current_owner_distinguished_name = conn._ldap_connection.entries[0]
    logging.info("- distinguishedName: %s" % current_owner_distinguished_name['distinguishedName'])

    logging.debug('Attempt to modify the OwnerSid')
    _new_owner_SID = ldaptypes.LDAP_SID()
    _new_owner_SID.fromCanonical(new_owner_SID)
    target_principal_security_descriptor['OwnerSid'] = _new_owner_SID

    try:
        conn.modify(
            target_principal.entry_dn,
            {'nTSecurityDescriptor': (ldap3.MODIFY_REPLACE, [
                target_principal_security_descriptor.getData()
            ])},
            controls=security_descriptor_control(sdflags=0x01))
        logging.info('OwnerSid modified successfully!')
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def computer_name(conn, current_name, new_name):
    """
    Rename a computer account (change sAMAccountName).

    Args:
        conn: LDAP connection object
        current_name: Current sAMAccountName
        new_name: New sAMAccountName
    """
    conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(current_name), attributes=['objectSid', 'sAMAccountName'])
    computer_dn = conn._ldap_connection.entries[0].entry_dn
    if not computer_dn:
        return "Computer not found in LDAP: %s" % current_name

    entry = conn._ldap_connection.entries[0]
    samAccountName = entry["samAccountName"].value
    logging.info("Original sAMAccountName: %s" % samAccountName)

    logging.info("New sAMAccountName: %s" % new_name)

    try:
        conn.modify(computer_dn, {'sAMAccountName':(ldap3.MODIFY_REPLACE, [new_name])})
        logging.info("Updated sAMAccountName successfully")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def dontreqpreauth(conn, account, flag):
    """
    Set or unset the DONT_REQUIRE_PREAUTH flag on an account.

    Args:
        conn: LDAP connection object
        account: sAMAccountName of the account
        flag: "True" to set flag, "False" to unset
    """
    UF_DONT_REQUIRE_PREAUTH = 4194304

    conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(account), attributes=['objectSid', 'userAccountControl'])
    user_dn = conn._ldap_connection.entries[0].entry_dn
    if not user_dn:
        return "User not found in LDAP: %s" % account

    entry = conn._ldap_connection.entries[0]
    userAccountControl = entry["userAccountControl"].value
    logging.info("Original userAccountControl: %d" % userAccountControl) 

    set_flag = True if flag == "True" else False

    if set_flag:
        userAccountControl = userAccountControl | UF_DONT_REQUIRE_PREAUTH
    else:
        userAccountControl = userAccountControl & ~UF_DONT_REQUIRE_PREAUTH

    logging.info("Updated userAccountControl: %d" % userAccountControl) 

    try:
        conn.modify(user_dn, {'userAccountControl':(ldap3.MODIFY_REPLACE, [userAccountControl])})
        logging.info("Updated userAccountControl attribute successfully")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def disable_account(conn, username):
    """Disable a user account."""
    _toggle_account_enable_disable(conn, username, False)

def enable_account(conn, username):
    """Enable a user account."""
    _toggle_account_enable_disable(conn, username, True)

def _toggle_account_enable_disable(conn, user_name, enable):
    """
    Internal helper to enable or disable an account.

    Args:
        conn: LDAP connection object
        user_name: sAMAccountName of the user
        enable: True to enable, False to disable
    """
    UF_ACCOUNT_DISABLE = 2
    conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(user_name), attributes=['objectSid', 'userAccountControl'])

    if len(conn._ldap_connection.entries) != 1:
        logging.error("Error expected only one search result got %d results", len(conn._ldap_connection.entries))
        return

    user_dn = conn._ldap_connection.entries[0].entry_dn
    if not user_dn:
        logging.error("User not found in LDAP: %s" % user_name)
        return

    entry = conn._ldap_connection.entries[0]
    userAccountControl = entry["userAccountControl"].value

    logging.info("Original userAccountControl: %d" % userAccountControl)

    if enable:
        userAccountControl = userAccountControl & ~UF_ACCOUNT_DISABLE
    else:
        userAccountControl = userAccountControl | UF_ACCOUNT_DISABLE

    try:
        conn.modify(user_dn, {'userAccountControl':(ldap3.MODIFY_REPLACE, [userAccountControl])})
        logging.info("Updated userAccountControl attribute successfully")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def attribute(conn, target: str, attr: str, values: list, raw: bool = False, b64: bool = False):
    """
    Replace/set an attribute value on any LDAP object.

    This function provides generic replace/set capability for any AD object's attributes,
    supporting multiple target identification formats (sAMAccountName, DN, SID).

    Args:
        conn: LDAP connection object
        target: Target identifier (sAMAccountName, DN, or SID)
        attr: Name of the attribute to modify
        values: List of values to set
        raw: If True, send values as-is without encoding (default: False)
        b64: If True, decode values from base64 first (default: False)

    Example:
        modify attribute user1 description "New description"
        modify attribute user1 userAccountControl 514
        modify attribute computer1$ servicePrincipalName HTTP/server.domain.local
    """
    # Resolve target to DN
    target_dn = resolve_target(conn, target)
    if not target_dn:
        return

    # Encode values
    encoded_values = []
    for value in values:
        encoded_value = encode_ldap_value(attr, value, raw=raw, b64=b64)
        if encoded_value is None:
            logging.error(f"Failed to encode value: {value}")
            return
        encoded_values.append(encoded_value)

    # Perform the modification
    try:
        logging.debug(f"Replacing {target_dn}: {attr} = {encoded_values}")
        conn.modify(target_dn, {attr: [(ldap3.MODIFY_REPLACE, encoded_values)]})
        logging.info(f"Successfully set attribute '{attr}' on {target}")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)
    except Exception as e:
        logging.error(f"Error modifying object: {e}")
