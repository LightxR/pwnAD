import copy
import ldap3
import random
import string
import logging
from impacket.ldap import ldaptypes
from ldap3 import MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars

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

    _, new_sid = conn.ldap_get_user(new_owner)
    target_dn, _ = conn.ldap_get_user(target)
 
    res = conn.search(search_base=target_dn, search_filter=f'(distinguishedName={target_dn})', attributes=['nTSecurityDescriptor'])
    if res is None:
        logging.error('Failed to get forest\'s SD')

    target_dn_sd = conn._ldap_connection.entries[0].entry_raw_attributes
    if target_dn_sd['nTSecurityDescriptor'] == []:
        return "User doesn't have right read nTSecurityDescriptor!"

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target_dn_sd['nTSecurityDescriptor'][0])
    new_sd = copy.deepcopy(sd)
    old_sid = new_sd['OwnerSid'].formatCanonical()

    if old_sid == new_sid:
        logging.warning(f"[!] {old_sid} is already the owner, no modification will be made")
    else:
        new_sd["OwnerSid"].fromCanonical(new_sid)

        try:
            conn.modify(target_dn, {'nTSecurityDescriptor': [MODIFY_REPLACE, [new_sd.getData()]]})
            logging.info(f"Old owner {old_sid} is now replaced by {new_owner} on {target}")
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
    userAccountControl = entry["userAccountControl"].value

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
