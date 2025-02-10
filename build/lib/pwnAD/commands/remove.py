import copy
import logging
from impacket.ldap import ldaptypes
from ldap3 import MODIFY_DELETE, MODIFY_REPLACE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from pwnAD.lib.accesscontrol import *
from pwnAD.lib.utils import check_error


def computer(conn, computer_name):
    if computer_name[-1] != '$':
        computer_name = computer_name + '$'

    res = conn.exists(computer_name)
    if not res:
        logging.error(f"Account %s not found in %s!" % (computer_name, conn._baseDN))
        return

    computer = conn.get(computer_name)
    logging.debug(f"LDAP result for computer : {computer}")
    try:
        conn.delete(computer.entry_dn)
        logging.info("Successfully deleted %s." % computer_name)
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def user(conn, user_name):

    res = conn.exists(user_name)
    print(res)
    if not res:
        logging.error("Account %s not found in %s!" % (user_name, conn._baseDN))
        return

    user= conn.get(user_name)
    logging.debug(f"LDAP result for user : {user}")

    try:
        conn.delete(user.entry_dn)
        logging.info("Successfully deleted %s." % user_name)
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def groupMember(conn, group: str, member: str):

    user_dn = conn.get_dn_from_samaccountname(member, 'user')
    group_dn = conn.get_dn_from_samaccountname(group, 'group')

    try:
        conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
        logging.info(f"{member} successfully removed from {group} !")
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)    


def dcsync(conn, trustee):

    targetDN, targetSID = conn.ldap_get_user(trustee)
    logging.debug(f"targetSID : {targetSID}")

    res = conn.search(search_base=conn._baseDN, 
                      search_filter=f'(distinguishedName={conn._baseDN})', 
                      attributes=['nTSecurityDescriptor'])
    if res is None:
        logging.error('Failed to get forest\'s SD')

    baseDN_sd = conn._ldap_connection.entries[0].entry_raw_attributes
    if baseDN_sd['nTSecurityDescriptor'] == []:
        raise Exception("User doesn't have right to read nTSecurityDescriptor!")

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=baseDN_sd['nTSecurityDescriptor'][0])
    new_sd = copy.deepcopy(sd)

    new_aces = []
    for ace in new_sd['Dacl'].aces:
        logging.debug(f"SID found : {ace['Ace']['Sid'].formatCanonical()}")

        if ace['Ace']['Sid'].formatCanonical() == targetSID:
            if ace['Ace']['Sid'].formatCanonical() == targetSID and ace['Ace']['Mask']['Mask'] & ACCESS_FLAGS["FULL_CONTROL"]:
                logging.info(f"Removing ACE from {targetDN}")
                continue  
        new_aces.append(ace)
    new_sd['Dacl'].aces = new_aces

    try:
        conn.modify(conn._baseDN, 
                      {'nTSecurityDescriptor': [MODIFY_REPLACE, [new_sd.getData()]]}, 
                      controls=security_descriptor_control(sdflags=0x04))  # SDFlags = 0x04 pour DACL uniquement
        logging.info(f"Successfully removed DCSYNC rights from user '{trustee}'!")
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)  


def genericAll(conn, target, trustee):
    _, trusteeSID = conn.ldap_get_user(trustee)
    targetDN, _ = conn.ldap_get_user(target)

    res = conn.search(
        search_base=targetDN,
        search_filter=f'(distinguishedName={targetDN})',
        attributes=['nTSecurityDescriptor']
    )
    if res is None:
        logging.error("Failed to get target's SD")
        return

    targetDN_sd = conn._ldap_connection.entries[0].entry_raw_attributes
    if targetDN_sd['nTSecurityDescriptor'] == []:
        raise Exception("Cannot read nTSecurityDescriptor!")

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=targetDN_sd['nTSecurityDescriptor'][0])
    new_sd = copy.deepcopy(sd)

    original_count = len(new_sd['Dacl'].aces)
    new_sd['Dacl'].aces = [
        ace for ace in new_sd['Dacl'].aces
        if not (ace['Ace']['Sid'].formatCanonical() == trusteeSID and ace['Ace']['Mask']['Mask'] & ACCESS_FLAGS["FULL_CONTROL"])
    ]

    if len(new_sd['Dacl'].aces) == original_count:
        logging.warning("No GenericAll rights found for '%s' on '%s'" % (trustee, target))
        return

    try:
        conn.modify(targetDN, {'nTSecurityDescriptor': [MODIFY_REPLACE, [new_sd.getData()]]})
        logging.info("Removed GenericAll rights for '%s' on '%s'!" % (trustee, target))
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)    


def RBCD(conn, computer_name):

    success = conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(computer_name), attributes=['objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
    if success is False or len(conn._ldap_connection.entries) != 1:
        logging.error("Error expected only one search result got %d results", len(conn._ldap_connection.entries))
        return

    target = conn._ldap_connection.entries[0]
    target_sid = target["objectsid"].value
    logging.info("Found Target DN: %s" % target.entry_dn)
    logging.info("Target SID: %s\n" % target_sid)

    sd = create_empty_sd()

    try:
        conn.modify(target.entry_dn, {'msDS-AllowedToActOnBehalfOfOtherIdentity':[MODIFY_REPLACE, [sd.getData()]]})
        logging.info('Delegation rights cleared successfully!')
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e) 