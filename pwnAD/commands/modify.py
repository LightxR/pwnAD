import copy
import ldap3
import random
import string
import logging
from pwnAD.lib.logger import BRIGHT_GREEN, RESET
from impacket.ldap import ldaptypes
from ldap3 import MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.protocol.formatters.formatters import format_sid

from pwnAD.lib.accesscontrol import ACCOUNT_FLAGS
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
        conn.modify(targetDN, {'unicodePwd': [(ldap3.MODIFY_REPLACE, [f'"{new_password}"'.encode('utf-16-le')])]})
        logging.info(f"Successfully changed password for {account}")
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
        logging.debug(f"Found new owner SID: {new_owner_SID}")
    except IndexError:
        logging.error(f'New owner SID not found in LDAP ({new_owner})')
        return

    current_owner_SID = format_sid(target_principal_security_descriptor['OwnerSid']).formatCanonical()
    logging.info("Current owner information below")
    logging.info(f"- SID: {current_owner_SID}")
    logging.info(f"- sAMAccountName: {conn.get_samaccountname_from_sid(current_owner_SID)}")
    conn._ldap_connection.search(conn._baseDN, '(objectSid=%s)' % current_owner_SID, attributes=['distinguishedName'])
    current_owner_distinguished_name = conn._ldap_connection.entries[0]
    logging.info(f"- distinguishedName: {current_owner_distinguished_name['distinguishedName']}")

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
    if len(conn._ldap_connection.entries) != 1:
        logging.error(f"Computer not found in LDAP: {current_name}")
        return

    entry = conn._ldap_connection.entries[0]
    computer_dn = entry.entry_dn
    sam_account_name = entry["samAccountName"].value
    logging.info(f"Original sAMAccountName: {sam_account_name}")

    logging.info(f"New sAMAccountName: {new_name}")

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
    dont_req_preauth = ACCOUNT_FLAGS["DONT_REQ_PREAUTH"]

    conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(account), attributes=['objectSid', 'userAccountControl'])
    if len(conn._ldap_connection.entries) != 1:
        logging.error(f"User not found in LDAP: {account}")
        return

    entry = conn._ldap_connection.entries[0]
    user_dn = entry.entry_dn
    uac = entry["userAccountControl"].value
    logging.info(f"Original userAccountControl: {uac}")

    set_flag = flag == "True"

    if set_flag:
        uac = uac | dont_req_preauth
    else:
        uac = uac & ~dont_req_preauth

    logging.info(f"Updated userAccountControl: {uac}") 

    try:
        conn.modify(user_dn, {'userAccountControl': (ldap3.MODIFY_REPLACE, [uac])})
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
    account_disable = ACCOUNT_FLAGS["ACCOUNTDISABLE"]
    conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(user_name), attributes=['objectSid', 'userAccountControl'])

    if len(conn._ldap_connection.entries) != 1:
        logging.error("Error expected only one search result got %d results", len(conn._ldap_connection.entries))
        return

    user_dn = conn._ldap_connection.entries[0].entry_dn
    if not user_dn:
        logging.error(f"User not found in LDAP: {user_name}")
        return

    entry = conn._ldap_connection.entries[0]
    uac = int(entry["userAccountControl"].value)

    logging.info(f"Original userAccountControl: {uac}")

    if enable:
        uac = uac & ~account_disable
    else:
        uac = uac | account_disable

    try:
        conn.modify(user_dn, {'userAccountControl': (ldap3.MODIFY_REPLACE, [uac])})
        logging.info("Updated userAccountControl attribute successfully")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def restore_deleted(conn, target: str, new_name: str = None, new_parent: str = None):
    """
    Restore a deleted object from the AD Recycle Bin.

    This function restores a deleted object by:
    1. Finding it in the Deleted Objects container
    2. Removing the isDeleted attribute
    3. Moving it to its original or a new parent container

    Args:
        conn: LDAP connection object
        target: Target identifier (sAMAccountName, objectSid, or DN of deleted object)
        new_name: Optional new name for the restored object (updates sAMAccountName, UPN, SPN)
        new_parent: Optional new parent container DN (default: original lastKnownParent)

    Note:
        Requires the following permissions:
        - "Reanimate Tombstones" right on the domain object
        - Generic Write on the deleted object
        - Create Child right on the target container

    Example:
        modify restore_deleted user1
        modify restore_deleted S-1-5-21-xxx-1234
        modify restore_deleted user1 --new-name user1_restored
        modify restore_deleted user1 --new-parent "OU=Restored,DC=corp,DC=local"
    """
    # LDAP control to show deleted objects
    LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
    show_deleted_control = (LDAP_SERVER_SHOW_DELETED_OID, True, None)

    # Build search filter based on target type
    target = target.strip()
    escaped_target = escape_filter_chars(target)

    if target.lower().startswith("cn=") or target.lower().startswith("dc="):
        # DN - need to double-encode special chars in deleted object DNs
        ldap_filter = f"(&(isDeleted=TRUE)(distinguishedName={escaped_target}))"
    elif target.startswith("S-1-"):
        # SID
        ldap_filter = f"(&(isDeleted=TRUE)(objectSid={escaped_target}))"
    else:
        # sAMAccountName
        ldap_filter = f"(&(isDeleted=TRUE)(sAMAccountName={escaped_target}))"

    # Search in Deleted Objects container
    deleted_objects_dn = f"CN=Deleted Objects,{conn._baseDN}"

    attributes = [
        'distinguishedName',
        'sAMAccountName',
        'msDS-LastKnownRDN',
        'lastKnownParent',
        'name',
        'objectClass',
        'servicePrincipalName',
        'userPrincipalName',
        'dNSHostName',
        'displayName'
    ]

    try:
        conn._ldap_connection.search(
            search_base=deleted_objects_dn,
            search_filter=ldap_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            controls=[show_deleted_control]
        )

        entries = conn._ldap_connection.entries

        if not entries:
            logging.error(f"Deleted object not found: {target}")
            return

        if len(entries) > 1:
            logging.warning(f"Multiple deleted objects match '{target}'. Using the first one.")
            for i, entry in enumerate(entries):
                sam = entry.entry_attributes_as_dict.get('sAMAccountName', [''])[0] if entry.entry_attributes_as_dict.get('sAMAccountName') else ''
                logging.info(f"  [{i}] {sam} - {entry.entry_dn}")

        entry = entries[0]
        attrs = entry.entry_attributes_as_dict

        # Get the current values
        deleted_dn = entry.entry_dn
        sam_account_name = attrs.get('sAMAccountName', [''])[0] if attrs.get('sAMAccountName') else ''
        last_known_rdn = attrs.get('msDS-LastKnownRDN', [''])[0] if attrs.get('msDS-LastKnownRDN') else ''
        last_known_parent = attrs.get('lastKnownParent', [''])[0] if attrs.get('lastKnownParent') else ''
        name = attrs.get('name', [''])[0] if attrs.get('name') else ''
        spn_list = attrs.get('servicePrincipalName', [])
        upn = attrs.get('userPrincipalName', [''])[0] if attrs.get('userPrincipalName') else ''
        dns_hostname = attrs.get('dNSHostName', [''])[0] if attrs.get('dNSHostName') else ''
        display_name = attrs.get('displayName', [''])[0] if attrs.get('displayName') else ''

        # Determine the RDN to use for the restored object
        if new_name:
            restored_rdn = new_name
        elif last_known_rdn:
            restored_rdn = last_known_rdn
        else:
            # Extract RDN from the name (before \0ADEL:)
            if name and '\x0a' in name:
                restored_rdn = name.split('\x0a')[0]
            elif name:
                restored_rdn = name
            else:
                logging.error("Cannot determine RDN for restoration")
                return

        # Determine the parent container
        if new_parent:
            restored_parent = new_parent
        elif last_known_parent:
            restored_parent = last_known_parent
        else:
            logging.error("Cannot determine parent container for restoration. Use --new-parent to specify.")
            return

        # Build the new DN
        new_dn = f"CN={restored_rdn},{restored_parent}"

        logging.info(f"Restoring deleted object:")
        logging.info(f"  Original sAMAccountName: {sam_account_name}")
        logging.info(f"  Deleted DN: {deleted_dn}")
        logging.info(f"  New DN: {new_dn}")

        # Build the modification dictionary
        # The key is to:
        # 1. Delete the isDeleted attribute
        # 2. Modify the distinguishedName (move the object)
        modifications = {
            'isDeleted': [(ldap3.MODIFY_DELETE, [])],
            'distinguishedName': [(ldap3.MODIFY_REPLACE, [new_dn])]
        }

        # If renaming, update related attributes
        if new_name and new_name != last_known_rdn:
            # Update displayName if it existed
            if display_name:
                new_display_name = display_name.replace(name.split('\x0a')[0] if '\x0a' in name else name, new_name)
                modifications['displayName'] = [(ldap3.MODIFY_REPLACE, [new_display_name])]

            # Update sAMAccountName
            if sam_account_name:
                # Preserve $ suffix for computer accounts
                if sam_account_name.endswith('$'):
                    new_sam = new_name + '$' if not new_name.endswith('$') else new_name
                else:
                    new_sam = new_name
                modifications['sAMAccountName'] = [(ldap3.MODIFY_REPLACE, [new_sam])]

            # Update servicePrincipalName
            if spn_list:
                old_name_part = name.split('\x0a')[0] if '\x0a' in name else name
                new_spns = [spn.replace(old_name_part, new_name) for spn in spn_list]
                modifications['servicePrincipalName'] = [(ldap3.MODIFY_REPLACE, new_spns)]

            # Update userPrincipalName
            if upn:
                domain_part = upn.split('@')[-1] if '@' in upn else ''
                if domain_part:
                    modifications['userPrincipalName'] = [(ldap3.MODIFY_REPLACE, [f"{new_name}@{domain_part}"])]

            # Update dNSHostName
            if dns_hostname:
                domain_suffix = dns_hostname.split('.', 1)[-1] if '.' in dns_hostname else ''
                if domain_suffix:
                    modifications['dNSHostName'] = [(ldap3.MODIFY_REPLACE, [f"{new_name}.{domain_suffix}"])]

        # Perform the restore operation
        try:
            conn._ldap_connection.modify(
                deleted_dn,
                modifications,
                controls=[show_deleted_control]
            )

            if conn._ldap_connection.result['result'] == 0:
                logging.info(f"{BRIGHT_GREEN}Successfully restored {sam_account_name or target} to {new_dn}{RESET}")
            else:
                error_msg = conn._ldap_connection.result.get('message', 'Unknown error')
                desc = conn._ldap_connection.result.get('description', '')
                logging.error(f"Failed to restore object: {desc} - {error_msg}")

        except ldap3.core.exceptions.LDAPException as e:
            error_code = conn._ldap_connection.result['result']
            if 'userPrincipalName' in str(e) and error_code == 19:
                logging.error("Restore failed: userPrincipalName is already in use by another object")
            else:
                check_error(conn, error_code, e)

    except ldap3.core.exceptions.LDAPException as e:
        if "noSuchObject" in str(e):
            logging.error("Deleted Objects container not found. AD Recycle Bin may not be enabled.")
        else:
            logging.error(f"LDAP error: {e}")
    except Exception as e:
        logging.error(f"Error restoring deleted object: {e}")


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
