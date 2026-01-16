"""
DACL module for pwnAD - ACE manipulation on AD objects.
Based on dacledit.py (https://github.com/fortra/impacket/blob/master/examples/dacledit.py)

This module provides functionality to read, write, remove, backup, and restore
Discretionary Access Control Lists (DACLs) on Active Directory objects.
"""

import copy
import json
import logging
import datetime
from binascii import hexlify, unhexlify

import ldap3
from impacket.ldap import ldaptypes
from ldap3 import MODIFY_REPLACE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from pwnAD.lib.accesscontrol import (
    ACCESS_FLAGS,
    ACE_TYPE_NAMES,
    ACE_TYPE_ACCESS_ALLOWED,
    ACE_TYPE_ACCESS_DENIED,
    ACE_TYPE_ACCESS_ALLOWED_OBJECT,
    ACE_TYPE_ACCESS_DENIED_OBJECT,
    DACL_RIGHTS,
    WELL_KNOWN_SIDS,
    create_ace,
    create_deny_ace,
    parse_ace,
    ace_matches,
    guid_to_string,
    resolve_sid_to_name,
    get_rights_from_mask,
)
from pwnAD.lib.utils import check_error


def _resolve_target(conn, target):
    """
    Resolve a target identifier to its DN.

    Args:
        conn: LDAP connection object
        target: Target identifier (sAMAccountName, SID, or DN)

    Returns:
        str: Distinguished Name of the target, or None if not found
    """
    # Check if already a DN
    if target.lower().startswith("cn=") or target.lower().startswith("dc="):
        return target

    # Check if it's a SID
    if target.upper().startswith("S-1-"):
        dn = conn.get_dn_from_sid(target)
        if dn:
            return dn
        logging.error(f"Could not find object with SID: {target}")
        return None

    # Assume it's a sAMAccountName - try multiple object classes
    for obj_class in ['*', 'user', 'computer', 'group']:
        if obj_class == '*':
            search_filter = f"(sAMAccountName={escape_filter_chars(target)})"
        else:
            search_filter = f"(&(objectClass={obj_class})(sAMAccountName={escape_filter_chars(target)}))"

        conn.search(
            conn._baseDN,
            search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName']
        )

        if conn._ldap_connection.entries:
            return conn._ldap_connection.entries[0].distinguishedName.value

    logging.error(f"Could not find object: {target}")
    return None


def _resolve_principal(conn, principal):
    """
    Resolve a principal identifier to its DN and SID.

    Args:
        conn: LDAP connection object
        principal: Principal identifier (sAMAccountName or SID)

    Returns:
        tuple: (DN, SID) or (None, None) if not found
    """
    # Check if it's a SID
    if principal.upper().startswith("S-1-"):
        dn = conn.get_dn_from_sid(principal)
        return dn, principal

    # Assume it's a sAMAccountName
    dn, sid = conn.ldap_get_user(principal)
    return dn, sid


def _get_security_descriptor(conn, target_dn):
    """
    Get the security descriptor of an object.

    Args:
        conn: LDAP connection object
        target_dn: Distinguished Name of the target

    Returns:
        tuple: (raw_bytes, parsed_sd) or (None, None) on error
    """
    controls = security_descriptor_control(sdflags=0x04)  # DACL only

    conn.search(
        search_base=target_dn,
        search_filter=f'(distinguishedName={escape_filter_chars(target_dn)})',
        attributes=['nTSecurityDescriptor'],
        controls=controls
    )

    if not conn._ldap_connection.entries:
        logging.error(f"Object not found: {target_dn}")
        return None, None

    raw_attrs = conn._ldap_connection.entries[0].entry_raw_attributes
    if 'nTSecurityDescriptor' not in raw_attrs or not raw_attrs['nTSecurityDescriptor']:
        logging.error("Cannot read nTSecurityDescriptor attribute (insufficient permissions?)")
        return None, None

    raw_sd = raw_attrs['nTSecurityDescriptor'][0]
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)

    return raw_sd, sd


def _set_security_descriptor(conn, target_dn, sd):
    """
    Set the security descriptor of an object.

    Args:
        conn: LDAP connection object
        target_dn: Distinguished Name of the target
        sd: Security descriptor to set

    Returns:
        bool: True on success, False on error
    """
    controls = security_descriptor_control(sdflags=0x04)  # DACL only

    try:
        conn.modify(
            target_dn,
            {'nTSecurityDescriptor': [MODIFY_REPLACE, [sd.getData()]]},
            controls=controls
        )
        return True
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)
        return False


def read(conn, target, principal=None, resolve_sids=False):
    """
    Read and display the DACL of an object.

    Args:
        conn: LDAP connection object
        target: Target object (sAMAccountName, SID, or DN)
        principal: Optional filter by principal
        resolve_sids: Whether to resolve SIDs to names
    """
    target_dn = _resolve_target(conn, target)
    if not target_dn:
        return

    # If filtering by principal, resolve it to get the SID
    principal_sid = None
    if principal:
        _, principal_sid = _resolve_principal(conn, principal)
        if not principal_sid:
            logging.error(f"Could not resolve principal: {principal}")
            return

    raw_sd, sd = _get_security_descriptor(conn, target_dn)
    if not sd:
        return

    logging.info(f"DACL for: {target_dn}")
    logging.info("-" * 80)

    if not sd['Dacl'] or not sd['Dacl'].aces:
        logging.info("No ACEs in DACL")
        return

    ace_count = 0
    for i, ace in enumerate(sd['Dacl'].aces):
        ace_info = parse_ace(ace)

        # Filter by principal if specified
        if principal_sid:
            if ace_info['sid'].upper() != principal_sid.upper():
                continue

        ace_count += 1

        # Build output in dacledit.py format
        print(f"\n[*]   ACE[{i}] info")

        # ACE Type
        print(f"[*]     ACE Type                  : {ace_info['type']}")

        # ACE flags
        ace_flags_display = "None"
        if ace_info['ace_flags']:
            flags_str = []
            if ace_info['ace_flags'] & 0x01:
                flags_str.append("OBJECT_INHERIT_ACE")
            if ace_info['ace_flags'] & 0x02:
                flags_str.append("CONTAINER_INHERIT_ACE")
            if ace_info['ace_flags'] & 0x04:
                flags_str.append("NO_PROPAGATE_INHERIT_ACE")
            if ace_info['ace_flags'] & 0x08:
                flags_str.append("INHERIT_ONLY_ACE")
            if ace_info['ace_flags'] & 0x10:
                flags_str.append("INHERITED_ACE")
            if ace_info['ace_flags'] & 0x40:
                flags_str.append("SUCCESSFUL_ACCESS_ACE_FLAG")
            if ace_info['ace_flags'] & 0x80:
                flags_str.append("FAILED_ACCESS_ACE_FLAG")
            if flags_str:
                ace_flags_display = ", ".join(flags_str)
        print(f"[*]     ACE flags                 : {ace_flags_display}")

        # Access mask
        rights_display = ", ".join(ace_info['rights']) if ace_info['rights'] else "Unknown"
        print(f"[*]     Access mask               : {rights_display}")

        # Flags (object ACE flags)
        if ace_info['object_ace_flags']:
            print(f"[*]     Flags                     : {', '.join(ace_info['object_ace_flags'])}")

        # Object type (GUID)
        if ace_info['object_type']:
            if ace_info.get('object_type_name'):
                print(f"[*]     Object type (GUID)        : {ace_info['object_type_name']} ({ace_info['object_type'].lower()})")
            else:
                print(f"[*]     Object type (GUID)        : {ace_info['object_type'].lower()}")

        # Inherited type (GUID)
        if ace_info['inherited_object_type']:
            if ace_info.get('inherited_object_type_name'):
                print(f"[*]     Inherited type (GUID)     : {ace_info['inherited_object_type_name']} ({ace_info['inherited_object_type'].lower()})")
            else:
                print(f"[*]     Inherited type (GUID)     : {ace_info['inherited_object_type'].lower()}")

        # Trustee (SID)
        if resolve_sids:
            sid_name = resolve_sid_to_name(conn, ace_info['sid'])
            print(f"[*]     Trustee (SID)             : {sid_name} ({ace_info['sid']})")
        else:
            # Try to resolve SID even if not explicitly requested
            sid_name = resolve_sid_to_name(conn, ace_info['sid'])
            if sid_name != ace_info['sid']:
                print(f"[*]     Trustee (SID)             : {sid_name} ({ace_info['sid']})")
            else:
                print(f"[*]     Trustee (SID)             : {ace_info['sid']}")

    logging.info(f"\nTotal ACEs displayed: {ace_count}")


def write(conn, target, principal, right, ace_type="allowed", inheritance=False):
    """
    Add an ACE to the DACL of an object.

    Args:
        conn: LDAP connection object
        target: Target object (sAMAccountName, SID, or DN)
        principal: Principal to grant/deny rights (sAMAccountName or SID)
        right: Right to grant (from DACL_RIGHTS)
        ace_type: 'allowed' or 'denied'
        inheritance: Whether to set inheritance flags
    """
    target_dn = _resolve_target(conn, target)
    if not target_dn:
        return

    _, principal_sid = _resolve_principal(conn, principal)
    if not principal_sid:
        logging.error(f"Could not resolve principal: {principal}")
        return

    if right not in DACL_RIGHTS:
        logging.error(f"Unknown right: {right}")
        logging.info(f"Available rights: {', '.join(DACL_RIGHTS.keys())}")
        return

    right_config = DACL_RIGHTS[right]
    access_mask = right_config['access_mask']
    object_types = right_config['object_type']

    # Get current security descriptor
    raw_sd, sd = _get_security_descriptor(conn, target_dn)
    if not sd:
        return

    new_sd = copy.deepcopy(sd)

    # Handle rights that require multiple ACEs (like DCSync)
    if isinstance(object_types, list):
        for obj_type in object_types:
            new_ace = create_ace(
                sid=principal_sid,
                access_mask=access_mask,
                object_type=obj_type,
                ace_type=ace_type,
                inheritance=inheritance
            )
            new_sd['Dacl'].aces.append(new_ace)
            logging.debug(f"Created ACE with object type: {obj_type}")
    else:
        new_ace = create_ace(
            sid=principal_sid,
            access_mask=access_mask,
            object_type=object_types,
            ace_type=ace_type,
            inheritance=inheritance
        )
        new_sd['Dacl'].aces.append(new_ace)

    # Write the modified security descriptor
    if _set_security_descriptor(conn, target_dn, new_sd):
        ace_count = len(object_types) if isinstance(object_types, list) else 1
        ace_type_str = "ALLOWED" if ace_type == "allowed" else "DENIED"
        logging.info(f"Successfully added {ace_count} {ace_type_str} ACE(s) for '{right}' to '{principal}' on '{target}'")


def remove(conn, target, principal, right=None, ace_type=None):
    """
    Remove ACEs from the DACL of an object.

    Args:
        conn: LDAP connection object
        target: Target object (sAMAccountName, SID, or DN)
        principal: Principal whose ACEs to remove
        right: Optional specific right to remove
        ace_type: Optional filter by ACE type ('allowed' or 'denied')
    """
    target_dn = _resolve_target(conn, target)
    if not target_dn:
        return

    _, principal_sid = _resolve_principal(conn, principal)
    if not principal_sid:
        logging.error(f"Could not resolve principal: {principal}")
        return

    # Get current security descriptor
    raw_sd, sd = _get_security_descriptor(conn, target_dn)
    if not sd:
        return

    new_sd = copy.deepcopy(sd)

    # Determine what to match
    match_access_mask = None
    match_object_types = None

    if right:
        if right not in DACL_RIGHTS:
            logging.error(f"Unknown right: {right}")
            return
        right_config = DACL_RIGHTS[right]
        match_access_mask = right_config['access_mask']
        match_object_types = right_config['object_type']
        if isinstance(match_object_types, str):
            match_object_types = [match_object_types]

    # Filter ACEs
    original_count = len(new_sd['Dacl'].aces)
    new_aces = []

    for ace in new_sd['Dacl'].aces:
        ace_sid = ace["Ace"]["Sid"].formatCanonical()

        # Check if this ACE belongs to the principal
        if ace_sid.upper() != principal_sid.upper():
            new_aces.append(ace)
            continue

        # Check ACE type filter
        if ace_type:
            if ace_type == "allowed" and ace["AceType"] not in [ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_OBJECT]:
                new_aces.append(ace)
                continue
            if ace_type == "denied" and ace["AceType"] not in [ACE_TYPE_ACCESS_DENIED, ACE_TYPE_ACCESS_DENIED_OBJECT]:
                new_aces.append(ace)
                continue

        # Check right filter
        if right:
            ace_mask = ace["Ace"]["Mask"]["Mask"]

            # Check if this ACE's access mask matches
            if not (ace_mask & match_access_mask):
                new_aces.append(ace)
                continue

            # For object ACEs, check object type
            if match_object_types and match_object_types[0] is not None:
                if ace["AceType"] in [ACE_TYPE_ACCESS_ALLOWED_OBJECT, ACE_TYPE_ACCESS_DENIED_OBJECT]:
                    try:
                        flags = ace["Ace"]["Flags"]
                        if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                            ace_obj_type = guid_to_string(ace["Ace"]["ObjectType"])
                            if ace_obj_type.lower() not in [g.lower() for g in match_object_types if g]:
                                new_aces.append(ace)
                                continue
                        else:
                            new_aces.append(ace)
                            continue
                    except (KeyError, TypeError):
                        new_aces.append(ace)
                        continue
                else:
                    # Non-object ACE but we're looking for object type
                    new_aces.append(ace)
                    continue

        # If we get here, this ACE should be removed
        logging.debug(f"Removing ACE: SID={ace_sid}, Mask=0x{ace['Ace']['Mask']['Mask']:08x}")

    new_sd['Dacl'].aces = new_aces
    removed_count = original_count - len(new_aces)

    if removed_count == 0:
        logging.warning(f"No matching ACEs found for principal '{principal}'")
        return

    # Write the modified security descriptor
    if _set_security_descriptor(conn, target_dn, new_sd):
        logging.info(f"Successfully removed {removed_count} ACE(s) for '{principal}' from '{target}'")


def backup(conn, target, output=None):
    """
    Backup the DACL of an object to a JSON file.

    Args:
        conn: LDAP connection object
        target: Target object (sAMAccountName, SID, or DN)
        output: Optional output file path
    """
    target_dn = _resolve_target(conn, target)
    if not target_dn:
        return

    raw_sd, sd = _get_security_descriptor(conn, target_dn)
    if not raw_sd:
        return

    # Generate default filename if not provided
    if not output:
        # Sanitize target for filename
        safe_name = target.replace('=', '_').replace(',', '_').replace(' ', '_')
        output = f"{safe_name}_dacl_backup.json"

    # Create backup data
    backup_data = {
        "target_dn": target_dn,
        "security_descriptor": hexlify(raw_sd).decode('utf-8'),
        "backup_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "domain": conn.domain,
    }

    # Write to file
    try:
        with open(output, 'w') as f:
            json.dump(backup_data, f, indent=2)
        logging.info(f"DACL backed up successfully to: {output}")
    except Exception as e:
        logging.error(f"Failed to write backup file: {e}")


def restore(conn, backup_file):
    """
    Restore the DACL of an object from a JSON backup file.

    Args:
        conn: LDAP connection object
        backup_file: Path to the backup JSON file
    """
    # Read backup file
    try:
        with open(backup_file, 'r') as f:
            backup_data = json.load(f)
    except FileNotFoundError:
        logging.error(f"Backup file not found: {backup_file}")
        return
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in backup file: {e}")
        return

    # Validate backup data
    required_fields = ['target_dn', 'security_descriptor']
    for field in required_fields:
        if field not in backup_data:
            logging.error(f"Missing required field in backup: {field}")
            return

    target_dn = backup_data['target_dn']
    sd_hex = backup_data['security_descriptor']

    # Verify target exists
    conn.search(
        search_base=target_dn,
        search_filter=f'(distinguishedName={escape_filter_chars(target_dn)})',
        attributes=['distinguishedName']
    )

    if not conn._ldap_connection.entries:
        logging.error(f"Target object not found: {target_dn}")
        return

    # Parse security descriptor
    try:
        raw_sd = unhexlify(sd_hex)
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
    except Exception as e:
        logging.error(f"Failed to parse security descriptor from backup: {e}")
        return

    # Restore the DACL
    if _set_security_descriptor(conn, target_dn, sd):
        timestamp = backup_data.get('backup_timestamp', 'unknown')
        logging.info(f"DACL restored successfully for: {target_dn}")
        logging.info(f"Backup was created at: {timestamp}")
