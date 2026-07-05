"""
Permission and DACL analysis utilities for Active Directory.

This module contains functions for analyzing Active Directory permissions,
security descriptors, and access control lists (DACLs).
"""

import logging
import ldap3
from ldap3 import BASE, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars
from impacket.ldap import ldaptypes

from pwnAD.lib.accesscontrol import (
    ACCESS_FLAGS,
    ACE_TYPE_ACCESS_DENIED,
    ACE_TYPE_ACCESS_DENIED_OBJECT,
    ACE_TYPE_ACCESS_ALLOWED,
    ACE_TYPE_ACCESS_ALLOWED_OBJECT,
    parse_ace
)


def resolve_principal_sids(conn, principal):
    """
    Resolve a principal to its SID, DN and all group SIDs (including nested groups).

    Uses the tokenGroups computed attribute which returns all transitive group
    memberships.

    Args:
        conn: LDAP connection object
        principal: sAMAccountName or SID string

    Returns:
        tuple: (principal_sid, principal_dn, set_of_all_sids) or (None, None, None) on error
    """
    # Resolve principal to DN and SID
    if principal.upper().startswith("S-1-"):
        principal_sid = principal
        search_filter = f"(objectSid={principal})"
    else:
        search_filter = f"(sAMAccountName={escape_filter_chars(principal)})"
        principal_sid = None

    # Find the principal and get its SID
    conn._ldap_connection.search(
        search_base=conn._baseDN,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=['objectSid', 'distinguishedName']
    )

    if not conn._ldap_connection.entries:
        logging.error(f"Principal not found: {principal}")
        return None, None, None

    entry = conn._ldap_connection.entries[0]
    principal_dn = entry.entry_dn

    if principal_sid is None:
        raw_sid = entry.entry_raw_attributes.get('objectSid')
        if raw_sid:
            principal_sid = format_sid(raw_sid[0])
        else:
            logging.error(f"Cannot read SID for principal: {principal}")
            return None, None, None

    # Get tokenGroups (all transitive group memberships)
    all_sids = set()
    all_sids.add(principal_sid)

    try:
        conn._ldap_connection.search(
            search_base=principal_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=['tokenGroups']
        )

        if conn._ldap_connection.entries:
            token_entry = conn._ldap_connection.entries[0]
            raw_groups = token_entry.entry_raw_attributes.get('tokenGroups', [])
            for raw_group_sid in raw_groups:
                group_sid = format_sid(raw_group_sid)
                all_sids.add(group_sid)
    except Exception as e:
        logging.debug(f"Could not retrieve tokenGroups: {e}")

    # Note: We intentionally do NOT add well-known SIDs like Everyone (S-1-1-0)
    # and Authenticated Users (S-1-5-11) because they have permissions on almost
    # every AD object (e.g., CreateChild on DNS zones). Including them would flood
    # results with objects that are writable by anyone, which is not useful for
    # targeted privilege escalation analysis.
    #
    # The SELF SID (S-1-5-10) is handled specially in writable_by_target - it's
    # added only when checking permissions on the principal's own object.

    return principal_sid, principal_dn, all_sids


def check_dacl_permissions(sd, target_sids, right):
    """
    Check if any of the target SIDs have write permissions in the security descriptor's DACL.

    Respects DENY ACEs (evaluated first, as Windows does).

    Args:
        sd: Parsed SR_SECURITY_DESCRIPTOR object
        target_sids: Set of SID strings to check
        right: "WRITE", "CHILD", or "ALL"

    Returns:
        tuple: (has_permission, permissions_list, detail_info_list)
    """
    # Write-related access masks
    WRITE_MASKS = (
        ACCESS_FLAGS["GENERIC_ALL"] |
        ACCESS_FLAGS["GENERIC_WRITE"] |
        ACCESS_FLAGS["FULL_CONTROL"] |
        ACCESS_FLAGS["WRITE_DACL"] |
        ACCESS_FLAGS["WRITE_OWNER"] |
        ACCESS_FLAGS["ADS_RIGHT_DS_WRITE_PROP"] |
        ACCESS_FLAGS["ADS_RIGHT_DS_SELF"] |
        ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]
    )

    CHILD_MASKS = (
        ACCESS_FLAGS["GENERIC_ALL"] |
        ACCESS_FLAGS["FULL_CONTROL"] |
        ACCESS_FLAGS["ADS_RIGHT_DS_CREATE_CHILD"]
    )

    if not sd or not sd['Dacl']:
        return False, [], []

    dacl = sd['Dacl']

    # Collect DENY and ALLOW ACEs separately
    denied_rights = set()
    allowed_permissions = []
    allowed_detail = []

    for ace in dacl['Data']:
        ace_type = ace['AceType']
        ace_sid = ace['Ace']['Sid'].formatCanonical()
        ace_mask = ace['Ace']['Mask']['Mask']

        if ace_sid not in target_sids:
            continue

        is_deny = ace_type in (ACE_TYPE_ACCESS_DENIED, ACE_TYPE_ACCESS_DENIED_OBJECT)
        is_allow = ace_type in (ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_OBJECT)

        if is_deny:
            # Track denied masks for later filtering
            denied_rights.add(ace_mask)

        elif is_allow:
            has_write = False
            has_child = False

            if right in ("WRITE", "ALL") and (ace_mask & WRITE_MASKS):
                has_write = True

            if right in ("CHILD", "ALL") and (ace_mask & CHILD_MASKS):
                has_child = True

            if has_write or has_child:
                parsed = parse_ace(ace)
                rights_names = parsed.get("rights", [])
                obj_type_name = parsed.get("object_type_name", "")

                if has_write:
                    if "WRITE" not in allowed_permissions:
                        allowed_permissions.append("WRITE")
                    right_desc = ", ".join(rights_names)
                    if obj_type_name:
                        right_desc += f" ({obj_type_name})"
                    allowed_detail.append(right_desc)

                if has_child:
                    if "CREATE_CHILD" not in allowed_permissions:
                        allowed_permissions.append("CREATE_CHILD")

    has_permission = len(allowed_permissions) > 0
    return has_permission, allowed_permissions, allowed_detail


def writable_by_target(conn, target, otype="*", right="ALL", detail=False, partition="DOMAIN", exclude_deleted=False):
    """
    Find writable objects for a specified principal by reading nTSecurityDescriptor
    and parsing the DACL.

    Args:
        conn: LDAP connection object
        target: Target principal (sAMAccountName or SID)
        otype: Object class filter
        right: Type of right to search for
        detail: If True, display specific rights found in DACL
        partition: Directory partition to explore
        exclude_deleted: If True, exclude deleted objects
    """
    # Resolve principal and get all SIDs (direct + group memberships)
    principal_sid, principal_dn, all_sids = resolve_principal_sids(conn, target)
    if principal_sid is None:
        return

    logging.info(f"Checking permissions for principal: {target} (SID: {principal_sid})")
    logging.info(f"Total SIDs to check (including groups): {len(all_sids)}")

    # SELF SID (S-1-5-10) - represents "the object itself"
    # This is added dynamically when checking an object that IS the principal
    SELF_SID = "S-1-5-10"

    # Build LDAP filter
    if otype == "useronly":
        ldap_filter = "(sAMAccountType=805306368)"
    elif otype == "ou":
        ldap_filter = "(|(objectClass=container)(objectClass=organizationalUnit))"
    elif otype == "gpo":
        ldap_filter = "(objectClass=groupPolicyContainer)"
    else:
        ldap_filter = f"(objectClass={otype})"

    # Determine search bases
    search_bases = []
    if partition == "DOMAIN":
        search_bases.append(conn._baseDN)
    elif partition == "CONFIGURATION":
        search_bases.append(conn.configuration_path)
    elif partition == "SCHEMA":
        search_bases.append(f"CN=Schema,{conn.configuration_path}")
    elif partition == "DNS":
        # DNS application partitions
        search_bases.extend([
            f"DC=DomainDnsZones,{conn._baseDN}",
            f"DC=ForestDnsZones,{conn._baseDN}"
        ])
    elif partition == "ALL":
        search_bases.extend([
            conn._baseDN,
            conn.configuration_path,
            f"CN=Schema,{conn.configuration_path}",
            f"DC=DomainDnsZones,{conn._baseDN}",
            f"DC=ForestDnsZones,{conn._baseDN}"
        ])

    # Set up LDAP controls - request DACL in nTSecurityDescriptor
    all_controls = security_descriptor_control(sdflags=0x04)

    if not exclude_deleted:
        show_deleted_control = ('1.2.840.113556.1.4.417', True, None)
        all_controls.append(show_deleted_control)

    writable_objects_count = 0

    for search_base in search_bases:
        try:
            logging.info(f"Searching for writable objects in {search_base}...")

            conn._ldap_connection.search(
                search_base=search_base,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName', 'nTSecurityDescriptor'],
                controls=all_controls
            )

            for entry in conn._ldap_connection.entries:
                raw_sd = entry.entry_raw_attributes.get('nTSecurityDescriptor')
                if not raw_sd:
                    continue

                try:
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd[0])
                except Exception:
                    continue

                # Build the set of SIDs to check for this specific object
                # Add SELF SID (S-1-5-10) if this object IS the principal
                sids_to_check = all_sids
                if entry.entry_dn.lower() == principal_dn.lower():
                    sids_to_check = all_sids | {SELF_SID}

                has_permission, permissions, detail_info = check_dacl_permissions(sd, sids_to_check, right)

                if has_permission:
                    writable_objects_count += 1
                    dn = entry.entry_dn

                    print(f"\ndistinguishedName: {dn}")
                    if permissions:
                        print(f"permission: {'; '.join(permissions)}")
                    if detail and detail_info:
                        # Deduplicate detail info
                        seen = set()
                        for info in detail_info:
                            if info not in seen:
                                seen.add(info)
                                print(f"  {info}")

        except ldap3.core.exceptions.LDAPException as e:
            logging.error(f"Error searching {search_base}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error searching {search_base}: {e}")

    if writable_objects_count == 0:
        logging.info("No writable objects found")
    else:
        logging.info(f"Total writable objects found: {writable_objects_count}")
