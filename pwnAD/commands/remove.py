import copy
import logging
import ldap3
from impacket.ldap import ldaptypes
from ldap3 import MODIFY_DELETE, MODIFY_REPLACE, BASE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from pwnAD.lib.accesscontrol import *
from pwnAD.lib.utils import check_error, resolve_target, encode_ldap_value, LDAPOperationError
from pwnAD.lib.dns import DNSRecord, DNS_RECORD_TYPE


def computer(conn, computer_name):
    """
    Delete a computer account from Active Directory.

    Args:
        conn: LDAP connection object
        computer_name: Name of the computer to delete ($ appended automatically if missing)
    """
    if computer_name[-1] != '$':
        computer_name = computer_name + '$'

    res = conn.exists(computer_name)
    if not res:
        logging.error(f"Account {computer_name} not found in {conn._baseDN}!")
        return

    computer = conn.get(computer_name)
    logging.debug(f"LDAP result for computer : {computer}")
    try:
        conn.delete(computer.entry_dn)
        logging.info(f"Successfully deleted {computer_name}.")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def user(conn, user_name):
    """
    Delete a user account from Active Directory.

    Args:
        conn: LDAP connection object
        user_name: sAMAccountName of the user to delete
    """
    res = conn.exists(user_name)
    if not res:
        logging.error(f"Account {user_name} not found in {conn._baseDN}!")
        return

    user= conn.get(user_name)
    logging.debug(f"LDAP result for user : {user}")

    try:
        conn.delete(user.entry_dn)
        logging.info(f"Successfully deleted {user_name}.")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def groupMember(conn, group: str, member: str):
    """
    Remove a user from a group.

    Args:
        conn: LDAP connection object
        group: sAMAccountName of the target group
        member: sAMAccountName of the user to remove
    """
    user_dn = conn.get_dn_from_samaccountname(member, 'user')
    group_dn = conn.get_dn_from_samaccountname(group, 'group')

    try:
        conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
        logging.info(f"{member} successfully removed from {group} !")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def dcsync(conn, trustee):
    """
    Remove DCSync rights from a user by removing replication ACEs.

    Args:
        conn: LDAP connection object
        trustee: sAMAccountName of the user to remove DCSync rights from
    """
    targetDN, targetSID = conn.ldap_get_user(trustee)
    logging.debug(f"targetSID : {targetSID}")

    res = conn.search(search_base=conn._baseDN,
                      search_filter=f'(distinguishedName={conn._baseDN})',
                      attributes=['nTSecurityDescriptor'])
    if res is None:
        raise LDAPOperationError('Failed to get forest\'s SD')

    baseDN_sd = conn._ldap_connection.entries[0].entry_raw_attributes
    if baseDN_sd['nTSecurityDescriptor'] == []:
        raise LDAPOperationError("User doesn't have right to read nTSecurityDescriptor")

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
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def genericAll(conn, target, trustee):
    """
    Remove GenericAll (full control) rights from a trustee over a target object.

    Args:
        conn: LDAP connection object
        target: sAMAccountName of the target object
        trustee: sAMAccountName of the user to remove rights from
    """
    _, trustee_sid = conn.ldap_get_user(trustee)
    target_dn, _ = conn.ldap_get_user(target)

    res = conn.search(
        search_base=target_dn,
        search_filter=f'(distinguishedName={target_dn})',
        attributes=['nTSecurityDescriptor']
    )
    if res is None:
        raise LDAPOperationError("Failed to get target's SD")

    target_sd = conn._ldap_connection.entries[0].entry_raw_attributes
    if target_sd['nTSecurityDescriptor'] == []:
        raise LDAPOperationError("User doesn't have right to read nTSecurityDescriptor")

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target_sd['nTSecurityDescriptor'][0])
    new_sd = copy.deepcopy(sd)

    original_count = len(new_sd['Dacl'].aces)
    new_sd['Dacl'].aces = [
        ace for ace in new_sd['Dacl'].aces
        if not (ace['Ace']['Sid'].formatCanonical() == trustee_sid and ace['Ace']['Mask']['Mask'] & ACCESS_FLAGS["FULL_CONTROL"])
    ]

    if len(new_sd['Dacl'].aces) == original_count:
        logging.warning(f"No GenericAll rights found for '{trustee}' on '{target}'")
        return

    try:
        conn.modify(target_dn, {'nTSecurityDescriptor': [MODIFY_REPLACE, [new_sd.getData()]]})
        logging.info(f"Removed GenericAll rights for '{trustee}' on '{target}'!")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def uac(conn, target: str, flags: list):
    """
    Remove property flags from userAccountControl attribute.

    Args:
        conn: LDAP connection object
        target: sAMAccountName of the target user/computer
        flags: List of UAC flag names to remove (e.g., ['DONT_REQ_PREAUTH', 'TRUSTED_FOR_DELEGATION'])
    """
    # Build the UAC value from provided flags
    uac_to_remove = 0
    for flag in flags:
        flag_upper = flag.upper()
        if flag_upper not in ACCOUNT_FLAGS:
            raise LDAPOperationError(f"Unknown UAC flag: {flag}. Available flags: {', '.join(ACCOUNT_FLAGS.keys())}")
        uac_to_remove |= ACCOUNT_FLAGS[flag_upper]

    # Search for the target and get current userAccountControl
    conn.search(
        conn._baseDN,
        '(sAMAccountName=%s)' % escape_filter_chars(target),
        attributes=['distinguishedName', 'userAccountControl']
    )

    if not conn._ldap_connection.entries:
        raise LDAPOperationError(f"Target '{target}' not found in LDAP")

    entry = conn._ldap_connection.entries[0]
    target_dn = entry.entry_dn

    try:
        old_uac = entry['userAccountControl'].value
    except (KeyError, IndexError):
        raise LDAPOperationError(f"Cannot read userAccountControl attribute for '{target}'")

    # Remove flags using bitwise AND with NOT
    new_uac = old_uac & ~uac_to_remove

    if new_uac == old_uac:
        logging.info(f"Flags {flags} not set on '{target}', nothing to remove")
        return

    logging.debug(f"Original userAccountControl: {old_uac}")
    logging.debug(f"New userAccountControl: {new_uac}")

    try:
        conn.modify(target_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
        logging.info(f"Successfully removed {flags} from '{target}' userAccountControl")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def RBCD(conn, computer_name):
    """
    Clear Resource-Based Constrained Delegation (RBCD) configuration.

    Args:
        conn: LDAP connection object
        computer_name: sAMAccountName of the computer to clear RBCD from
    """
    success = conn.search(conn._baseDN, '(sAMAccountName=%s)' % escape_filter_chars(computer_name), attributes=['objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
    if success is False or len(conn._ldap_connection.entries) != 1:
        raise LDAPOperationError(f"Target '{computer_name}' not found")

    target = conn._ldap_connection.entries[0]
    target_sid = target["objectsid"].value
    logging.info(f"Found Target DN: {target.entry_dn}")
    logging.info(f"Target SID: {target_sid}\n")

    sd = create_empty_sd()

    try:
        conn.modify(target.entry_dn, {'msDS-AllowedToActOnBehalfOfOtherIdentity':[MODIFY_REPLACE, [sd.getData()]]})
        logging.info('Delegation rights cleared successfully!')
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def dnsRecord(conn, name: str, data: str = None, dnstype: str = None, zone: str = None):
    """
    Remove a DNS record from Active Directory Integrated DNS.

    Args:
        conn: LDAP connection object
        name: Hostname of the DNS record to remove
        data: Optional record data to remove specific record (IP address, hostname, or text)
        dnstype: Optional type of DNS record to remove (A, AAAA, CNAME, MX, PTR, SRV, TXT)
        zone: DNS zone name (default: current domain)

    Note:
        - If data and dnstype are not specified, the entire DNS node will be deleted
        - If data or dnstype is specified, only matching records will be removed
    """
    # Use current domain as zone if not specified
    if zone is None:
        zone = conn.domain

    logging.info(f"Removing DNS record: {name}.{zone}")

    try:
        # Build zone DN
        naming_context = "," + conn._baseDN
        zone_types = ["DomainDnsZones", "ForestDnsZones"]

        record_dn = None
        existing_records = None
        zone_dn = None

        # Try to find the record in different zone locations
        for zone_type in zone_types:
            zone_dn = f"DC={zone},CN=MicrosoftDNS,DC={zone_type}{naming_context}"
            logging.debug(f"Trying zone: {zone_dn}")

            try:
                # Search for the DNS record
                conn.search(
                    search_base=zone_dn,
                    search_filter=f"(name={name})",
                    search_scope=ldap3.SUBTREE,
                    attributes=["name", "dnsRecord", "distinguishedName"],
                )

                if not conn._ldap_connection.entries:
                    logging.debug(f"Record not found in {zone_type}")
                    continue

                # Found the record
                entry = conn._ldap_connection.entries[0]
                record_dn = entry.distinguishedName.value
                existing_records = entry["dnsRecord"].raw_values if "dnsRecord" in entry else []
                logging.debug(f"Found existing record at: {record_dn}")
                logging.debug(f"Found {len(existing_records)} DNS record(s)")
                break

            except Exception as e:
                logging.debug(f"Error searching {zone_type}: {e}")
                continue

        if record_dn is None:
            logging.error(f"DNS record '{name}' not found in zone '{zone}'")
            return

        # If no specific data/type provided, delete the entire DNS node
        if data is None and dnstype is None:
            logging.debug(f"Deleting entire DNS node at {record_dn}")
            try:
                conn.delete(record_dn)
                logging.info(f"DNS record '{name}' deleted successfully")
            except ldap3.core.exceptions.LDAPException as e:
                error_code = conn._ldap_connection.result['result']
                check_error(conn, error_code, e)
            return

        # Parse existing records to find matches
        records_to_keep = []
        removed_count = 0

        for record_bytes in existing_records:
            try:
                dns_record = DNSRecord(record_bytes)
                record_dict = dns_record.to_dict()

                # Determine if we should keep this record
                should_keep = True

                # Check dnstype match if specified
                if dnstype is not None:
                    record_type_code = DNS_RECORD_TYPE.get(dnstype.upper())
                    if record_type_code is not None and dns_record.record_type != record_type_code:
                        should_keep = True  # Different type, keep it
                    elif record_type_code is not None and dns_record.record_type == record_type_code:
                        # Same type, check data if provided
                        if data is not None:
                            # Parse record data to compare
                            record_data_str = str(record_dict.get("data", ""))
                            if data.lower() in record_data_str.lower():
                                should_keep = False  # Match found, remove it
                        else:
                            should_keep = False  # Remove all of this type

                # If only data is specified (no type), match by data content
                elif data is not None:
                    record_data_str = str(record_dict.get("data", ""))
                    if data.lower() in record_data_str.lower():
                        should_keep = False

                if should_keep:
                    records_to_keep.append(record_bytes)
                else:
                    removed_count += 1
                    logging.debug(f"Removing record: type={record_dict.get('type')}, data={record_dict.get('data')}")

            except Exception as e:
                logging.debug(f"Error parsing DNS record: {e}")
                # Keep unparseable records to avoid data loss
                records_to_keep.append(record_bytes)

        if removed_count == 0:
            logging.error("No matching DNS records found to remove")
            return

        # Update or delete based on remaining records
        if len(records_to_keep) == 0:
            # No records left, delete the entire DNS node
            logging.debug(f"No records remaining, deleting DNS node at {record_dn}")
            try:
                conn.delete(record_dn)
                logging.info(f"All DNS records removed, '{name}' deleted")
            except ldap3.core.exceptions.LDAPException as e:
                error_code = conn._ldap_connection.result['result']
                check_error(conn, error_code, e)
        else:
            # Update with remaining records
            logging.debug(f"Updating record with {len(records_to_keep)} remaining record(s)")
            try:
                conn.modify(record_dn, {"dnsRecord": [(MODIFY_REPLACE, records_to_keep)]})
                logging.info(f"Removed {removed_count} DNS record(s) from '{name}'")
            except ldap3.core.exceptions.LDAPException as e:
                error_code = conn._ldap_connection.result['result']
                check_error(conn, error_code, e)

    except Exception as e:
        logging.error(f"Failed to remove DNS record: {e}")
        raise


def attribute(conn, target: str, attr: str, values: list = None, raw: bool = False, b64: bool = False):
    """
    Remove values from an attribute or clear the entire attribute.

    This function removes specific values from a multi-valued attribute or
    clears the entire attribute if no values are specified.

    Args:
        conn: LDAP connection object
        target: Target identifier (sAMAccountName, DN, or SID)
        attr: Name of the attribute to remove values from
        values: List of values to remove. If None/empty, clears the entire attribute
        raw: If True, send values as-is without encoding (default: False)
        b64: If True, decode values from base64 first (default: False)

    Example:
        remove attribute user1 servicePrincipalName MSSQLSvc/server:1433
        remove attribute user1 description  # clears the description attribute
    """
    # Resolve target to DN
    target_dn = resolve_target(conn, target)
    if not target_dn:
        return

    # If no values provided, clear the entire attribute
    if not values:
        try:
            logging.debug(f"Clearing attribute {attr} on {target_dn}")
            conn.modify(target_dn, {attr: [(MODIFY_REPLACE, [])]})
            logging.info(f"Successfully cleared attribute '{attr}' on {target}")
        except ldap3.core.exceptions.LDAPException as e:
            error_code = conn._ldap_connection.result['result']
            check_error(conn, error_code, e)
        except Exception as e:
            logging.error(f"Error clearing attribute: {e}")
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
        logging.debug(f"Removing from {target_dn}: {attr} -= {encoded_values}")
        conn.modify(target_dn, {attr: [(MODIFY_DELETE, encoded_values)]})
        logging.info(f"Successfully removed value(s) from attribute '{attr}' on {target}")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)
    except Exception as e:
        logging.error(f"Error removing attribute value: {e}")


def object(conn, target: str):
    """
    Delete an LDAP object entirely.

    This function deletes the entire object from Active Directory.
    Use with caution as this operation is irreversible.

    Args:
        conn: LDAP connection object
        target: Target identifier (sAMAccountName, DN, or SID)

    Example:
        remove object testuser
        remove object "CN=TestOU,DC=domain,DC=local"
    """
    # Resolve target to DN
    target_dn = resolve_target(conn, target)
    if not target_dn:
        return

    try:
        logging.debug(f"Deleting object: {target_dn}")
        conn.delete(target_dn)
        logging.info(f"Successfully deleted object: {target}")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)
    except Exception as e:
        logging.error(f"Error deleting object: {e}")