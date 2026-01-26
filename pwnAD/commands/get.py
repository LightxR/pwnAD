from impacket.ldap import ldaptypes
from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars
from ldap3 import BASE, SUBTREE
from pyasn1.error import PyAsn1Error
import ldap3
import logging

from pwnAD.lib.accesscontrol import *
from pwnAD.lib.utils import format_list_results, check_error, resolve_target
from pwnAD.lib.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from pwnAD.commands.query import query


def users(conn):
    """List all user accounts in the domain."""
    query(conn, "(objectClass=user)", "samaccountname", simple=True)

def user(conn, account):
    """Get all attributes for a specific user account."""
    query(conn, f"(&(objectClass=*)(samaccountname={account}))", "*")

def computers(conn):
    """List all computer accounts in the domain."""
    query(conn, "(objectCategory=Computer)", "samaccountname", simple=True)

def DC(conn):
    """List all Domain Controllers with their SPNs."""
    query(conn, "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", ["samaccountname", "serviceprincipalname"])

def servers(conn):
    """List all servers excluding Domain Controllers."""
    query(conn, "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))", "samaccountname", simple=True)

def CA(conn):
    """List all Certificate Authorities in the forest."""
    query(conn,
        search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{conn.configuration_path}",
        search_filter="(&(objectClass=pKIEnrollmentService))",
        attributes=[
            "cn",
            "name",
            "dNSHostName",
            "cACertificateDN",
            "cACertificate",
            "certificateTemplates",
            "objectGUID",
        ],
    )

def OU(conn):
    """List all Organizational Units in the domain."""
    query(conn, "(objectCategory=organizationalUnit)", "distinguishedname", simple=True)

def containers(conn):
    """List all containers in the domain."""
    query(conn, "(objectCategory=container)", "distinguishedname", simple=True)

def spn(conn):
    """List all user accounts with Service Principal Names."""
    query(conn, "(&(objectClass=User)(serviceprincipalname=*)(samaccountname=*))", ["samaccountname", "serviceprincipalname"])

def constrained_delegation(conn):
    """List accounts configured for constrained delegation."""
    query(conn, "(&(objectClass=User)(msDS-AllowedToDelegateTo=*))", ["samaccountname", "serviceprincipalname", "msDS-AllowedToDelegateTo"])

def unconstrained_delegation(conn):
    """List accounts configured for unconstrained delegation."""
    query(conn, "(userAccountControl:1.2.840.113556.1.4.803:=524288)", ["samaccountname", "servicePrincipalName"])

def not_trusted_for_delegation(conn):
    """List accounts marked as NOT_DELEGATED."""
    query(conn, "(&(samaccountname=*)(userAccountControl:1.2.840.113556.1.4.803:=1048576))", "samaccountname", simple=True)

def asreproastables(conn):
    """List accounts vulnerable to AS-REP roasting (no Kerberos pre-auth required)."""
    query(conn, "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", "samaccountname", simple=True)

def kerberoastables(conn):
    """List accounts vulnerable to Kerberoasting (user accounts with SPNs)."""
    query(conn, "(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))", "samaccountname", simple=True)

def password_not_required(conn):
    """List accounts with PASSWORD_NOT_REQUIRED flag."""
    query(conn, "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))", "samaccountname", simple=True)

def groups(conn):
    """List all security and distribution groups."""
    query(conn, "(objectCategory=group)", "samaccountname", simple=True)

def protected_users(conn):
    """List members of Protected Users group."""
    query(conn, f"(&(objectCategory=CN=group,CN=Schema,CN=configuration,{conn._baseDN})(samaccountname=Protect*)(member=*))", "samaccountname", simple=True)

def users_description(conn):
    """List user descriptions (may contain passwords)."""
    query(conn, "(&(objectCategory=user)(description=*))", "description")

def passwords_dont_expire(conn):
    """List accounts with passwords set to never expire."""
    query(conn, "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))", "samaccountname", simple=True)

def users_with_admin_count(conn):
    """List users with adminCount=1 (historically privileged accounts)."""
    query(conn, "(&(objectClass=user)(admincount=1)(!(samaccountname=krbtgt))(!(samaccountname=administrator)))", "samaccountname", simple=True)

def accounts_with_sid_histoy(conn):
    """List accounts with SID History attribute set."""
    query(conn, "(&(objectCategory=Person)(objectClass=User)(sidHistory=*))", "samaccountname", simple=True) 

def members(conn, group):
    """
    List all members of a group including primary group members.

    Args:
        conn: LDAP connection object
        group: sAMAccountName of the group
    """
    results = query(conn, f"(&(objectClass=group)(samaccountname={group}))", ["distinguishedName", "objectSid"], raw=True)
    if not results:
        logging.error(f"The group {group} doesn't exist")
        return

    group_dn = conn.get_dn_from_samaccountname(group, "*")
    primary_group_id = results[group_dn]['objectSid'].split("-")[-1]
    
    members = query(conn, f"(|(primaryGroupID={primary_group_id})(memberOf={group_dn}))", ["samaccountname"], simple=True, do_print=False)
    for member in members:
        if member == []:
            continue
        print(member)


def membership(conn, account, recurse=False):
    """
    Get group membership for an account.

    Args:
        conn: LDAP connection object
        account: sAMAccountName of the account
        recurse: If True, get nested group membership (max depth 5)
    """
    def get_recursive_groups(conn, account, max_depth, current_depth=1):
        nonlocal group_membership

        if current_depth > max_depth:
            return

        account_dn = conn.get_dn_from_samaccountname(account, "*")
        results = query(conn, f"(samaccountname={account})", ["memberOf", "primaryGroupID"], raw=True)
        account_data = results.get(account_dn)

        if 'memberOf' in account_data and account_data['memberOf']:
            for group_dn in account_data['memberOf']:
                sAMAccountName = conn.get_samaccountname_from_dn(group_dn, "*")
                if sAMAccountName not in group_membership:
                    group_membership.append(sAMAccountName)
                get_recursive_groups(conn, sAMAccountName, max_depth, current_depth + 1)

        if 'primaryGroupID' in account_data and account_data['primaryGroupID']:
            if isinstance(account_data['primaryGroupID'], list):
                for primary_group_id in account_data['primaryGroupID']:
                    sAMAccountName = conn.get_group_from_primary_group_id(primary_group_id, "*")
                    if sAMAccountName not in group_membership:
                        group_membership.append(sAMAccountName)
                    get_recursive_groups(conn, sAMAccountName, max_depth, current_depth + 1)
            else:
                primary_group_id = account_data['primaryGroupID']
                sAMAccountName = conn.get_group_from_primary_group_id(primary_group_id, "*")
                if sAMAccountName not in group_membership:
                    group_membership.append(sAMAccountName)
                get_recursive_groups(conn, sAMAccountName, max_depth, current_depth + 1)

    if not conn.exists(account):
        logging.error("This account doesn't exist")
    else:
        try:
            group_membership = []
            max_depth = 5 if recurse else 1
            get_recursive_groups(conn, account, max_depth)

        except Exception as e:
            logging.error(f"An error occured while trying to get membership : {e}")
            
        else:
            if group_membership != []:
                group_membership.sort()
                for group in group_membership:
                    print(group)
            else:
                logging.info(f"No group membership found for {account}")



def RBCD(conn):
    """List all accounts configured with Resource-Based Constrained Delegation."""
    rbcd_results = query(conn, "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", "samaccountname", simple=True, do_print=False)
    for computer in rbcd_results:
        DN_delegate_to = conn.get_dn_from_samaccountname(samaccountname=computer, object_class="computer")

        conn.search(
                DN_delegate_to, 
                '(objectClass=*)', 
                search_scope=BASE,
                attributes=['SAMAccountName', 'objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
                )
        targetuser = None
        for entry in conn._ldap_connection.response:
            if entry['type'] != 'searchResEntry':
                continue
            targetuser = entry
        if not targetuser:
            logging.error('Could not query target user properties')
            return

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=targetuser['raw_attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'][0])
            if len(sd['Dacl'].aces) > 0:
                sam = targetuser['attributes']['sAMAccountName']
                logging.info(f"Accounts allowed to act on behalf of other identity to \x1b[34m{sam}\x1b[0m:")
                for ace in sd['Dacl'].aces:
                    SID = ace['Ace']['Sid'].formatCanonical()
                    SidInfos = conn.get_sid_info(ace['Ace']['Sid'].formatCanonical())
                    if SidInfos:
                        SamAccountName = SidInfos[1]
                        logging.info('    \x1b[34m%-10s\x1b[0m   (%s)' % (SamAccountName, SID))
            else:
                logging.info(f"Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty on {targetuser['attributes']['sAMAccountName']}")
        except IndexError:
            logging.info('Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')


def owner(conn, target: str):
    """
    Get the owner of a target object from its security descriptor.

    Args:
        conn: LDAP connection object
        target: sAMAccountName of the target object
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

    current_owner_SID = format_sid(target_principal_security_descriptor['OwnerSid']).formatCanonical()
    logging.info("Current owner information below")
    logging.info("- SID: %s" % current_owner_SID)
    logging.info("- sAMAccountName: %s" % conn.get_samaccountname_from_sid(current_owner_SID))
    conn._ldap_connection.search(conn._baseDN, '(objectSid=%s)' % current_owner_SID, attributes=['distinguishedName'])
    current_owner_distinguished_name = conn._ldap_connection.entries[0]
    logging.info("- distinguishedName: %s" % current_owner_distinguished_name['distinguishedName'])

def machine_quota(conn):
    """Get the machine account quota (number of computers a user can join to domain)."""
    conn.search(search_base=conn._baseDN, search_filter="(objectClass=*)", attributes=["ms-DS-MachineAccountQuota"])
    try:
        maq = conn._ldap_connection.entries[0]["ms-DS-MachineAccountQuota"]
        logging.info(f"MachineAccountQuota: {maq}")
    except PyAsn1Error:
        logging.error("MachineAccountQuota: <not set>")

def laps(conn):
    """Retrieve LAPS (Local Administrator Password Solution) passwords for computers."""
    try:
        conn.search(search_base=conn._baseDN, search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*))', attributes=["ms-Mcs-AdmPwd","SAMAccountname"])
        results = conn._ldap_connection.entries
        if results == []:
            logging.info("No LAPS password have been found")
        else :
            logging.info("LAPS password(s) found :")
            for result in results:
                logging.info(f'{result["SAMAccountname"]} : {result["ms-MCS-AdmPwd"]}')
    except ldap3.core.exceptions.LDAPException as e:
        if e.args[0] == "invalid attribute type ms-Mcs-AdmPwd":
            logging.error("This domain does not have LAPS configured")
        else:
            error_code = conn._ldap_connection.result['result']
            check_error(conn, error_code, e)

def gmsa(conn):
    """
    Retrieve Group Managed Service Account (gMSA) passwords and compute hashes.

    Note:
        Requires TLS connection for security. Displays NT hash and AES keys.
    """
    # code inspired from micahvandeusen's gMSADumper https://github.com/micahvandeusen/gMSADumper
    if conn._do_tls == False:
        logging.error("GMSA passwords can only be retrived through a secure connection.")
        choice = input("Do you want to start a TLS connection ? y/N")
        if choice.lower() == "y":
            try:
                conn.start_tls()
            except Exception as e:
                logging.error(f"An error occured while trying to start a TLS connection : {e}")
        else:
            return

    try :
        conn.search(
            search_base=conn._baseDN,
            search_filter='(&(ObjectClass=msDS-GroupManagedServiceAccount))',
            search_scope=SUBTREE,
            attributes=['sAMAccountName','msDS-ManagedPassword','msDS-GroupMSAMembership']
            )

        if len(conn._ldap_connection.entries) == 0:
            logging.info('No gMSAs returned.')

        for entry in conn._ldap_connection.entries:
            sam = entry['sAMAccountName'].value
            logging.info(f'Users or groups who can read password for {sam}:')
            for dacl in SR_SECURITY_DESCRIPTOR(data=entry['msDS-GroupMSAMembership'].raw_values[0])['Dacl']['Data']:
                conn.search(conn._baseDN, '(&(objectSID='+dacl['Ace']['Sid'].formatCanonical()+'))', attributes=['sAMAccountName'])

                # Added this check to prevent an error from occuring when there are no results returned
                if len(conn._ldap_connection.entries) != 0:
                    logging.info(conn._ldap_connection.entries[0]['sAMAccountName'].value)

            if 'msDS-ManagedPassword' in entry and entry['msDS-ManagedPassword']:
                data = entry['msDS-ManagedPassword'].raw_values[0]
                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(data)
                currentPassword = blob['CurrentPassword'][:-2]

                # Compute ntlm key
                ntlm_hash = MD4.new ()
                ntlm_hash.update (currentPassword)
                passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                userpass = sam + ':::' + passwd
                logging.info(userpass)

                # Compute aes keys
                password = currentPassword.decode('utf-16-le', 'replace').encode('utf-8')
                salt = '%shost%s.%s' % (args.domain.upper(), sam[:-1].lower(), args.domain.lower())
                aes_128_hash = hexlify(string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents)
                aes_256_hash = hexlify(string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents)
                logging.info('%s:aes256-cts-hmac-sha1-96:%s' % (sam, aes_256_hash.decode('utf-8')))
                logging.info('%s:aes128-cts-hmac-sha1-96:%s' % (sam, aes_128_hash.decode('utf-8')))

    except Exception as e:
        logging.error(f"An error occured while trying to retreive GMSA passwords : {e}")


def writable(conn, otype="*", right="ALL", detail=False, partition="DOMAIN", exclude_deleted=False):
    """
    Based on bloodyAD code.
    Retrieve objects writable by the current authenticated user.

    This function identifies directory objects that the authenticated user can modify based on effective permissions.
    It uses Active Directory's computed attributes (allowedAttributesEffective, allowedChildClassesEffective,
    sDRightsEffective) to determine actual write permissions.

    Args:
        conn: LDAP connection object
        otype: Object class filter. Special keywords:
               - "useronly": Only user accounts (sAMAccountType=805306368)
               - "ou": Organizational Units and Containers
               - "gpo": Group Policy Objects
               - "*": All objects (default)
               - Or any valid objectClass name
        right: Type of right to search for:
               - "ALL": Search for all rights (WRITE + CHILD) (default)
               - "WRITE": Only objects where attributes can be written
               - "CHILD": Only objects where child objects can be created
        detail: If True, displays specific writable attributes and child classes
        partition: Directory partition to explore:
                   - "DOMAIN": Domain naming context (default)
                   - "CONFIGURATION": Configuration naming context
                   - "SCHEMA": Schema naming context
                   - "ALL": All naming contexts
        exclude_deleted: If True, exclude deleted objects from results

    Returns:
        None (prints results to console)

    Example:
        writable(conn, otype="user", right="WRITE", detail=True)
        writable(conn, otype="ou", partition="ALL")
    """
    # Build LDAP filter based on object type
    if otype == "useronly":
        ldap_filter = "(sAMAccountType=805306368)"
    elif otype == "ou":
        ldap_filter = "(|(objectClass=container)(objectClass=organizationalUnit))"
    elif otype == "gpo":
        ldap_filter = "(objectClass=groupPolicyContainer)"
    else:
        ldap_filter = f"(objectClass={otype})"

    # Determine which attributes to retrieve
    attributes = ['distinguishedName']

    if right in ["WRITE", "ALL"]:
        attributes.extend(['allowedAttributesEffective', 'sDRightsEffective'])

    if right in ["CHILD", "ALL"]:
        attributes.append('allowedChildClassesEffective')

    # Determine search bases based on partition
    search_bases = []
    if partition == "DOMAIN":
        search_bases.append(conn._baseDN)
    elif partition == "CONFIGURATION":
        search_bases.append(conn.configuration_path)
    elif partition == "SCHEMA":
        search_bases.append(f"CN=Schema,{conn.configuration_path}")
    elif partition == "ALL":
        search_bases.extend([
            conn._baseDN,
            conn.configuration_path,
            f"CN=Schema,{conn.configuration_path}"
        ])

    # Set up LDAP controls
    controls = []
    if not exclude_deleted:
        # Include deleted objects (tombstones) by setting the LDAP_SERVER_SHOW_DELETED_OID control
        from ldap3.protocol.microsoft import extended_dn_control
        try:
            # Show deleted objects control
            show_deleted_control = ('1.2.840.113556.1.4.417', True, None)
            controls.append(show_deleted_control)
        except Exception:
            pass

    # Helper function to interpret sDRightsEffective
    def parse_sd_rights(sd_rights_value):
        """
        Parse sDRightsEffective value to determine SD modification rights.

        Bit flags:
        - 0x01: OWNER (can modify owner)
        - 0x04: DACL (can modify DACL)
        - 0x08: SACL (can modify SACL)
        """
        rights = {}
        if not sd_rights_value:
            return rights

        try:
            value = int(sd_rights_value)
            if value & 0x01:
                rights["OWNER"] = "WRITE"
            if value & 0x04:
                rights["DACL"] = "WRITE"
            if value & 0x08:
                rights["SACL"] = "WRITE"
        except (ValueError, TypeError):
            pass

        return rights

    # Search for writable objects
    writable_objects_count = 0

    for search_base in search_bases:
        try:
            logging.info(f"Searching for writable objects in {search_base}...")

            conn.search(
                search_base=search_base,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                controls=controls if controls else None
            )

            entries = conn._ldap_connection.entries

            for entry in entries:
                has_write_permission = False
                permissions = []
                sd_rights_info = {}
                detail_info = []

                # Check for attribute write permissions
                if right in ["WRITE", "ALL"]:
                    if 'allowedAttributesEffective' in entry:
                        allowed_attrs = entry['allowedAttributesEffective'].value
                        if allowed_attrs:
                            has_write_permission = True
                            permissions.append("WRITE")
                            if detail:
                                if isinstance(allowed_attrs, list):
                                    detail_info.append(f"Writable attributes ({len(allowed_attrs)}): {', '.join(allowed_attrs[:5])}" +
                                                      (" ..." if len(allowed_attrs) > 5 else ""))
                                else:
                                    detail_info.append(f"Writable attributes: {allowed_attrs}")

                    # Check for Security Descriptor write permissions
                    if 'sDRightsEffective' in entry:
                        sd_rights = entry['sDRightsEffective'].value
                        if sd_rights:
                            sd_rights_info = parse_sd_rights(sd_rights)
                            if sd_rights_info:
                                has_write_permission = True

                # Check for child creation permissions
                if right in ["CHILD", "ALL"]:
                    if 'allowedChildClassesEffective' in entry:
                        allowed_child_classes = entry['allowedChildClassesEffective'].value
                        if allowed_child_classes:
                            has_write_permission = True
                            permissions.append("CREATE_CHILD")
                            if detail:
                                if isinstance(allowed_child_classes, list):
                                    detail_info.append(f"Creatable child classes ({len(allowed_child_classes)}): {', '.join(allowed_child_classes[:5])}" +
                                                      (" ..." if len(allowed_child_classes) > 5 else ""))
                                else:
                                    detail_info.append(f"Creatable child classes: {allowed_child_classes}")

                # Display if object has write permissions
                if has_write_permission:
                    writable_objects_count += 1
                    dn = entry.distinguishedName.value if hasattr(entry.distinguishedName, 'value') else str(entry.distinguishedName)

                    print(f"\ndistinguishedName: {dn}")
                    if permissions:
                        print(f"permission: {'; '.join(permissions)}")
                    for sd_type, sd_perm in sd_rights_info.items():
                        print(f"{sd_type}: {sd_perm}")
                    if detail:
                        for info in detail_info:
                            print(f"  {info}")

        except ldap3.core.exceptions.LDAPException as e:
            logging.error(f"Error searching {search_base}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error searching {search_base}: {e}")

    # Summary
    if writable_objects_count == 0:
        logging.info("No writable objects found")
    else:
        logging.info(f"Total writable objects found: {writable_objects_count}")


def object(conn, target: str, attr: str = "*", resolve_sd: bool = False, raw: bool = False):
    """
    Retrieve attributes of any LDAP object.

    This function provides generic access to any AD object's attributes,
    supporting multiple target identification formats (sAMAccountName, DN, SID).

    Args:
        conn: LDAP connection object
        target: Target identifier (sAMAccountName, DN, or SID)
        attr: Comma-separated list of attributes to retrieve (default: "*" for all)
        resolve_sd: If True, resolve security descriptors to SDDL format (default: False)
        raw: If True, display raw values without formatting (default: False)

    Example:
        get object Administrator
        get object Administrator --attr sAMAccountName,memberOf
        get object S-1-5-21-xxx-500
        get object "CN=Admin,CN=Users,DC=corp,DC=local" --resolve-sd
    """
    # Resolve target to DN
    target_dn = resolve_target(conn, target)
    if not target_dn:
        return

    # Parse attributes
    if attr == "*":
        attributes = ["*"]
    else:
        attributes = [a.strip() for a in attr.split(",")]

    # Add nTSecurityDescriptor if resolve_sd is requested
    if resolve_sd and "nTSecurityDescriptor" not in attributes and "*" not in attributes:
        attributes.append("nTSecurityDescriptor")

    # Set up controls for security descriptor retrieval
    controls = None
    if resolve_sd:
        controls = security_descriptor_control(sdflags=0x07)  # Owner + Group + DACL

    try:
        conn._ldap_connection.search(
            search_base=target_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=attributes,
            controls=controls
        )

        if not conn._ldap_connection.entries:
            logging.error(f"Object not found: {target}")
            return

        entry = conn._ldap_connection.entries[0]

        # Display results
        print(f"\n{entry.entry_dn}")
        print("-" * len(entry.entry_dn))

        for attr_name in sorted(entry.entry_attributes):
            attr_value = entry[attr_name]

            # Handle security descriptor resolution
            if resolve_sd and attr_name.lower() == "ntsecuritydescriptor":
                try:
                    raw_sd = attr_value.raw_values[0]
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)

                    # Display owner
                    if sd['OwnerSid']:
                        owner_sid = format_sid(sd['OwnerSid']).formatCanonical()
                        owner_name = conn.get_samaccountname_from_sid(owner_sid)
                        print(f"  Owner: {owner_name} ({owner_sid})")

                    # Display group
                    if sd['GroupSid']:
                        group_sid = format_sid(sd['GroupSid']).formatCanonical()
                        group_name = conn.get_samaccountname_from_sid(group_sid)
                        print(f"  Group: {group_name} ({group_sid})")

                    # Display DACL ACE count
                    if sd['Dacl']:
                        print(f"  DACL ACEs: {len(sd['Dacl'].aces)}")
                    continue
                except Exception as e:
                    logging.debug(f"Failed to parse security descriptor: {e}")

            # Handle raw values
            if raw:
                if hasattr(attr_value, 'raw_values'):
                    values = attr_value.raw_values
                else:
                    values = [attr_value.value]
            else:
                if hasattr(attr_value, 'values'):
                    values = attr_value.values if attr_value.values else [attr_value.value]
                else:
                    values = [attr_value.value]

            # Format output
            if values is None:
                continue
            elif isinstance(values, list):
                if len(values) == 0:
                    continue
                elif len(values) == 1:
                    print(f"  {attr_name}: {values[0]}")
                else:
                    print(f"  {attr_name}:")
                    for v in values:
                        print(f"    {v}")
            else:
                print(f"  {attr_name}: {values}")

        print()

    except ldap3.core.exceptions.LDAPException as e:
        logging.error(f"LDAP error: {e}")
    except Exception as e:
        logging.error(f"Error retrieving object: {e}")


def attribute(conn, target: str, attr: str, raw: bool = False):
    """
    Retrieve a specific attribute value from any LDAP object.

    This function provides a simple way to get one or more attribute values
    from an AD object, supporting multiple target identification formats.

    Args:
        conn: LDAP connection object
        target: Target identifier (sAMAccountName, DN, or SID)
        attr: Comma-separated list of attributes to retrieve
        raw: If True, display raw values without formatting (default: False)

    Example:
        get attribute Administrator description
        get attribute user1 memberOf,primaryGroupID
        get attribute DC01$ servicePrincipalName
    """
    # Resolve target to DN
    target_dn = resolve_target(conn, target)
    if not target_dn:
        return

    # Parse attributes
    attributes = [a.strip() for a in attr.split(",")]

    try:
        conn._ldap_connection.search(
            search_base=target_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=attributes
        )

        if not conn._ldap_connection.entries:
            logging.error(f"Object not found: {target}")
            return

        entry = conn._ldap_connection.entries[0]

        # Display results
        for attr_name in attributes:
            if attr_name not in entry.entry_attributes:
                logging.info(f"{attr_name}: <not set>")
                continue

            attr_value = entry[attr_name]

            # Handle raw values
            if raw:
                if hasattr(attr_value, 'raw_values'):
                    values = attr_value.raw_values
                else:
                    values = [attr_value.value]
            else:
                if hasattr(attr_value, 'values'):
                    values = attr_value.values if attr_value.values else [attr_value.value]
                else:
                    values = [attr_value.value]

            # Format output
            if values is None:
                logging.info(f"{attr_name}: <not set>")
            elif isinstance(values, list):
                if len(values) == 0:
                    logging.info(f"{attr_name}: <empty>")
                elif len(values) == 1:
                    print(f"{attr_name}: {values[0]}")
                else:
                    print(f"{attr_name}:")
                    for v in values:
                        print(f"  {v}")
            else:
                print(f"{attr_name}: {values}")

    except ldap3.core.exceptions.LDAPException as e:
        logging.error(f"LDAP error: {e}")
    except Exception as e:
        logging.error(f"Error retrieving attribute: {e}")

