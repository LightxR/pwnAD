from impacket.ldap import ldaptypes
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars
from ldap3 import BASE
import ldap3
import logging

from pwnAD.lib.accesscontrol import *
from pwnAD.lib.utils import format_list_results
from pwnAD.commands.query import query


def users(conn):
    query(conn, "(objectClass=user)", "samaccountname", simple=True)

def user(conn, account):
    query(conn, f"(&(objectClass=*)(samaccountname={account}))", "*")

def computers(conn):
    query(conn, "(objectCategory=Computer)", "samaccountname", simple=True)

def DC(conn):
    query(conn, "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", ["samaccountname", "serviceprincipalname"])

def servers(conn):
    query(conn, "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))", "samaccountname", simple=True)

def CA(conn):
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
    query(conn, "(objectCategory=organizationalUnit)", "distinguishedname", simple=True)

def containers(conn):
    query(conn, "(objectCategory=container)", "distinguishedname", simple=True)

def spn(conn):
    query(conn, "(&(objectClass=User)(serviceprincipalname=*)(samaccountname=*))", ["samaccountname", "serviceprincipalname"])

def constrained_delegation(conn):
    query(conn, "(&(objectClass=User)(msDS-AllowedToDelegateTo=*))", ["samaccountname", "serviceprincipalname", "msDS-AllowedToDelegateTo"])

def unconstrained_delegation(conn):
    query(conn, "(userAccountControl:1.2.840.113556.1.4.803:=524288)", ["samaccountname", "servicePrincipalName"])

def not_trusted_for_delegation(conn):
    query(conn, "(&(samaccountname=*)(userAccountControl:1.2.840.113556.1.4.803:=1048576))", "samaccountname", simple=True)

def asreproastables(conn):
    query(conn, "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", "samaccountname", simple=True)

def kerberoastables(conn):
    query(conn, "(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))", "samaccountname", simple=True)

def password_not_required(conn):
    query(conn, "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))", "samaccountname", simple=True)

def groups(conn):
    query(conn, "(objectCategory=group)", "samaccountname", simple=True)

def protected_users(conn):
    query(conn, f"(&(objectCategory=CN=group,CN=Schema,CN=configuration,{conn._baseDN})(samaccountname=Protect*)(member=*))", "samaccountname", simple=True)

def users_description(conn):
    query(conn, "(&(objectCategory=user)(description=*))", "description")

def passwords_dont_expire(conn):
    query(conn, "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))", "samaccountname", simple=True)

def users_with_admin_count(conn):
    query(conn, "(&(objectClass=user)(admincount=1)(!(samaccountname=krbtgt))(!(samaccountname=administrator)))", "samaccountname", simple=True)

def accounts_with_sid_histoy(conn):
    query(conn, "(&(objectCategory=Person)(objectClass=User)(sidHistory=*))", "samaccountname", simple=True) 

def members(conn, group):
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
