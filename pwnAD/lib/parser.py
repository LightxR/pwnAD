import argparse
import sys
import re
from impacket.krb5 import constants


class PwnADHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom help formatter for pwnAD with clean grouped commands display."""

    def __init__(self, prog, indent_increment=2, max_help_position=36, width=100):
        super().__init__(prog, indent_increment, max_help_position, width)

    def _metavar_formatter(self, action, default_metavar):
        # Suppress subparsers choices display in usage line
        if isinstance(action, argparse._SubParsersAction):
            def format(tuple_size):
                return '<command>' if tuple_size == 1 else ('<command>',) * tuple_size
            return format
        return super()._metavar_formatter(action, default_metavar)

    def _format_action(self, action):
        # Skip the subparsers action entirely - we show commands in description
        if isinstance(action, argparse._SubParsersAction):
            return ''
        return super()._format_action(action)


class PwnADArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that shows formatted help on errors."""

    def error(self, message):
        """Override error to show help instead of ugly error message."""
        sys.stderr.write(f'\n\033[91m[-] Error: {self._clean_error_message(message)}\033[0m\n\n')
        self.print_help(sys.stderr)
        sys.exit(2)

    def _clean_error_message(self, message):
        """Clean up error message for better readability."""
        # Simplify "invalid choice" messages
        if 'invalid choice:' in message:
            match = re.search(r"invalid choice: '([^']+)'", message)
            if match:
                invalid_value = match.group(1)
                return f"'{invalid_value}' is not a valid command. See available commands below."
        # Simplify "required" messages
        if 'required:' in message:
            return message.replace('the following arguments are required:', 'missing required argument(s):')
        return message


def authentication_args(parser):
    conn = parser.add_argument_group("Connection")
    conn.add_argument("--dc-ip", action="store", metavar="IP", help="Domain Controller IP address")
    conn.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN", help="KDC hostname (for Kerberos)")
    conn.add_argument("-d", "--domain", dest="domain", metavar="DOMAIN", action="store", help="Target domain (FQDN)")
    conn.add_argument("-u", "--user", dest="username", metavar="USER", action="store", help="Username")
    conn.add_argument("--port", dest="port", metavar="PORT", action="store", type=int, help="LDAP port")
    conn.add_argument("--tls", dest="_do_tls", action="store_true", default=None, help="Use LDAPS/TLS")

    creds = parser.add_argument_group("Credentials")
    cred_mutex = creds.add_mutually_exclusive_group()
    cred_mutex.add_argument("-p", "--password", dest="password", metavar="PASS", action="store", help="Password")
    cred_mutex.add_argument("-H", "--hashes", dest="hashes", action="store", metavar="[LM:]NT", help="NTLM hash (LMhash:NThash or :NThash)")
    cred_mutex.add_argument("--aes-key", dest="aesKey", action="store", metavar="KEY", help="AES128/256 key for Kerberos")
    creds.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos auth (ccache from KRB5CCNAME)")

    cert = parser.add_argument_group("Certificate Auth")
    cert.add_argument("-pfx", dest="pfx", action="store", metavar="FILE", help="PFX/P12 certificate file")
    cert.add_argument("-pfx-pass", dest="pfx_pass", action="store", metavar="PASS", default=None, help="PFX password")
    cert.add_argument("-key", dest="key", action="store", metavar="FILE", help="Private key file (.key)")
    cert.add_argument("-cert", dest="cert", action="store", metavar="FILE", help="Certificate file (.crt)")

    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-i", "--interactive", dest="interactive", action="store_true", default=None, help="Start interactive shell")


def get_parser(interactive=False):
    all_subparsers = []
    action_parsers = {}  # Parsers for actions that require a function

    description = """
Active Directory exploitation tool for LDAP and Kerberos protocols.

Commands:
  LDAP Actions:
    add                 Add objects, ACEs, or attributes
    remove              Remove objects, ACEs, or attributes
    get                 Query objects and enumerate information
    modify              Modify object attributes
    query               Execute raw LDAP queries

  Modules:
    shadow              Shadow Credentials attack (msDS-KeyCredentialLink)
    dacl                DACL operations (read, write, backup, restore)

  Kerberos:
    getTGT              Request TGT (AS-REQ)
    getST               Request ST via S4U2Self/S4U2Proxy
    getNThash           Extract NT hash via U2U PKINIT"""

    epilog = """
Examples:
  pwnAD get users -d corp.local -u admin -p 'P@ss' --dc-ip 10.0.0.1
  pwnAD add computer YOURPC$ pass123 -d corp.local -u user -H :NTHASH --dc-ip DC
  pwnAD shadow auto targetUser$ -d corp.local -u admin -p pass --dc-ip DC
  pwnAD getTGT -d corp.local -u user -p pass --dc-ip 10.0.0.1
  pwnAD -i -d corp.local -u admin -p 'P@ss' --dc-ip 10.0.0.1

Use 'pwnAD <command> -h' for more information on a specific command."""

    if interactive:
        description += """

  Session:
    switch_user         Re-authenticate as a different user
    infos               Display current session information
    rebind              Reconnect after timeout
    start_tls           Upgrade connection to TLS"""
        epilog = ""

    parser = PwnADArgumentParser(
        prog='pwnAD',
        description=description,
        epilog=epilog,
        formatter_class=PwnADHelpFormatter,
        add_help=True
    )

    # Create subparsers (hidden from main help, shown in description)
    subparsers = parser.add_subparsers(
        dest="action",
        metavar="<command>",
        parser_class=PwnADArgumentParser
    )

    # ═══════════════════════════════════════════════════════════════════
    # LDAP Actions
    # ═══════════════════════════════════════════════════════════════════

    # ADD action
    add_description = """
Add objects, ACEs, or attributes to Active Directory.

Functions:
  Objects:       user, computer
  ACEs:          dcsync, genericAll, write_gpo_dacl, RBCD
  Membership:    groupMember
  Attributes:    uac, attribute, dnsRecord"""

    parser_add = subparsers.add_parser(
        'add',
        help='Add objects, ACEs, or attributes',
        description=add_description,
        formatter_class=PwnADHelpFormatter
    )
    add_subparsers = parser_add.add_subparsers(dest="function", metavar="<function>", parser_class=PwnADArgumentParser)
    all_subparsers.append(parser_add)
    action_parsers['add'] = parser_add

    # ADD specific functions
    add_user_parser = add_subparsers.add_parser('user', help="Add a user")
    add_user_parser.add_argument("new_user",  action="store", help="Name of the user you wish to add")
    add_user_parser.add_argument("new_password", action="store", help="Password of the user you wish to add")
    all_subparsers.append(add_user_parser)

    add_computer_parser = add_subparsers.add_parser('computer', help="Add a computer")
    add_computer_parser.add_argument("new_computer", action="store", help="Name of the user you wish to add")
    add_computer_parser.add_argument("new_password", action="store", help="Password of the user you wish to add")
    all_subparsers.append(add_computer_parser)

    add_dcsync_parser = add_subparsers.add_parser('dcsync', help="Add DCSync rights to an object")
    add_dcsync_parser.add_argument("trustee", action="store", help="Name of the trustee you want to add DCSync rights")
    all_subparsers.append(add_dcsync_parser)

    add_genericAll_parser = add_subparsers.add_parser('genericAll', help="Add genericAll rights to an object")
    add_genericAll_parser.add_argument("target", action="store", help="Target")
    add_genericAll_parser.add_argument("trustee", action="store", help="Trustee that will have genericAll rights on target")
    all_subparsers.append(add_genericAll_parser)

    add_groupMember_parser = add_subparsers.add_parser('groupMember', help="Add a user/computer to a targeted group")
    add_groupMember_parser.add_argument("group", action="store", help="Group you want your member to be added")
    add_groupMember_parser.add_argument("member", action="store", help="Member that will be added to the specified group")
    all_subparsers.append(add_groupMember_parser)

    add_write_gpo_dacl_parser = add_subparsers.add_parser('write_gpo_dacl', help="Give full control on a GPO for the specified user")
    add_write_gpo_dacl_parser.add_argument("user", action="store", help="User you want to give the rights on GPO")
    add_write_gpo_dacl_parser.add_argument("gposid", action="store", help="sid of the GPO to be controlled by the specified user")
    all_subparsers.append(add_write_gpo_dacl_parser)

    add_rbcd_parser = add_subparsers.add_parser('RBCD', help="Add Resource Based Constraint Delegation for service on target")
    add_rbcd_parser.add_argument("target", action="store", help="Target which msDS-AllowedToActOnBehalfOfOtherIdentity attribute will be modified")
    add_rbcd_parser.add_argument("grantee", action="store", help="Service that will be granted rights to impersonate users on target")
    all_subparsers.append(add_rbcd_parser)

    add_dnsrecord_parser = add_subparsers.add_parser('dnsRecord', help="Add a DNS record to Active Directory Integrated DNS")
    add_dnsrecord_parser.add_argument("name", action="store", help="Hostname for the DNS record")
    add_dnsrecord_parser.add_argument("data", action="store", help="Record data (IP address, hostname, or text)")
    add_dnsrecord_parser.add_argument("--dnstype", dest="dnstype", action="store", default="A", choices=["A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT"], help="Type of DNS record (default: A)")
    add_dnsrecord_parser.add_argument("--zone", dest="zone", action="store", default=None, help="DNS zone name (default: current domain)")
    add_dnsrecord_parser.add_argument("--ttl", dest="ttl", action="store", type=int, default=300, help="Time to live in seconds (default: 300)")
    add_dnsrecord_parser.add_argument("--preference", dest="preference", action="store", type=int, default=10, help="Preference for MX records (default: 10)")
    add_dnsrecord_parser.add_argument("--priority", dest="priority", action="store", type=int, default=0, help="Priority for SRV records (default: 0)")
    add_dnsrecord_parser.add_argument("--weight", dest="weight", action="store", type=int, default=100, help="Weight for SRV records (default: 100)")
    add_dnsrecord_parser.add_argument("--srvport", dest="srvport", action="store", type=int, default=80, help="Port for SRV records (default: 80)")
    all_subparsers.append(add_dnsrecord_parser)

    add_uac_parser = add_subparsers.add_parser('uac', help="Add UAC property flags to a user/computer account")
    add_uac_parser.add_argument("target", action="store", help="sAMAccountName of the target user/computer")
    add_uac_parser.add_argument("-f", "--flag", dest="flags", action="append", required=True, metavar="FLAG", help="UAC flag to add (can be specified multiple times, e.g. -f DONT_REQ_PREAUTH -f TRUSTED_FOR_DELEGATION)")
    all_subparsers.append(add_uac_parser)

    add_attribute_parser = add_subparsers.add_parser('attribute', help="Add values to an attribute of any LDAP object")
    add_attribute_parser.add_argument("target", action="store", help="Target object (sAMAccountName, DN, or SID)")
    add_attribute_parser.add_argument("attr", action="store", help="Attribute name to add values to")
    add_attribute_parser.add_argument("values", nargs="+", action="store", help="Value(s) to add")
    add_attribute_parser.add_argument("--raw", dest="raw", action="store_true", help="Send values as-is without encoding")
    add_attribute_parser.add_argument("--b64", dest="b64", action="store_true", help="Decode values from base64")
    all_subparsers.append(add_attribute_parser)


    # REMOVE action
    remove_description = """
Remove objects, ACEs, or attributes from Active Directory.

Functions:
  Objects:       user, computer, object
  ACEs:          dcsync, genericAll, RBCD
  Membership:    groupMember
  Attributes:    uac, attribute, dnsRecord"""

    parser_remove = subparsers.add_parser(
        'remove',
        help='Remove objects, ACEs, or attributes',
        description=remove_description,
        formatter_class=PwnADHelpFormatter
    )
    remove_subparsers = parser_remove.add_subparsers(dest="function", metavar="<function>", parser_class=PwnADArgumentParser)
    all_subparsers.append(parser_remove)
    action_parsers['remove'] = parser_remove

    # REMOVE specific functions 
    remove_computer_parser = remove_subparsers.add_parser('computer', help="Remove a computer")
    remove_computer_parser.add_argument("computer_name", action="store", help="Name of the computer you wish to remove")
    all_subparsers.append(remove_computer_parser)

    remove_user_parser = remove_subparsers.add_parser('user', help="Remove a user")
    remove_user_parser.add_argument("user_name", action="store", help="Name of the user you wish to remove")
    all_subparsers.append(remove_user_parser)

    remove_groupMember_parser = remove_subparsers.add_parser('groupMember', help="Remove a user/computer from a targeted group")
    remove_groupMember_parser.add_argument("group", action="store", help="Group you want your member to be removed")
    remove_groupMember_parser.add_argument("member", action="store", help="Member that will be removed from the specified group")
    all_subparsers.append(remove_groupMember_parser)

    remove_dcsync_parser = remove_subparsers.add_parser('dcsync', help="Remove DCSync rights from an object")
    remove_dcsync_parser.add_argument("trustee", action="store", help="Name of the trustee you want to remove DCSync rights from")
    all_subparsers.append(remove_dcsync_parser)

    remove_genericAll_parser = remove_subparsers.add_parser('genericAll', help="Remove genericAll rights from an object")
    remove_genericAll_parser.add_argument("target", action="store", help="Target")
    remove_genericAll_parser.add_argument("trustee", action="store", help="Trustee that have genericAll rights on target")
    all_subparsers.append(remove_genericAll_parser)

    remove_rbcd_parser = remove_subparsers.add_parser('RBCD', help="Remove msDS-AllowedToActOnBehalfOfOtherIdentity attribute")
    remove_rbcd_parser.add_argument("computer_name", action="store", help="Name of the computer you wish to remove msDS-AllowedToActOnBehalfOfOtherIdentity attribute")
    all_subparsers.append(remove_rbcd_parser)

    remove_uac_parser = remove_subparsers.add_parser('uac', help="Remove UAC property flags from a user/computer account")
    remove_uac_parser.add_argument("target", action="store", help="sAMAccountName of the target user/computer")
    remove_uac_parser.add_argument("-f", "--flag", dest="flags", action="append", required=True, metavar="FLAG", help="UAC flag to remove (can be specified multiple times, e.g. -f DONT_REQ_PREAUTH -f TRUSTED_FOR_DELEGATION)")
    all_subparsers.append(remove_uac_parser)

    remove_dnsrecord_parser = remove_subparsers.add_parser('dnsRecord', help="Remove a DNS record from Active Directory Integrated DNS")
    remove_dnsrecord_parser.add_argument("name", action="store", help="Hostname of the DNS record to remove")
    remove_dnsrecord_parser.add_argument("--data", dest="data", action="store", default=None, help="Record data to remove specific record (IP, hostname, text)")
    remove_dnsrecord_parser.add_argument("--dnstype", dest="dnstype", action="store", default=None, choices=["A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT"], help="Type of DNS record to remove")
    remove_dnsrecord_parser.add_argument("--zone", dest="zone", action="store", default=None, help="DNS zone name (default: current domain)")
    all_subparsers.append(remove_dnsrecord_parser)

    remove_attribute_parser = remove_subparsers.add_parser('attribute', help="Remove values from an attribute or clear it entirely")
    remove_attribute_parser.add_argument("target", action="store", help="Target object (sAMAccountName, DN, or SID)")
    remove_attribute_parser.add_argument("attr", action="store", help="Attribute name to remove values from")
    remove_attribute_parser.add_argument("values", nargs="*", action="store", help="Value(s) to remove. If not specified, clears the entire attribute")
    remove_attribute_parser.add_argument("--raw", dest="raw", action="store_true", help="Send values as-is without encoding")
    remove_attribute_parser.add_argument("--b64", dest="b64", action="store_true", help="Decode values from base64")
    all_subparsers.append(remove_attribute_parser)

    remove_object_parser = remove_subparsers.add_parser('object', help="Delete an entire LDAP object")
    remove_object_parser.add_argument("target", action="store", help="Target object to delete (sAMAccountName, DN, or SID)")
    all_subparsers.append(remove_object_parser)

    # GET action
    get_description = """
Query and enumerate Active Directory objects.

Functions:
  Objects:
    user, users, computers, groups, DC, servers, CA, OU, containers, object, attribute

  Membership:
    members, membership

  Delegation:
    constrained_delegation, unconstrained_delegation, RBCD, not_trusted_for_delegation

  Kerberos Attacks:
    asreproastables, kerberoastables, spn

  Credentials:
    laps, gmsa

  Miscellaneous:
    owner, machine_quota, writable, protected_users, users_description,
    passwords_dont_expire, users_with_admin_count, accounts_with_sid_histoy,
    password_not_required"""

    parser_get = subparsers.add_parser(
        'get',
        help='Query objects and enumerate information',
        description=get_description,
        formatter_class=PwnADHelpFormatter
    )
    get_subparsers = parser_get.add_subparsers(dest="function", metavar="<function>", parser_class=PwnADArgumentParser)
    all_subparsers.append(parser_get)
    action_parsers['get'] = parser_get

    # GET specific functions
    get_user_parser = get_subparsers.add_parser('user', help="Get user account information")
    get_user_parser.add_argument("account", action="store", help="Account you want information on")
    all_subparsers.append(get_user_parser)

    get_users_parser = get_subparsers.add_parser('users', help="Retrieve all domain users")
    all_subparsers.append(get_users_parser)

    get_members_parser = get_subparsers.add_parser('members', help="Retrieve all members from a group")
    get_members_parser.add_argument("group", action="store", help="Group you want to know the members")
    all_subparsers.append(get_members_parser)
    
    get_membership_parser = get_subparsers.add_parser('membership', help="Retrieve all groups membership for a specified account")
    get_membership_parser.add_argument("account", action="store", help="Account you want to know group memberships")
    get_membership_parser.add_argument("-r", "--recurse", action="store_true", help="Perform recursive search for membership (depth up to 5)")
    all_subparsers.append(get_membership_parser)

    get_computers_parser = get_subparsers.add_parser('computers', help="Retrieve computers")
    all_subparsers.append(get_computers_parser)

    get_DC_parser = get_subparsers.add_parser('DC', help="Retrieve domain controllers")
    all_subparsers.append(get_DC_parser)

    get_servers_parser = get_subparsers.add_parser('servers', help="Retrieve servers")
    all_subparsers.append(get_servers_parser)

    get_CA_parser = get_subparsers.add_parser('CA', help="Retrieve Certificate Authority")
    all_subparsers.append(get_CA_parser)

    get_OU_parser = get_subparsers.add_parser('OU', help="Retrieve OU from the domain")
    all_subparsers.append(get_OU_parser)

    get_containers_parser = get_subparsers.add_parser('containers', help="Retrieve containers from the domain")
    all_subparsers.append(get_containers_parser)

    get_spn_parser = get_subparsers.add_parser('spn', help="Retrieve all accounts with spn")
    all_subparsers.append(get_spn_parser)

    get_constrained_delegation_parser = get_subparsers.add_parser('constrained_delegation', help="Retrieve accounts with constrained delegation enabled")
    all_subparsers.append(get_constrained_delegation_parser)

    get_unconstrained_delegation_parser = get_subparsers.add_parser('unconstrained_delegation', help="Retrieve accounts with unconstrained delegation enabled")
    all_subparsers.append(get_unconstrained_delegation_parser)

    get_rbcd_parser = get_subparsers.add_parser('RBCD', help="Retrieve accounts with RBCD enabled")
    all_subparsers.append(get_rbcd_parser)

    get_not_trusted_for_delegation_parser = get_subparsers.add_parser('not_trusted_for_delegation', help="Retrieve accounts not trusted for delegation")
    all_subparsers.append(get_not_trusted_for_delegation_parser)

    get_asreproastables_parser = get_subparsers.add_parser('asreproastables', help="Retrieve asreproastables accounts")
    all_subparsers.append(get_asreproastables_parser)

    get_kerberoastables_parser = get_subparsers.add_parser('kerberoastables', help="Retrieve kerberoastable accounts")
    all_subparsers.append(get_kerberoastables_parser)

    get_password_not_required_parser = get_subparsers.add_parser('password_not_required', help="Retrieve accounts with PASSWD_NOTREQD set")
    all_subparsers.append(get_password_not_required_parser)

    get_user_parser = get_subparsers.add_parser('groups', help="Retrieve user account information")
    all_subparsers.append(get_user_parser)

    get_groups_parser = get_subparsers.add_parser('protected_users', help="Retrieve all groups from domain")
    all_subparsers.append(get_groups_parser)

    get_users_description_parser = get_subparsers.add_parser('users_description', help="Retrieve all user accounts with description")
    all_subparsers.append(get_users_description_parser)

    get_passwords_dont_expire_parser = get_subparsers.add_parser('passwords_dont_expire', help="Retrieve accounts with UserAccountControl set to DONT_EXPIRE_PASSWD")
    all_subparsers.append(get_passwords_dont_expire_parser)

    get_users_with_admin_count_parser = get_subparsers.add_parser('users_with_admin_count', help="Retrieve account with attribute adminaccount=1")
    all_subparsers.append(get_users_with_admin_count_parser)

    get_accounts_with_sid_histoy_parser = get_subparsers.add_parser('accounts_with_sid_histoy', help="Retrieve accounts with SID history")
    all_subparsers.append(get_accounts_with_sid_histoy_parser)

    get_owner_parser = get_subparsers.add_parser('owner', help="Get the owner of a specified object")
    get_owner_parser.add_argument("target", action="store", help="Object you want to known the owner")
    all_subparsers.append(get_owner_parser)

    get_machine_quota_parser = get_subparsers.add_parser('machine_quota', help="Retrieve machine_quota from domain")
    all_subparsers.append(get_machine_quota_parser)

    get_laps_parser = get_subparsers.add_parser('laps', help="Retrieve laps passwords")
    all_subparsers.append(get_laps_parser)

    get_gmsa_parser = get_subparsers.add_parser('gmsa', help="Retrieve gmsa passwords")
    all_subparsers.append(get_gmsa_parser)

    get_writable_parser = get_subparsers.add_parser('writable', help="Retrieve objects writable by the current user")
    get_writable_parser.add_argument("--otype", dest="otype", action="store", default="*", help="Object class filter (e.g., user, computer, group, ou, gpo, or *)")
    get_writable_parser.add_argument("--right", dest="right", action="store", choices=["ALL", "WRITE", "CHILD"], default="ALL", help="Type of right to search (default: ALL)")
    get_writable_parser.add_argument("--detail", dest="detail", action="store_true", help="Display writable attributes and child classes")
    get_writable_parser.add_argument("--partition", dest="partition", action="store", choices=["DOMAIN", "CONFIGURATION", "SCHEMA", "ALL"], default="DOMAIN", help="Directory partition to explore (default: DOMAIN)")
    get_writable_parser.add_argument("--exclude-deleted", dest="exclude_deleted", action="store_true", help="Exclude deleted objects from results")
    all_subparsers.append(get_writable_parser)

    get_object_parser = get_subparsers.add_parser('object', help="Retrieve attributes of any LDAP object")
    get_object_parser.add_argument("target", action="store", help="Target object (sAMAccountName, DN, or SID)")
    get_object_parser.add_argument("--attr", dest="attr", action="store", default="*", help="Comma-separated list of attributes to retrieve (default: *)")
    get_object_parser.add_argument("--resolve-sd", dest="resolve_sd", action="store_true", help="Resolve security descriptors to readable format")
    get_object_parser.add_argument("--raw", dest="raw", action="store_true", help="Display raw attribute values")
    all_subparsers.append(get_object_parser)

    get_attribute_parser = get_subparsers.add_parser('attribute', help="Retrieve specific attribute(s) from any LDAP object")
    get_attribute_parser.add_argument("target", action="store", help="Target object (sAMAccountName, DN, or SID)")
    get_attribute_parser.add_argument("attr", action="store", help="Comma-separated list of attributes to retrieve")
    get_attribute_parser.add_argument("--raw", dest="raw", action="store_true", help="Display raw attribute values")
    all_subparsers.append(get_attribute_parser)

    # MODIFY action
    modify_description = """
Modify Active Directory object attributes.

Functions:
  Credentials:   password
  Properties:    owner, computer_name, dontreqpreauth, attribute
  Account:       disable_account, enable_account"""

    parser_modify = subparsers.add_parser(
        'modify',
        help='Modify object attributes',
        description=modify_description,
        formatter_class=PwnADHelpFormatter
    )
    modify_subparsers = parser_modify.add_subparsers(dest="function", metavar="<function>", parser_class=PwnADArgumentParser)
    all_subparsers.append(parser_modify)
    action_parsers['modify'] = parser_modify
    
    # MODIFY specific functions
    modify_password_parser = modify_subparsers.add_parser('password', help="Modify a password for a specified account")
    modify_password_parser.add_argument("account", action="store", help="Name of the account you wish to modify")
    modify_password_parser.add_argument("new_password", action="store", help="New password of the account")
    all_subparsers.append(modify_password_parser)

    modify_owner_parser = modify_subparsers.add_parser('owner', help="Modify the owner of a specified object")
    modify_owner_parser.add_argument("target", action="store", help="Name of the object you want to modify the owner")
    modify_owner_parser.add_argument("new_owner", action="store", help="New owner of the object")
    all_subparsers.append(modify_owner_parser)

    modify_computer_name_parser = modify_subparsers.add_parser('computer_name', help="Modify the name of the specified computer")
    modify_computer_name_parser.add_argument("current_name", action="store", help="Current name of the computer")
    modify_computer_name_parser.add_argument("new_name", action="store", help="New name of the computer")
    all_subparsers.append(modify_computer_name_parser)

    modify_dontreqpreauth_parser = modify_subparsers.add_parser('dontreqpreauth', help="Modify the userAccountControl to set UF_DONT_REQUIRE_PREAUTH to True or False")
    modify_dontreqpreauth_parser.add_argument("account", action="store", help="Current name of the computer")
    modify_dontreqpreauth_parser.add_argument("flag", action="store", choices=["True", "False"], help="New name of the computer")
    all_subparsers.append(modify_dontreqpreauth_parser)

    modify_disable_account_parser = modify_subparsers.add_parser('disable_account', help="Disable the targeted account")
    modify_disable_account_parser.add_argument("username", action="store", help="Account to be disabled")
    all_subparsers.append(modify_disable_account_parser)

    modify_enable_account_parser = modify_subparsers.add_parser('enable_account', help="Enable the targeted account")
    modify_enable_account_parser.add_argument("username", action="store", help="Account to be enabled")
    all_subparsers.append(modify_enable_account_parser)

    modify_attribute_parser = modify_subparsers.add_parser('attribute', help="Replace/set an attribute value on any LDAP object")
    modify_attribute_parser.add_argument("target", action="store", help="Target object (sAMAccountName, DN, or SID)")
    modify_attribute_parser.add_argument("attr", action="store", help="Attribute name to modify")
    modify_attribute_parser.add_argument("values", nargs="+", action="store", help="Value(s) to set")
    modify_attribute_parser.add_argument("--raw", dest="raw", action="store_true", help="Send values as-is without encoding")
    modify_attribute_parser.add_argument("--b64", dest="b64", action="store_true", help="Decode values from base64")
    all_subparsers.append(modify_attribute_parser)


    # QUERY action
    parser_query = subparsers.add_parser('query', help='Execute custom LDAP query')
    parser_query.add_argument("search_filter", action="store", help="Filter to be applied on LDAP query")
    parser_query.add_argument("attributes", action="store", help="Attributes to be applied on LDAP query")
    all_subparsers.append(parser_query)

    # ═══════════════════════════════════════════════════════════════════
    # Special Modules
    # ═══════════════════════════════════════════════════════════════════

    # SHADOW action
    shadow_description = """
Shadow Credentials attack via msDS-KeyCredentialLink attribute.
Abuses PKINIT to authenticate and retrieve NT hash/TGT.

Functions:
  auto      Full attack: add KeyCredential, get NT hash + TGT, restore
  add       Add a KeyCredential to target
  list      List all KeyCredentials on target
  info      Show KeyCredential details by Device ID
  remove    Remove specific KeyCredential by Device ID
  clear     Remove all KeyCredentials from target"""

    parser_shadow = subparsers.add_parser(
        'shadow',
        help='Shadow Credentials attacks',
        description=shadow_description,
        formatter_class=PwnADHelpFormatter
    )
    shadow_subparsers = parser_shadow.add_subparsers(dest="function", metavar="<function>", parser_class=PwnADArgumentParser)
    all_subparsers.append(parser_shadow)
    action_parsers['shadow'] = parser_shadow
    
    # SHADOW specific functions
    shadow_auto_parser = shadow_subparsers.add_parser('auto', help="Add a new Key Credential to the target account, authenticate with the Key Credential to retrieve the NT hash and a TGT for the target, and finally restore the old Key Credential attribute")
    shadow_auto_parser.add_argument("target", action="store", help="Account to target")
    all_subparsers.append(shadow_auto_parser)

    shadow_add_parser = shadow_subparsers.add_parser('add', help="Add Key Credentials to a target")
    shadow_add_parser.add_argument("target", action="store", help="Account to target")
    all_subparsers.append(shadow_add_parser)

    shadow_list_parser = shadow_subparsers.add_parser('list', help="List all Key Credentials of a target")
    shadow_list_parser.add_argument("target", action="store", help="Account to target")
    all_subparsers.append(shadow_list_parser)

    shadow_clear_parser = shadow_subparsers.add_parser('clear', help="Clear all Key Credentials from a target")
    shadow_clear_parser.add_argument("target", action="store", help="Account to target")
    all_subparsers.append(shadow_clear_parser)

    shadow_remove_parser = shadow_subparsers.add_parser('remove', help="Remove Key Credentials from a target")
    shadow_remove_parser.add_argument("target", action="store", help="Account to target")
    shadow_remove_parser.add_argument("device_id", action="store", help="Device ID of the Key Credential Link")
    all_subparsers.append(shadow_remove_parser)

    shadow_info_parser = shadow_subparsers.add_parser('info', help="Display Key Credentials information from a supplied device ID")
    shadow_info_parser.add_argument("target", action="store", help="Account to target")
    shadow_info_parser.add_argument("device_id", action="store", help="Device ID of the Key Credential Link")
    all_subparsers.append(shadow_info_parser)


    # DACL action
    dacl_description = """
Discretionary Access Control List (DACL) manipulation.

Functions:
  read      Read and display DACL of an object
  write     Add an ACE to the DACL
  remove    Remove ACEs from the DACL
  backup    Export DACL to JSON file
  restore   Restore DACL from JSON backup"""

    parser_dacl = subparsers.add_parser(
        'dacl',
        help='DACL manipulation (ACL/ACE)',
        description=dacl_description,
        formatter_class=PwnADHelpFormatter
    )
    dacl_subparsers = parser_dacl.add_subparsers(dest="function", metavar="<function>", parser_class=PwnADArgumentParser)
    all_subparsers.append(parser_dacl)
    action_parsers['dacl'] = parser_dacl

    # Available rights for --right argument
    dacl_rights_choices = [
        "FullControl", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
        "AllExtendedRights", "DCSync", "WriteMembers", "AddMember", "ResetPassword",
        "Self", "ReadGMSAPassword", "ReadLAPSPassword", "WriteKeyCredentialLink", "WriteSPN"
    ]

    # DACL read - Read DACL of an object
    dacl_read_parser = dacl_subparsers.add_parser('read', help="Read and display the DACL of an object")
    dacl_read_parser.add_argument("target", action="store", help="Target object (sAMAccountName, SID, or DN)")
    dacl_read_parser.add_argument("--principal", action="store", help="Filter ACEs by principal (sAMAccountName or SID)")
    dacl_read_parser.add_argument("--resolve-sids", dest="resolve_sids", action="store_true", help="Resolve SIDs to sAMAccountNames")
    all_subparsers.append(dacl_read_parser)

    # DACL write - Add an ACE to the DACL
    dacl_write_parser = dacl_subparsers.add_parser('write', help="Add an ACE to the DACL of an object")
    dacl_write_parser.add_argument("target", action="store", help="Target object (sAMAccountName, SID, or DN)")
    dacl_write_parser.add_argument("--principal", required=True, action="store", help="Principal to grant/deny rights (sAMAccountName or SID)")
    dacl_write_parser.add_argument("--right", required=True, action="store", choices=dacl_rights_choices, help="Right to grant/deny")
    dacl_write_parser.add_argument("--ace-type", dest="ace_type", action="store", choices=["allowed", "denied"], default="allowed", help="ACE type (default: allowed)")
    dacl_write_parser.add_argument("--inheritance", action="store_true", help="Set inheritance flags on the ACE")
    all_subparsers.append(dacl_write_parser)

    # DACL remove - Remove ACEs from the DACL
    dacl_remove_parser = dacl_subparsers.add_parser('remove', help="Remove ACEs from the DACL of an object")
    dacl_remove_parser.add_argument("target", action="store", help="Target object (sAMAccountName, SID, or DN)")
    dacl_remove_parser.add_argument("--principal", required=True, action="store", help="Principal whose ACEs to remove (sAMAccountName or SID)")
    dacl_remove_parser.add_argument("--right", action="store", choices=dacl_rights_choices, help="Specific right to remove (removes all if not specified)")
    dacl_remove_parser.add_argument("--ace-type", dest="ace_type", action="store", choices=["allowed", "denied"], help="Filter by ACE type")
    all_subparsers.append(dacl_remove_parser)

    # DACL backup - Backup the DACL to a JSON file
    dacl_backup_parser = dacl_subparsers.add_parser('backup', help="Backup the DACL of an object to a JSON file")
    dacl_backup_parser.add_argument("target", action="store", help="Target object (sAMAccountName, SID, or DN)")
    dacl_backup_parser.add_argument("--output", "-o", action="store", help="Output file path (default: <target>_dacl_backup.json)")
    all_subparsers.append(dacl_backup_parser)

    # DACL restore - Restore the DACL from a JSON file
    dacl_restore_parser = dacl_subparsers.add_parser('restore', help="Restore the DACL of an object from a JSON backup file")
    dacl_restore_parser.add_argument("backup_file", action="store", help="Path to the backup JSON file")
    all_subparsers.append(dacl_restore_parser)

    # ═══════════════════════════════════════════════════════════════════
    # Kerberos Actions
    # ═══════════════════════════════════════════════════════════════════

    # getTGT action
    parser_gettgt = subparsers.add_parser('getTGT', help='Request a Ticket Granting Ticket')
    parser_gettgt.add_argument('-principalType', nargs="?", type=lambda value: constants.PrincipalNameType[value.upper()] if value.upper() in constants.PrincipalNameType.__members__ else None,  action='store', default=constants.PrincipalNameType.NT_PRINCIPAL, help='PrincipalType of the token, can be one of  NT_UNKNOWN, NT_PRINCIPAL, NT_SRV_INST, NT_SRV_HST, NT_SRV_XHST, NT_UID, NT_SMTP_NAME, NT_ENTERPRISE, NT_WELLKNOWN, NT_SRV_HST_DOMAIN, NT_MS_PRINCIPAL, NT_MS_PRINCIPAL_AND_ID, NT_ENT_PRINCIPAL_AND_ID; default is NT_PRINCIPAL, ')
    parser_gettgt.add_argument("-spn", dest="spn", metavar="SPN", action="store", help="Request a Service Ticket directly through")
    all_subparsers.append(parser_gettgt)


    # getST action
    parser_getst = subparsers.add_parser('getST', help='Request a Service Ticket (S4U)')
    parser_getst.add_argument('-spn', action="store", help='SPN (service/server) of the target service the service ticket will be generated for')
    parser_getst.add_argument('-altservice', action="store", help='New sname/SPN to set in the ticket')
    parser_getst.add_argument('-impersonate', action="store", help='target username that will be impersonated (thru S4U2Self)'
                                                             ' for quering the ST. Keep in mind this will only work if '
                                                             'the identity provided in this scripts is allowed for '
                                                             'delegation to the SPN specified')
    parser_getst.add_argument('-additional-ticket', action='store', metavar='ticket.ccache', help='include a forwardable service ticket in a S4U2Proxy request for RBCD + KCD Kerberos only')
    parser_getst.add_argument('-u2u', dest='u2u', action='store_true', help='Request User-to-User ticket')
    parser_getst.add_argument('-self', dest='no_s4u2proxy', action='store_true', help='Only do S4U2self, no S4U2proxy')
    parser_getst.add_argument('-force-forwardable', action='store_true', help='Force the service ticket obtained through '
                                                                        'S4U2Self to be forwardable. For best results, the -hashes and -aesKey values for the '
                                                                        'specified -identity should be provided. This allows impresonation of protected users '
                                                                        'and bypass of "Kerberos-only" constrained delegation restrictions. See CVE-2020-17049')
    parser_getst.add_argument('-renew', action='store_true', help='Sets the RENEW ticket option to renew the TGT used for authentication. Set -spn to \'krbtgt/DOMAINFQDN\'')
    all_subparsers.append(parser_getst)


    # getNThash action
    parser_getnthash = subparsers.add_parser('getNThash', help='Retrieve NT hash via PKINIT (U2U)')
    all_subparsers.append(parser_getnthash)


    # getPFX action
    # parser_getpfx = subparsers.add_parser('getPFX', help='Perform getPFX related actions')
    # all_subparsers.append(parser_getpfx)


    if interactive:
        authentication_args(parser_gettgt)
        authentication_args(parser_getst)
        authentication_args(parser_getnthash)
        # authentication_args(parser_getpfx)

        # ═══════════════════════════════════════════════════════════════════
        # Interactive Session
        # ═══════════════════════════════════════════════════════════════════

        parser_switch = subparsers.add_parser('switch_user', help='Switch to a different user')
        authentication_args(parser_switch)

        parser_infos = subparsers.add_parser('infos', help='Display current session information')

        parser_rebind = subparsers.add_parser('rebind', help='Rebind session (after timeout)')

        parser_start_tls = subparsers.add_parser('start_tls', help='Initiate TLS connection')

    return parser, all_subparsers, action_parsers

def parseArgs():
    parser, all_subparsers, action_parsers = get_parser()

    authentication_args(parser)
    for subparser in all_subparsers:
        authentication_args(subparser)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    return args, action_parsers


def interactive_parser():
    parser, _, action_parsers = get_parser(interactive=True)

    return parser, action_parsers