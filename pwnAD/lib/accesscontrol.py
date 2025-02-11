from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin
import uuid


# 2.4.7 SECURITY_INFORMATION
OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
SACL_SECURITY_INFORMATION = 0x00000008
LABEL_SECURITY_INFORMATION = 0x00000010
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
ATTRIBUTE_SECURITY_INFORMATION = 0x00000020
SCOPE_SECURITY_INFORMATION = 0x00000040
BACKUP_SECURITY_INFORMATION = 0x00010000

# https://docs.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum
ACCESS_FLAGS = {
    # Flag constants
    "GENERIC_READ": 0x80000000,
    "GENERIC_WRITE": 0x40000000,
    "GENERIC_EXECUTE": 0x20000000,
    "GENERIC_ALL": 0x10000000,
    "MAXIMUM_ALLOWED": 0x02000000,
    "ACCESS_SYSTEM_SECURITY": 0x01000000,
    "SYNCHRONIZE": 0x00100000,
    # Not in the spec but equivalent to the flags below it
    "FULL_CONTROL": 0x000F01FF,
    "WRITE_OWNER": 0x00080000,
    "WRITE_DACL": 0x00040000,
    "READ_CONTROL": 0x00020000,
    "DELETE": 0x00010000,
    # ACE type specific mask constants
    # Note that while not documented, these also seem valid
    # for ACCESS_ALLOWED_ACE types
    "ADS_RIGHT_DS_CONTROL_ACCESS": 0x00000100,
    "ADS_RIGHT_DS_CREATE_CHILD": 0x00000001,
    "ADS_RIGHT_DS_DELETE_CHILD": 0x00000002,
    "ADS_RIGHT_DS_READ_PROP": 0x00000010,
    "ADS_RIGHT_DS_WRITE_PROP": 0x00000020,
    "ADS_RIGHT_DS_SELF": 0x00000008,
}

# https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addauditaccessobjectace
ACE_FLAGS = {
    # Flag constants
    "CONTAINER_INHERIT_ACE": 0x02,
    "FAILED_ACCESS_ACE_FLAG": 0x80,
    "INHERIT_ONLY_ACE": 0x08,
    "INHERITED_ACE": 0x10,
    "NO_PROPAGATE_INHERIT_ACE": 0x04,
    "OBJECT_INHERIT_ACE": 0x01,
    "SUCCESSFUL_ACCESS_ACE_FLAG": 0x40,
}

# see https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
ACCOUNT_FLAGS = {
    "SCRIPT": 0x0001,
    "ACCOUNTDISABLE": 0x0002,
    "HOMEDIR_REQUIRED": 0x0008,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "PASSWD_CANT_CHANGE": 0x0040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
    "TEMP_DUPLICATE_ACCOUNT": 0x0100,
    "NORMAL_ACCOUNT": 0x0200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "MNS_LOGON_ACCOUNT": 0x20000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "USE_DES_KEY_ONLY": 0x200000,
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000,
    "USE_AES_KEYS": 0x8000000,
}


def create_allow_ace(sid, object_type=None, access_mask=ACCESS_FLAGS["FULL_CONTROL"], inheritance=False):
    nace = ldaptypes.ACE()
    if inheritance:
        nace['AceFlags'] = ldaptypes.ACE.OBJECT_INHERIT_ACE + ldaptypes.ACE.CONTAINER_INHERIT_ACE
    else:
        nace['AceFlags'] = 0x00

    if object_type is None:
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        nace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    else:
        nace["AceType"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
        acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        acedata['ObjectType'] = string_to_bin(object_type)
        acedata['ObjectTypeLen'] = len(string_to_bin(object_type))
        acedata['InheritedObjectTypeLen'] = 0
        acedata['InheritedObjectType'] = b''
        acedata["Flags"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT

    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = access_mask
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)

    nace["Ace"] = acedata
    return nace


def create_empty_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    # BUILTIN\Administrators
    sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    sd["Dacl"] = acl
    return sd


# Universal SIDs
WELL_KNOWN_SIDS = {
    'S-1-0': 'Null Authority',
    'S-1-0-0': 'Nobody',
    'S-1-1': 'World Authority',
    'S-1-1-0': 'Everyone',
    'S-1-2': 'Local Authority',
    'S-1-2-0': 'Local',
    'S-1-2-1': 'Console Logon',
    'S-1-3': 'Creator Authority',
    'S-1-3-0': 'Creator Owner',
    'S-1-3-1': 'Creator Group',
    'S-1-3-2': 'Creator Owner Server',
    'S-1-3-3': 'Creator Group Server',
    'S-1-3-4': 'Owner Rights',
    'S-1-5-80-0': 'All Services',
    'S-1-4': 'Non-unique Authority',
    'S-1-5': 'NT Authority',
    'S-1-5-1': 'Dialup',
    'S-1-5-2': 'Network',
    'S-1-5-3': 'Batch',
    'S-1-5-4': 'Interactive',
    'S-1-5-6': 'Service',
    'S-1-5-7': 'Anonymous',
    'S-1-5-8': 'Proxy',
    'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'Principal Self',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-12': 'Restricted Code',
    'S-1-5-13': 'Terminal Server Users',
    'S-1-5-14': 'Remote Interactive Logon',
    'S-1-5-15': 'This Organization',
    'S-1-5-17': 'This Organization',
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'NT Authority',
    'S-1-5-20': 'NT Authority',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
    'S-1-5-32-547': 'Power Users',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-552': 'Replicators',
    'S-1-5-64-10': 'NTLM Authentication',
    'S-1-5-64-14': 'SChannel Authentication',
    'S-1-5-64-21': 'Digest Authority',
    'S-1-5-80': 'NT Service',
    'S-1-5-83-0': 'NT VIRTUAL MACHINE\\Virtual Machines',
    'S-1-16-0': 'Untrusted Mandatory Level',
    'S-1-16-4096': 'Low Mandatory Level',
    'S-1-16-8192': 'Medium Mandatory Level',
    'S-1-16-8448': 'Medium Plus Mandatory Level',
    'S-1-16-12288': 'High Mandatory Level',
    'S-1-16-16384': 'System Mandatory Level',
    'S-1-16-20480': 'Protected Process Mandatory Level',
    'S-1-16-28672': 'Secure Process Mandatory Level',
    'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
    'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
    'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
    'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
    'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
    'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
    'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
    'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
    'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
    'S-1-5-32-569': 'BUILTIN\\Cryptographic Operators',
    'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
    'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
    'S-1-5-32-575': 'BUILTIN\\RDS Remote Access Servers',
    'S-1-5-32-576': 'BUILTIN\\RDS Endpoint Servers',
    'S-1-5-32-577': 'BUILTIN\\RDS Management Servers',
    'S-1-5-32-578': 'BUILTIN\\Hyper-V Administrators',
    'S-1-5-32-579': 'BUILTIN\\Access Control Assistance Operators',
    'S-1-5-32-580': 'BUILTIN\\Remote Management Users',
}