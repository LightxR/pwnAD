from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin, bin_to_string
from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
import uuid


# GUIDs for Extended Rights (used in DACL operations)
EXTENDED_RIGHTS_GUIDS = {
    "DS-Replication-Get-Changes": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "DS-Replication-Get-Changes-All": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "DS-Replication-Get-Changes-In-Filtered-Set": "89e95b76-444d-4c62-991a-0facbeda640c",
    "User-Force-Change-Password": "00299570-246d-11d0-a768-00aa006e0529",
    "Self-Membership": "bf9679c0-0de6-11d0-a285-00aa003049e2",
    "Validated-SPN": "f3a64788-5306-11d1-a9c5-0000f80367c1",
    "Validated-DNS-Host-Name": "72e39547-7b18-11d1-adef-00c04fd8d5cd",
    "Validated-MS-DS-Behavior-Version": "d31a8757-2447-4545-8081-3bb610cacbf2",
    "Validated-MS-DS-Additional-DNS-Host-Name": "80863791-dbe9-4eb8-837e-7f0ab55d9ac7",
}

# GUIDs for Properties (used in DACL operations)
PROPERTY_GUIDS = {
    "ms-Mcs-AdmPwd": "f3531ec6-6498-4a88-8ee3-e5af2e61469f",  # LAPS legacy
    "ms-LAPS-Password": "f3531ec6-6498-4a88-8ee3-e5af2e61469f",  # LAPS
    "ms-LAPS-EncryptedPassword": "f3531ec6-6498-4a88-8ee3-e5af2e61469f",
    "msDS-ManagedPassword": "e362ed86-b728-0842-b27d-2dea7a9df218",  # gMSA
    "Member": "bf9679c0-0de6-11d0-a285-00aa003049e2",
    "ms-DS-Key-Credential-Link": "5b47d60f-6090-40b2-9f37-2a4de88f3063",
    "servicePrincipalName": "f3a64788-5306-11d1-a9c5-0000f80367c1",
    "User-Account-Control": "bf967a68-0de6-11d0-a285-00aa003049e2",
    "User-Logon": "5f202010-79a5-11d0-9020-00c04fc2d4cf",
    "User-Password": "bf967a6e-0de6-11d0-a285-00aa003049e2",
}

# Mapping of friendly right names to their configuration
DACL_RIGHTS = {
    "FullControl": {
        "access_mask": 0x000F01FF,
        "object_type": None,
        "description": "Full control over object"
    },
    "GenericAll": {
        "access_mask": 0x10000000,
        "object_type": None,
        "description": "Generic all rights"
    },
    "GenericWrite": {
        "access_mask": 0x40000000,
        "object_type": None,
        "description": "Generic write rights"
    },
    "WriteDacl": {
        "access_mask": 0x00040000,
        "object_type": None,
        "description": "Modify DACL"
    },
    "WriteOwner": {
        "access_mask": 0x00080000,
        "object_type": None,
        "description": "Modify owner"
    },
    "AllExtendedRights": {
        "access_mask": 0x00000100,
        "object_type": None,
        "description": "All extended rights"
    },
    "DCSync": {
        "access_mask": 0x00000100,
        "object_type": [
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
            "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
        ],
        "description": "DCSync replication rights"
    },
    "WriteMembers": {
        "access_mask": 0x00000020,  # ADS_RIGHT_DS_WRITE_PROP
        "object_type": "bf9679c0-0de6-11d0-a285-00aa003049e2",  # Member property
        "description": "Write to group members"
    },
    "AddMember": {
        "access_mask": 0x00000008,  # ADS_RIGHT_DS_SELF
        "object_type": "bf9679c0-0de6-11d0-a285-00aa003049e2",  # Self-Membership
        "description": "Add self to group"
    },
    "ResetPassword": {
        "access_mask": 0x00000100,  # ADS_RIGHT_DS_CONTROL_ACCESS
        "object_type": "00299570-246d-11d0-a768-00aa006e0529",  # User-Force-Change-Password
        "description": "Reset password"
    },
    "Self": {
        "access_mask": 0x00000008,
        "object_type": None,
        "description": "Self operations"
    },
    "ReadGMSAPassword": {
        "access_mask": 0x00000010,  # ADS_RIGHT_DS_READ_PROP
        "object_type": "e362ed86-b728-0842-b27d-2dea7a9df218",  # msDS-ManagedPassword
        "description": "Read gMSA password"
    },
    "ReadLAPSPassword": {
        "access_mask": 0x00000010,  # ADS_RIGHT_DS_READ_PROP
        "object_type": "f3531ec6-6498-4a88-8ee3-e5af2e61469f",  # ms-Mcs-AdmPwd / LAPS
        "description": "Read LAPS password"
    },
    "WriteKeyCredentialLink": {
        "access_mask": 0x00000020,  # ADS_RIGHT_DS_WRITE_PROP
        "object_type": "5b47d60f-6090-40b2-9f37-2a4de88f3063",  # ms-DS-Key-Credential-Link
        "description": "Write key credential (Shadow Credentials)"
    },
    "WriteSPN": {
        "access_mask": 0x00000020,  # ADS_RIGHT_DS_WRITE_PROP
        "object_type": "f3a64788-5306-11d1-a9c5-0000f80367c1",  # servicePrincipalName
        "description": "Write SPN (for Kerberoasting)"
    },
}

# ACE Type constants
ACE_TYPE_ACCESS_ALLOWED = 0x00
ACE_TYPE_ACCESS_DENIED = 0x01
ACE_TYPE_ACCESS_ALLOWED_OBJECT = 0x05
ACE_TYPE_ACCESS_DENIED_OBJECT = 0x06

# ACE Type names mapping
ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED_ACE",
    0x01: "ACCESS_DENIED_ACE",
    0x02: "SYSTEM_AUDIT_ACE",
    0x03: "SYSTEM_ALARM_ACE",
    0x04: "ACCESS_ALLOWED_COMPOUND_ACE",
    0x05: "ACCESS_ALLOWED_OBJECT_ACE",
    0x06: "ACCESS_DENIED_OBJECT_ACE",
    0x07: "SYSTEM_AUDIT_OBJECT_ACE",
    0x08: "SYSTEM_ALARM_OBJECT_ACE",
    0x09: "ACCESS_ALLOWED_CALLBACK_ACE",
    0x0A: "ACCESS_DENIED_CALLBACK_ACE",
    0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE",
    0x0C: "ACCESS_DENIED_CALLBACK_OBJECT_ACE",
    0x0D: "SYSTEM_AUDIT_CALLBACK_ACE",
    0x0E: "SYSTEM_ALARM_CALLBACK_ACE",
    0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE",
    0x10: "SYSTEM_ALARM_CALLBACK_OBJECT_ACE",
    0x11: "SYSTEM_MANDATORY_LABEL_ACE",
    0x12: "SYSTEM_RESOURCE_ATTRIBUTE_ACE",
    0x13: "SYSTEM_SCOPED_POLICY_ID_ACE",
}


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


def create_ace(sid, access_mask, object_type=None, ace_type="allowed", inheritance=False):
    """
    Create an ACE (Access Control Entry) with flexible parameters.

    Args:
        sid: Security Identifier string (e.g., 'S-1-5-21-...')
        access_mask: Access mask value (int)
        object_type: Optional GUID string for object-specific ACE
        ace_type: 'allowed' or 'denied'
        inheritance: Whether to set inheritance flags

    Returns:
        ldaptypes.ACE object
    """
    nace = ldaptypes.ACE()

    if inheritance:
        nace['AceFlags'] = ldaptypes.ACE.OBJECT_INHERIT_ACE + ldaptypes.ACE.CONTAINER_INHERIT_ACE
    else:
        nace['AceFlags'] = 0x00

    if object_type is None:
        # Simple ACE (non-object)
        if ace_type == "denied":
            nace["AceType"] = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_DENIED_ACE()
        else:
            nace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    else:
        # Object ACE with GUID
        if ace_type == "denied":
            nace["AceType"] = ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_DENIED_OBJECT_ACE()
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


def create_deny_ace(sid, access_mask, object_type=None, inheritance=False):
    """
    Create an ACCESS_DENIED ACE.

    Args:
        sid: Security Identifier string
        access_mask: Access mask value
        object_type: Optional GUID string for object-specific ACE
        inheritance: Whether to set inheritance flags

    Returns:
        ldaptypes.ACE object
    """
    return create_ace(sid, access_mask, object_type, ace_type="denied", inheritance=inheritance)


def parse_ace(ace):
    """
    Parse an ACE into a readable dictionary.

    Args:
        ace: ldaptypes.ACE object

    Returns:
        dict with ACE information
    """
    ace_info = {
        "type": ACE_TYPE_NAMES.get(ace["AceType"], f"UNKNOWN (0x{ace['AceType']:02x})"),
        "type_raw": ace["AceType"],
        "ace_flags": ace["AceFlags"],
        "sid": ace["Ace"]["Sid"].formatCanonical(),
        "access_mask": ace["Ace"]["Mask"]["Mask"],
        "access_mask_hex": f"0x{ace['Ace']['Mask']['Mask']:08x}",
        "object_type": None,
        "inherited_object_type": None,
        "object_ace_flags": [],
    }

    # Parse access rights - more intelligent interpretation
    ace_info["rights"] = _interpret_access_mask(ace["Ace"]["Mask"]["Mask"])

    # Check for object ACE and extract flags
    if ace["AceType"] in [ACE_TYPE_ACCESS_ALLOWED_OBJECT, ACE_TYPE_ACCESS_DENIED_OBJECT, 0x07, 0x08]:
        try:
            flags = ace["Ace"]["Flags"]

            # Parse object ACE flags
            if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                ace_info["object_ace_flags"].append("ACE_OBJECT_TYPE_PRESENT")
                object_type_bytes = ace["Ace"]["ObjectType"]
                if object_type_bytes:
                    ace_info["object_type"] = guid_to_string(object_type_bytes)

            if flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                ace_info["object_ace_flags"].append("ACE_INHERITED_OBJECT_TYPE_PRESENT")
                inherited_bytes = ace["Ace"]["InheritedObjectType"]
                if inherited_bytes:
                    ace_info["inherited_object_type"] = guid_to_string(inherited_bytes)
        except (KeyError, TypeError):
            pass

    # Resolve known GUIDs for object_type
    if ace_info["object_type"]:
        ace_info["object_type_name"] = _resolve_guid_name(ace_info["object_type"])

    # Resolve known GUIDs for inherited_object_type
    if ace_info["inherited_object_type"]:
        ace_info["inherited_object_type_name"] = _resolve_guid_name(ace_info["inherited_object_type"])

    return ace_info


def _interpret_access_mask(mask):
    """
    Interpret an access mask into a list of meaningful rights.
    Uses a hierarchical approach to avoid listing redundant flags.

    Args:
        mask: Access mask value (int)

    Returns:
        list: List of right names
    """
    rights = []

    # Check for specific composite rights first
    if mask == ACCESS_FLAGS["FULL_CONTROL"]:
        return ["FullControl"]

    # Check for high-level generic rights
    if mask & ACCESS_FLAGS["GENERIC_ALL"]:
        rights.append("GenericAll")
    if mask & ACCESS_FLAGS["GENERIC_WRITE"]:
        rights.append("GenericWrite")
    if mask & ACCESS_FLAGS["GENERIC_READ"]:
        rights.append("GenericRead")
    if mask & ACCESS_FLAGS["GENERIC_EXECUTE"]:
        rights.append("GenericExecute")

    # If we have generic rights, don't list specific ones
    if rights:
        return rights

    # Check standard rights
    if mask & ACCESS_FLAGS["WRITE_OWNER"]:
        rights.append("WriteOwner")
    if mask & ACCESS_FLAGS["WRITE_DACL"]:
        rights.append("WriteDacl")
    if mask & ACCESS_FLAGS["READ_CONTROL"]:
        rights.append("ReadControl")
    if mask & ACCESS_FLAGS["DELETE"]:
        rights.append("Delete")

    # Check DS-specific rights
    if mask & ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]:
        rights.append("ControlAccess")
    if mask & ACCESS_FLAGS["ADS_RIGHT_DS_CREATE_CHILD"]:
        rights.append("CreateChild")
    if mask & ACCESS_FLAGS["ADS_RIGHT_DS_DELETE_CHILD"]:
        rights.append("DeleteChild")
    if mask & ACCESS_FLAGS["ADS_RIGHT_DS_READ_PROP"]:
        rights.append("ReadProperty")
    if mask & ACCESS_FLAGS["ADS_RIGHT_DS_WRITE_PROP"]:
        rights.append("WriteProperty")
    if mask & ACCESS_FLAGS["ADS_RIGHT_DS_SELF"]:
        rights.append("Self")

    return rights if rights else ["Unknown"]


def _resolve_guid_name(guid_str):
    """
    Resolve a GUID to its friendly name using Impacket's GUID databases.

    Args:
        guid_str: GUID string

    Returns:
        str: Friendly name or None if not found
    """
    guid_lower = guid_str.lower()

    # Check Impacket's EXTENDED_RIGHTS first (contains property sets and extended rights)
    if guid_lower in EXTENDED_RIGHTS:
        return EXTENDED_RIGHTS[guid_lower]

    # Check Impacket's SCHEMA_OBJECTS (contains object classes and attributes)
    if guid_lower in SCHEMA_OBJECTS:
        return SCHEMA_OBJECTS[guid_lower]

    # If not found in Impacket's databases, return None
    return None


def ace_matches(ace, sid=None, access_mask=None, object_type=None, ace_type=None):
    """
    Check if an ACE matches the given criteria.

    Args:
        ace: ldaptypes.ACE object
        sid: Optional SID string to match
        access_mask: Optional access mask to match (exact or contains)
        object_type: Optional object type GUID to match
        ace_type: Optional 'allowed' or 'denied' to match

    Returns:
        bool: True if ACE matches all specified criteria
    """
    # Check SID
    if sid is not None:
        ace_sid = ace["Ace"]["Sid"].formatCanonical()
        if ace_sid.upper() != sid.upper():
            return False

    # Check ACE type
    if ace_type is not None:
        if ace_type == "allowed":
            if ace["AceType"] not in [ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_OBJECT]:
                return False
        elif ace_type == "denied":
            if ace["AceType"] not in [ACE_TYPE_ACCESS_DENIED, ACE_TYPE_ACCESS_DENIED_OBJECT]:
                return False

    # Check access mask (contains)
    if access_mask is not None:
        ace_mask = ace["Ace"]["Mask"]["Mask"]
        if not (ace_mask & access_mask):
            return False

    # Check object type
    if object_type is not None:
        if ace["AceType"] in [ACE_TYPE_ACCESS_ALLOWED_OBJECT, ACE_TYPE_ACCESS_DENIED_OBJECT]:
            try:
                flags = ace["Ace"]["Flags"]
                if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                    ace_object_type = guid_to_string(ace["Ace"]["ObjectType"])
                    if ace_object_type.lower() != object_type.lower():
                        return False
                else:
                    return False  # No object type in ACE but we need one
            except (KeyError, TypeError):
                return False
        else:
            return False  # Not an object ACE but we need object type

    return True


def guid_to_string(guid_bytes):
    """
    Convert GUID bytes to string representation.

    Args:
        guid_bytes: bytes representing the GUID

    Returns:
        str: GUID string (e.g., 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
    """
    if isinstance(guid_bytes, str):
        return guid_bytes
    try:
        return bin_to_string(guid_bytes)
    except Exception:
        return str(uuid.UUID(bytes_le=guid_bytes))


def resolve_sid_to_name(conn, sid):
    """
    Resolve a SID to a sAMAccountName via LDAP.

    Args:
        conn: LDAP connection object
        sid: SID string to resolve

    Returns:
        str: sAMAccountName or the original SID if not found
    """
    # Check well-known SIDs first
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]

    # Try LDAP lookup
    try:
        result = conn.get_samaccountname_from_sid(sid)
        if result:
            return result
    except Exception:
        pass

    return sid


def get_rights_from_mask(access_mask, object_type=None):
    """
    Determine which known rights are represented by an access mask.

    Args:
        access_mask: Access mask value
        object_type: Optional object type GUID

    Returns:
        list: List of matching right names
    """
    rights = []
    for right_name, right_config in DACL_RIGHTS.items():
        mask = right_config["access_mask"]
        obj_type = right_config["object_type"]

        if access_mask & mask:
            if obj_type is None and object_type is None:
                rights.append(right_name)
            elif isinstance(obj_type, list):
                if object_type and object_type.lower() in [g.lower() for g in obj_type]:
                    rights.append(right_name)
            elif obj_type and object_type:
                if obj_type.lower() == object_type.lower():
                    rights.append(right_name)

    return rights