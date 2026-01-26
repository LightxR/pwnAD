# remove Command

Remove objects or permissions from Active Directory.

## Usage

```bash
pwnAD [auth options] remove <subcommand> [arguments]
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `user` | Remove a user account |
| `computer` | Remove a computer account |
| `groupMember` | Remove a user/computer from a group |
| `dcsync` | Remove DCSync rights from an object |
| `genericAll` | Remove GenericAll rights from an object |
| `RBCD` | Remove RBCD configuration |

## Subcommand Details

### user

Remove a user account from the domain.

```bash
pwnAD [auth] remove user <username>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' remove user olduser
```

### computer

Remove a computer account from the domain.

```bash
pwnAD [auth] remove computer <computername>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' remove computer YOURPC$
```

### groupMember

Remove a user or computer from a group.

```bash
pwnAD [auth] remove groupMember <group> <member>
```

**Example:**
```bash
# Remove user from Domain Admins
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' remove groupMember "Domain Admins" compromiseduser
```

### dcsync

Remove DCSync replication rights from an account.

```bash
pwnAD [auth] remove dcsync <target>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' remove dcsync attacker
```

### genericAll

Remove GenericAll (Full Control) permissions from an object.

```bash
pwnAD [auth] remove genericAll <target> <trustee>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' remove genericAll victim attacker
```

### RBCD

Remove Resource-Based Constrained Delegation configuration by clearing the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

```bash
pwnAD [auth] remove RBCD <target>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' remove RBCD TARGETPC$
```

## Cleanup Operations

### Post-Engagement Cleanup

After a penetration test, clean up any artifacts:

```bash
# Start interactive session
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!'

# Remove added accounts
pwnAD [domain.local\admin]> remove user testuser
pwnAD [domain.local\admin]> remove computer YOURPC$

# Remove DCSync rights
pwnAD [domain.local\admin]> remove dcsync compromiseduser

# Remove RBCD configuration
pwnAD [domain.local\admin]> remove RBCD TARGETPC$

# Remove group memberships
pwnAD [domain.local\admin]> remove groupMember "Domain Admins" compromiseduser
```

!!! tip "Best Practice"
    Always document and clean up any changes made during testing. Use the `shadow` module with `auto` mode for automatic cleanup of key credentials.
