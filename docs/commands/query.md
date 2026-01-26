# query Command

Execute raw LDAP queries against Active Directory. This command provides direct access to LDAP search functionality for custom enumeration.

## Usage

```bash
pwnAD [auth options] query <search_filter> <attributes>
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `search_filter` | LDAP filter expression (RFC 4515) |
| `attributes` | Comma-separated list of attributes to return, or `*` for all |

## LDAP Filter Syntax

LDAP filters follow RFC 4515. Common operators:

| Operator | Meaning | Example |
|----------|---------|---------|
| `=` | Equal | `(sAMAccountName=admin)` |
| `>=` | Greater or equal | `(badPwdCount>=5)` |
| `<=` | Less or equal | `(logonCount<=10)` |
| `=*` | Presence (has value) | `(description=*)` |
| `*` | Wildcard | `(sAMAccountName=*admin*)` |
| `&` | AND | `(&(objectClass=user)(adminCount=1))` |
| `|` | OR | `(|(sAMAccountName=admin)(sAMAccountName=administrator))` |
| `!` | NOT | `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` |

## Examples

### Basic Queries

```bash
# Find specific user
pwnAD [auth] query "(sAMAccountName=administrator)" "distinguishedName,memberOf"

# Find all users
pwnAD [auth] query "(objectClass=user)" "sAMAccountName,description"

# Find all computers
pwnAD [auth] query "(objectClass=computer)" "dNSHostName,operatingSystem"
```

### Attribute Queries

```bash
# Get all attributes for a user
pwnAD [auth] query "(sAMAccountName=admin)" "*"

# Get specific attributes
pwnAD [auth] query "(sAMAccountName=admin)" "sAMAccountName,userAccountControl,memberOf,lastLogon"

# Find objects with descriptions
pwnAD [auth] query "(description=*)" "sAMAccountName,description"
```

### UserAccountControl Queries

UserAccountControl is a bitmask. Use the LDAP matching rule `1.2.840.113556.1.4.803` (bitwise AND):

```bash
# Disabled accounts (bit 0x2)
pwnAD [auth] query "(userAccountControl:1.2.840.113556.1.4.803:=2)" "sAMAccountName"

# Accounts with DONT_REQ_PREAUTH (bit 0x400000)
pwnAD [auth] query "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" "sAMAccountName"

# Enabled accounts only (NOT disabled)
pwnAD [auth] query "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" "sAMAccountName"
```

### Complex Queries

```bash
# Admin users with SPNs (Kerberoastable admins)
pwnAD [auth] query "(&(adminCount=1)(servicePrincipalName=*))" "sAMAccountName,servicePrincipalName"

# Users with passwords in description
pwnAD [auth] query "(&(objectClass=user)(description=*pass*))" "sAMAccountName,description"

# Computers with unconstrained delegation
pwnAD [auth] query "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" "sAMAccountName"

# Find GPOs
pwnAD [auth] query "(objectClass=groupPolicyContainer)" "displayName,gPCFileSysPath"
```

### Time-Based Queries

LDAP timestamps are in Windows FILETIME format:

```bash
# Users who haven't logged in recently (requires timestamp calculation)
pwnAD [auth] query "(&(objectClass=user)(lastLogon<=132500000000000000))" "sAMAccountName,lastLogon"

# Recently created objects
pwnAD [auth] query "(whenCreated>=20240101000000.0Z)" "sAMAccountName,whenCreated"
```

## Interactive Mode

```bash
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!'

# Custom enumeration
pwnAD [domain.local\admin]> query "(objectClass=user)" "sAMAccountName,description"
pwnAD [domain.local\admin]> query "(&(objectClass=group)(cn=*admin*))" "cn,member"
```

## Common LDAP Filters Reference

### User Filters

| Purpose | Filter |
|---------|--------|
| All users | `(objectClass=user)` |
| Enabled users | `(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))` |
| Users with SPN | `(&(objectClass=user)(servicePrincipalName=*))` |
| Users with adminCount | `(&(objectClass=user)(adminCount=1))` |

### Computer Filters

| Purpose | Filter |
|---------|--------|
| All computers | `(objectClass=computer)` |
| Domain controllers | `(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))` |
| Servers | `(&(objectClass=computer)(operatingSystem=*Server*))` |

### Group Filters

| Purpose | Filter |
|---------|--------|
| All groups | `(objectClass=group)` |
| Security groups | `(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))` |
| Groups with specific member | `(&(objectClass=group)(member=CN=User,CN=Users,DC=domain,DC=local))` |

## Tips

- Use `*` for attributes to get all available attributes (useful for discovery)
- Escape special characters: `*`, `(`, `)`, `\`, NUL with `\xx` hex notation
- Test complex filters incrementally
- Use debug mode (`--debug`) to see the actual LDAP query being sent
