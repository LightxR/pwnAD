# Commands Overview

pwnAD provides five main LDAP commands for interacting with Active Directory, plus specialized subcommands for ADCS and BloodHound export.

## Available Commands

| Command | Description |
|---------|-------------|
| [add](add.md) | Add objects or permissions to AD |
| [remove](remove.md) | Remove objects or permissions from AD |
| [get](get.md) | Retrieve and enumerate AD objects, request certificates, export to BloodHound |
| [modify](modify.md) | Modify AD objects and attributes |
| [query](query.md) | Execute raw LDAP queries |

## Command Structure

All commands follow the same pattern:

```bash
pwnAD [auth options] <command> <subcommand> [arguments]
```

### Example

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' get users
```

## Getting Help

Each command and subcommand has built-in help:

```bash
# Main help
pwnAD -h

# Command help
pwnAD get -h

# Subcommand help
pwnAD get user -h
```

## Common Options

These options apply to all LDAP commands:

| Option | Description |
|--------|-------------|
| `--dc-ip` | Domain controller IP address |
| `-d, --domain` | Domain FQDN |
| `-u, --user` | Username |
| `-p, --password` | Password |
| `-H, --hashes` | NT hash (format: `[LM:]NT`) |
| `--aes-key` | Kerberos AES key |
| `-k, --kerberos` | Use Kerberos authentication |
| `-pfx` | PFX certificate file |
| `-cert` / `-key` | PEM certificate and key files |
| `--tls` | Use TLS connection |
| `--port` | LDAP port (default: 389) |
| `--debug` | Enable debug output |
| `-i` | Interactive mode |
