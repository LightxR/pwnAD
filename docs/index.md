# pwnAD

**A powerful tool for Active Directory exploitation, focusing on LDAP and Kerberos protocols.**

## Features

- **Multiple authentication methods** - Support for NTLM, Kerberos, and certificate-based authentication
- **LDAP enumeration and exploitation** - Extensive support for LDAP operations
- **Enhanced security support** - LDAP signing and channel binding for both simple and NTLM authentication
- **Certificate-based attacks** - Kerberos actions supporting certificate authentication via PKINIT
- **Interactive shell** - User-friendly command-line interface with tab completion

## Quick Start

### Installation

```bash
pipx install "git+https://github.com/LightxR/pwnAD"
```

### Basic Usage

```bash
# Interactive mode with password authentication
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!'

# One-shot command: enumerate users
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!' get users

# Using Kerberos authentication
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!' -k get users

# Using certificate authentication
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx admin.pfx get users
```

## Available Actions

| Category | Actions |
|----------|---------|
| **LDAP** | `add`, `remove`, `get`, `modify`, `query` |
| **Modules** | `shadow` |
| **Kerberos** | `getTGT`, `getST`, `getNThash` |

## Documentation

- [Installation](installation.md) - Detailed installation instructions
- [Authentication](authentication.md) - All supported authentication methods
- [Interactive Mode](interactive-mode.md) - Shell features and special commands
- [Commands](commands/index.md) - Complete command reference
- [Modules](modules/index.md) - Special attack modules
- [Kerberos](kerberos/index.md) - Kerberos ticket operations
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Status

!!! warning "Active Development"
    This tool is currently in active development. Some features may not be fully operational.
    When using certificate authentication, it's recommended to specify a username.
    Please open an issue or submit a pull request if you encounter any problems.
