# pwnAD

**A powerful tool for Active Directory exploitation, focusing on LDAP and Kerberos protocols. Includes a web interface for interactive enumeration and abuse.**

## Features

- **Multiple authentication methods** - NTLM, Kerberos, Pass-the-Hash, certificates (Schannel/PKINIT)
- **LDAP enumeration and exploitation** - Extensive support for LDAP operations
- **Enhanced security support** - LDAP signing and channel binding for both simple and NTLM authentication
- **BloodHound CE export** - Full domain collection with selectable methods, compatible with BloodHound Community Edition
- **ADCS** - Certificate template enumeration, vulnerability scanning (ESC1-ESC8), and certificate request via MS-ICPR
- **Security analysis** - ACL abuse paths, privilege escalation, delegation mapping, misconfiguration detection
- **Web interface** - Full-featured browser UI for interactive AD exploration
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

# Web interface
pwnAD --web --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!'
```

## Available Actions

| Category | Actions |
|----------|---------|
| **LDAP** | `add`, `remove`, `get`, `modify`, `query` |
| **Modules** | `shadow`, `dacl` |
| **Kerberos** | `getTGT`, `getST`, `getNThash` |
| **Export** | `bloodhound` |
| **ADCS** | `adcs_req` |

## Documentation

- [Installation](installation.md) - Detailed installation instructions
- [Authentication](authentication.md) - All supported authentication methods
- [Interactive Mode](interactive-mode.md) - Shell features and special commands
- [Commands](commands/index.md) - Complete command reference
- [Modules](modules/index.md) - Special attack modules
- [Kerberos](kerberos/index.md) - Kerberos ticket operations
- [Web Interface](web-interface.md) - Browser-based UI
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Status

!!! warning "Active Development"
    This tool is currently in active development. Some features may not be fully operational.
    When using certificate authentication, it's recommended to specify a username.
    Please open an issue or submit a pull request if you encounter any problems.
