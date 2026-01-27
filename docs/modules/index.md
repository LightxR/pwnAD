# Modules Overview

pwnAD includes special attack modules that go beyond basic LDAP operations. These modules implement complex attack chains.

## Available Modules

| Module | Description |
|--------|-------------|
| [dacl](dacl.md) | DACL manipulation (read, write, remove, backup, restore ACEs) |
| [shadow](shadow.md) | Shadow Credentials attack for account takeover |

## What are Modules?

Modules are specialized attack implementations that combine multiple operations:

- **Multi-step attacks** - Automated attack chains
- **Cleanup capabilities** - Restore original state after exploitation
- **Certificate operations** - Generate and use X.509 certificates
- **PKINIT integration** - Leverage Kerberos certificate authentication

## Future Modules

Additional modules are planned for future releases. Potential additions include:

- ADCS (Active Directory Certificate Services) attacks
- Trust relationship exploitation
