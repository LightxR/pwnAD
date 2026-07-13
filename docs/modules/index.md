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

## Related Features

These features are available as `get` subcommands rather than standalone modules:

- **ADCS certificate request** (`get adcs_req`) - Request certificates from AD Certificate Services via MS-ICPR RPC, with support for custom SAN (UPN, DNS, SID) for ESC1 exploitation.
- **BloodHound CE export** (`get bloodhound`) - Export domain data in BloodHound Community Edition format using [BloodHound.py](https://github.com/dirkjanm/BloodHound.py). Supports all collection methods (group, localadmin, session, trusts, objectprops, acl, dcom, rdp, psremote, container, loggedon).

Both are also accessible from the [web interface](../web-interface.md).
