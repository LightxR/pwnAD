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

- **ADCS analysis** (`get adcs`) - Full ADCS vulnerability scan detecting ESC1-ESC15, including CA-level checks (ESC6/7/8/11), PKI container ACLs (ESC5), and certificate mapping settings (ESC10).
- **ADCS certificate request** (`get adcs_req`) - Request certificates via MS-ICPR RPC, with custom SAN (UPN, DNS, SID) for ESC1/ESC6 exploitation.
- **ESC4 exploitation** (`get esc4`) - Automated chain: modify writable template to enable SAN, request cert, restore original attributes.
- **ESC7 exploitation** (`get esc7`) - Automated chain: enable EDITF_ATTRIBUTESUBJECTALTNAME2 via ManageCA, request cert, restore.
- **ESC9/ESC10 exploitation** (`get esc9`) - Automated chain: swap UPN on target account, request cert, restore UPN.
- **BloodHound CE export** (`get bloodhound`) - Export domain data in BloodHound Community Edition format using [BloodHound.py](https://github.com/dirkjanm/BloodHound.py).

All are accessible from both CLI and [web interface](../web-interface.md).
