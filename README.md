# pwnAD

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Status](https://img.shields.io/badge/Status-Active%20Development-yellow.svg)](https://github.com/LightxR/pwnAD)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://lightxr.github.io/pwnAD)

A powerful tool for Active Directory exploitation, focusing on LDAP and Kerberos protocols.

## Installation

```bash
pipx install "git+https://github.com/LightxR/pwnAD"
```

## Quick Start

```bash
# Interactive mode
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Password123!'

# One-shot enumeration
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Password123!' get users

# Kerberos authentication
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Password123!' -k get users

# Certificate authentication
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -pfx admin.pfx get users
```

## Features

- **Multiple authentication methods** - NTLM, Kerberos, Pass-the-Hash, certificates (Schannel/PKINIT)
- **LDAP operations** - `add`, `remove`, `get`, `modify`, `query`
- **Kerberos operations** - `getTGT`, `getST`, `getNThash`
- **Attack modules** - Shadow Credentials
- **Interactive shell** - Tab completion, history, special commands

## Documentation

Full documentation: **[https://lightxr.github.io/pwnAD](https://lightxr.github.io/pwnAD)**

- [Installation](https://lightxr.github.io/pwnAD/installation/)
- [Authentication Methods](https://lightxr.github.io/pwnAD/authentication/)
- [Interactive Mode](https://lightxr.github.io/pwnAD/interactive-mode/)
- [Commands Reference](https://lightxr.github.io/pwnAD/commands/)
- [Kerberos Actions](https://lightxr.github.io/pwnAD/kerberos/)
- [Troubleshooting](https://lightxr.github.io/pwnAD/troubleshooting/)

## Credits

Built on inspiration from:

- [Certipy](https://github.com/ly4k/Certipy) by [@ly4k_](https://twitter.com/ly4k_)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD) by [CravateRouge](https://cravaterouge.bsky.social)
- [PyWhisker](https://github.com/ShutdownRepo/pywhisker) by [@podalirius_](https://twitter.com/podalirius_) and [@_nwodtuhs](https://twitter.com/_nwodtuhs)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) by [@_dirkjan](https://twitter.com/_dirkjan)
- [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) by [AlmondOffsec](https://offsec.almond.consulting)
- [Impacket](https://github.com/fortra/impacket) by [Fortra](https://github.com/fortra) and [contributors](https://github.com/fortra/impacket/graphs/contributors)

## License

MIT License - See [LICENSE](LICENSE) for details.
