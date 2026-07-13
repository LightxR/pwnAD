# Installation

## Requirements

- Python 3.8 or higher
- pip or pipx

## Recommended: Using pipx

[pipx](https://pypa.github.io/pipx/) installs pwnAD in an isolated environment, avoiding dependency conflicts.

```bash
# Install pipx if not already installed
pip install pipx
pipx ensurepath

# Install pwnAD
pipx install "git+https://github.com/LightxR/pwnAD"
```

## Alternative: Using pip

```bash
pip install "git+https://github.com/LightxR/pwnAD"
```

## Development Installation

For contributors or those who want the latest development version:

```bash
git clone https://github.com/LightxR/pwnAD.git
cd pwnAD
pip install -e .
```

## Dependencies

pwnAD relies on the following key packages:

| Package | Purpose |
|---------|---------|
| `impacket` | Windows network protocols (SMB, Kerberos, etc.) |
| `ldap3` | LDAP operations with signing and channel binding |
| `cryptography>=39.0` | Cryptographic operations |
| `asn1crypto` | ASN.1 parsing |
| `pyasn1==0.4.8` | ASN.1 structures |
| `dsinternals` | Active Directory internal structures |
| `bloodhound-ce` | BloodHound CE data collection ([BloodHound.py](https://github.com/dirkjanm/BloodHound.py)) |
| `flask` | Web interface backend |
| `waitress` | Production WSGI server for the web interface |

## Verifying Installation

After installation, verify pwnAD is working:

```bash
pwnAD -h
```

You should see the help message with available options and actions.

## Kerberos Configuration

For Kerberos authentication, ensure your system has a valid `/etc/krb5.conf` or rely on the `--kdcHost` flag to specify the KDC.

### Example krb5.conf

```ini
[libdefaults]
    default_realm = DOMAIN.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    DOMAIN.LOCAL = {
        kdc = dc01.domain.local
        admin_server = dc01.domain.local
    }

[domain_realm]
    .domain.local = DOMAIN.LOCAL
    domain.local = DOMAIN.LOCAL
```

## Troubleshooting Installation

### SSL/TLS Errors

If you encounter SSL errors, ensure your `cryptography` package is up to date:

```bash
pip install --upgrade cryptography
```

### Impacket Conflicts

If you have multiple Impacket versions installed, consider using pipx to isolate pwnAD:

```bash
pipx install "git+https://github.com/LightxR/pwnAD" --force
```

### Permission Errors

On Linux, you may need to install as user:

```bash
pip install --user "git+https://github.com/LightxR/pwnAD"
```

Or use a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
pip install "git+https://github.com/LightxR/pwnAD"
```
