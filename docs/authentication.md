# Authentication Methods

pwnAD supports multiple authentication methods for both LDAP and Kerberos operations.

## LDAP Operations

Authentication methods available for `get`, `add`, `remove`, `modify`, and `query` commands.

| Method | Flags | Description |
|--------|-------|-------------|
| NTLM (password) | `-p` | Falls back to simple auth when failing |
| NTLM (hash) | `-H` | Pass-the-Hash authentication |
| Kerberos (password) | `-p -k` | Kerberos with password |
| Kerberos (hash) | `-H -k` | Kerberos with NT hash |
| Kerberos (AES key) | `--aes-key` | Kerberos with AES key |
| Kerberos (ccache) | `-k` | Uses KRB5CCNAME environment variable |
| Schannel (PFX) | `-pfx` | Certificate in PFX/P12 format |
| Schannel (PEM) | `-cert -key` | Certificate and key in PEM format |

## Kerberos Operations

Authentication methods available for `getTGT`, `getST`, and `getNThash` commands.

| Method | Flags | Description |
|--------|-------|-------------|
| Password | `-p` | Standard password authentication |
| NT Hash | `-H` | Pass-the-Hash |
| AES Key | `--aes-key` | AES128 or AES256 key |
| ccache | `-k` | For getST only |
| PKINIT (PFX) | `-pfx` | Certificate authentication |
| PKINIT (PEM) | `-cert -key` | Certificate and key files |

## Authentication Examples

### Password Authentication

```bash
# Basic password authentication
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!' get users

# With TLS
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!' --tls get users
```

### Pass-the-Hash

```bash
# Using NT hash only
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' get users

# Using NT hash (short form)
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -H ':31d6cfe0d16ae931b73c59d7e0c089c0' get users
```

### Kerberos Authentication

```bash
# Kerberos with password
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!' -k get users

# Kerberos with NT hash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -H ':31d6cfe0d16ae931b73c59d7e0c089c0' -k get users

# Kerberos with AES key
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator --aes-key '4a3e8...' get users

# Kerberos with existing ccache
export KRB5CCNAME=/tmp/administrator.ccache
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -k get users
```

### Certificate Authentication

```bash
# Using PFX/P12 file
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx admin.pfx get users

# PFX with password
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx admin.pfx -pfx-pass 'PfxPassword!' get users

# Using separate cert and key files
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -cert admin.crt -key admin.key get users
```

## Connection Options

### Target Specification

| Flag | Description |
|------|-------------|
| `--dc-ip` | IP address of the domain controller |
| `--kdcHost` | FQDN of the KDC (for Kerberos) |
| `-d, --domain` | FQDN of the domain |
| `-u, --user` | Username to authenticate with |
| `--port` | LDAP port (default: 389, or 636 with TLS) |
| `--tls` | Use TLS connection |

### Debug Mode

Enable debug output to troubleshoot authentication issues:

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!' --debug get users
```

## Authentication Flow

### LDAP Authentication Flow

1. If `-k` (Kerberos) flag is set:
    - Try Kerberos authentication (SASL GSSAPI)
2. If certificate is provided (`-pfx` or `-cert -key`):
    - Use Schannel (TLS client certificate)
3. If hash is provided (`-H`):
    - Use NTLM authentication
4. If password is provided (`-p`):
    - Try NTLM authentication
    - Fall back to simple bind if NTLM fails

### Kerberos (PKINIT) Flow

For `getTGT`, `getST`, `getNThash` with certificates:

1. Load certificate and private key
2. Perform PKINIT AS-REQ with certificate
3. Receive TGT encrypted with session key
4. For `getNThash`: Use PAC_CREDENTIAL_INFO to retrieve NT hash
