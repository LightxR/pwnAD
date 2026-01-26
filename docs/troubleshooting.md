# Troubleshooting

Common issues and solutions when using pwnAD.

## Connection Issues

### "Connection refused" or "Connection timed out"

**Symptoms:**
- Cannot connect to the domain controller
- Connection errors immediately after running command

**Solutions:**

1. Verify the DC IP is correct:
   ```bash
   ping <dc-ip>
   ```

2. Check if LDAP port is open:
   ```bash
   nc -zv <dc-ip> 389
   nc -zv <dc-ip> 636  # LDAPS
   ```

3. Ensure no firewall is blocking the connection

4. Try specifying the port explicitly:
   ```bash
   pwnAD --dc-ip <ip> --port 389 ...
   ```

### "Connection reset by peer"

**Symptoms:**
- Connection works initially but drops
- Error appears after idle period

**Solutions:**

In interactive mode, use `rebind`:
```bash
pwnAD [domain.local\admin]> rebind
[*] Successfully performed a connection rebind.
```

### "Server unwilling to perform"

**Symptoms:**
- Operations fail with "unwillingToPerform"
- Common with password changes

**Solutions:**

Most likely you need TLS. Either:

1. Connect with TLS from the start:
   ```bash
   pwnAD --dc-ip <ip> -d domain.local -u admin -p 'Pass!' --tls ...
   ```

2. Upgrade with StartTLS in interactive mode:
   ```bash
   pwnAD [domain.local\admin]> start_tls
   ```

## Authentication Issues

### "Invalid credentials"

**Symptoms:**
- Authentication fails despite correct credentials
- Works with other tools but not pwnAD

**Solutions:**

1. Check username format (should be just username, not `domain\user`):
   ```bash
   # Correct
   pwnAD --dc-ip <ip> -d domain.local -u administrator -p 'Pass!'

   # Incorrect
   pwnAD --dc-ip <ip> -d domain.local -u domain.local\\administrator -p 'Pass!'
   ```

2. Escape special characters in password:
   ```bash
   pwnAD --dc-ip <ip> -d domain.local -u admin -p 'P@$$w0rd!'
   ```

3. Try using hash instead:
   ```bash
   pwnAD --dc-ip <ip> -d domain.local -u admin -H ':nthash'
   ```

### "KDC_ERR_PREAUTH_FAILED"

**Symptoms:**
- Kerberos operations fail
- "Pre-authentication failed" error

**Solutions:**

1. Verify password/hash is correct
2. Check for clock skew:
   ```bash
   sudo ntpdate <dc-ip>
   ```
3. Try NTLM instead of Kerberos (remove `-k` flag)

### Certificate Authentication Fails

**Symptoms:**
- Schannel or PKINIT authentication fails
- Certificate errors

**Solutions:**

1. Verify certificate is for the correct user:
   ```bash
   openssl x509 -in cert.crt -text -noout | grep Subject
   ```

2. Check certificate is not expired:
   ```bash
   openssl x509 -in cert.crt -dates -noout
   ```

3. Ensure private key matches certificate:
   ```bash
   openssl x509 -noout -modulus -in cert.crt | md5sum
   openssl rsa -noout -modulus -in cert.key | md5sum
   # Should match
   ```

4. Specify username explicitly:
   ```bash
   pwnAD --dc-ip <ip> -d domain.local -u administrator -pfx admin.pfx ...
   ```

## LDAP Operation Errors

### "Insufficient access rights"

**Symptoms:**
- Operation denied
- "insufficientAccessRights" error

**Solutions:**

1. Verify you have the required permissions
2. Check group memberships:
   ```bash
   pwnAD get membership <your_user>
   ```
3. Try with a higher-privileged account

### "Object does not exist"

**Symptoms:**
- Target not found
- "noSuchObject" error

**Solutions:**

1. Verify target name spelling
2. Check if using sAMAccountName or DN:
   ```bash
   # Try with full DN
   pwnAD query "(sAMAccountName=targetuser)" "distinguishedName"
   ```

### "Constraint violation"

**Symptoms:**
- Modification fails
- "constraintViolation" error

**Solutions:**

Common with password changes:

1. Password doesn't meet complexity requirements
2. Password history conflict
3. Minimum password age not met

## Kerberos Issues

### "KRB_AP_ERR_SKEW"

**Symptoms:**
- All Kerberos operations fail
- Time-related error

**Solution:**

Sync your clock with the DC:
```bash
sudo ntpdate <dc-ip>
# Or
sudo timedatectl set-ntp true
```

### "KDC_ERR_S_PRINCIPAL_UNKNOWN"

**Symptoms:**
- getST fails
- Service not found

**Solutions:**

1. Verify SPN format:
   ```bash
   # Correct formats
   cifs/hostname.domain.local
   http/hostname.domain.local
   ldap/hostname.domain.local
   ```

2. Check if SPN exists:
   ```bash
   pwnAD get spn
   ```

### ccache Issues

**Symptoms:**
- `-k` flag doesn't use existing ticket
- "Credentials cache file not found"

**Solutions:**

1. Set KRB5CCNAME correctly:
   ```bash
   export KRB5CCNAME=/full/path/to/ticket.ccache
   ```

2. Verify ccache exists and is readable:
   ```bash
   ls -la $KRB5CCNAME
   klist
   ```

## Shadow Credentials Issues

### "msDS-KeyCredentialLink not found"

**Symptoms:**
- Shadow operations fail
- Attribute error

**Solutions:**

1. Verify domain functional level is 2016+
2. Check if attribute exists on target:
   ```bash
   pwnAD query "(sAMAccountName=target)" "msDS-KeyCredentialLink"
   ```

### PKINIT Fails After Adding Key Credential

**Symptoms:**
- Key added successfully
- Certificate authentication fails

**Solutions:**

1. Ensure ADCS is deployed or Azure AD supports PKINIT
2. Check certificate was generated correctly
3. Try the `shadow auto` command for full automation

## Debug Mode

Enable debug output for detailed information:

```bash
pwnAD --dc-ip <ip> -d domain.local -u admin -p 'Pass!' --debug get users
```

Debug mode shows:

- LDAP queries being sent
- Server responses
- Authentication flow
- Error details

## Getting Help

If you're still stuck:

1. Run with `--debug` and capture the full output
2. Check [GitHub Issues](https://github.com/LightxR/pwnAD/issues)
3. Open a new issue with:
    - pwnAD version
    - Command used (mask credentials!)
    - Full error message
    - Debug output
    - Expected vs actual behavior
