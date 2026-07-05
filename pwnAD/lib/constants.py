"""
Shared protocol and error constants for pwnAD.

This module centralises magic numbers that appear across multiple modules
so they can be referenced by name rather than as bare literals.
"""

# ---------------------------------------------------------------------------
# Default LDAP ports
# ---------------------------------------------------------------------------
LDAP_PORT: int = 389
LDAPS_PORT: int = 636

# ---------------------------------------------------------------------------
# DNS defaults
# ---------------------------------------------------------------------------
DNS_DEFAULT_TTL: int = 300  # seconds

# ---------------------------------------------------------------------------
# Kerberos protocol constants
# ---------------------------------------------------------------------------

# RFC 4120 §7.5.1 — key usage for AP-REQ Authenticator encryption
KRB5_KEY_USAGE_AP_REQ_AUTHENTICATOR: int = 11

# GSS-API checksum flags (RFC 4121 §4.1.1.1, cksumtype=0x8003)
# REPLAY=0x04 | SEQUENCE=0x08 | CONF=0x10 | INTEG=0x20
KRB5_GSS_FLAGS: int = 0x3C

# LDAP Kerberos bind result codes
LDAP_RESULT_SUCCESS: int = 0
LDAP_RESULT_STRONGER_AUTH_REQUIRED: int = 8
LDAP_RESULT_INVALID_CREDENTIALS: int = 49

# ---------------------------------------------------------------------------
# Windows extended LDAP error codes (appear in LDAP result message strings)
# ---------------------------------------------------------------------------
WIN_ERROR_PASSWORD_POLICY: str = "0000052D"   # Password does not meet policy
WIN_ERROR_ACCOUNT_EXISTS: str = "00000524"    # Account already exists
WIN_ERROR_PASSWORD_EXPIRED: str = "00000532"  # Password expired
WIN_ERROR_ACCOUNT_LOCKED: str = "00000775"    # Account locked out
