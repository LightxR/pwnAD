"""
ADCS (Active Directory Certificate Services) module for pwnAD.
Inspired by Certipy for ESC vulnerability detection.

This module provides:
- Certificate template parsing and analysis
- ESC1-ESC15 vulnerability detection
- CA enumeration helpers

IMPORTANT: Vulnerabilities are only reported if the current user can enroll
in the template, following Certipy's approach.
"""

import logging
import uuid
import struct
from datetime import datetime, timezone
from ldap3 import SUBTREE, BASE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars

from impacket.ldap import ldaptypes

# Try to import cryptography for certificate parsing
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    logging.debug("cryptography library not available - certificate parsing limited")

# Try to import impacket for RRP (Remote Registry Protocol) and CSRA
try:
    from impacket.dcerpc.v5 import transport, rrp
    from impacket.dcerpc.v5.dtypes import NULL
    HAS_RRP = True
except ImportError:
    HAS_RRP = False
    logging.debug("impacket RRP not available - CA configuration via registry not available")

# Try to import impacket for CSRA (Certificate Services Remote Administration)
try:
    from impacket.dcerpc.v5 import icpr
    HAS_CSRA = True
except ImportError:
    HAS_CSRA = False
    logging.debug("impacket CSRA not available")


# =============================================================================
# EKU OIDs (Extended Key Usage)
# =============================================================================

EKU_CLIENT_AUTHENTICATION = "1.3.6.1.5.5.7.3.2"
EKU_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT_CLIENT_AUTH = "1.3.6.1.5.2.3.4"
EKU_CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_SUBORDINATE_CA = "1.3.6.1.4.1.311.76.6.1"

# OID names for display
EKU_NAMES = {
    EKU_CLIENT_AUTHENTICATION: "Client Authentication",
    EKU_SMART_CARD_LOGON: "Smart Card Logon",
    EKU_PKINIT_CLIENT_AUTH: "PKINIT Client Authentication",
    EKU_CERTIFICATE_REQUEST_AGENT: "Certificate Request Agent",
    EKU_ANY_PURPOSE: "Any Purpose",
    EKU_SUBORDINATE_CA: "Subordinate CA",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.4": "Email Protection",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.4.1.311.10.3.4": "EFS Encryption",
    "1.3.6.1.4.1.311.10.3.4.1": "EFS Recovery",
}

# Authentication-enabling EKUs
AUTHENTICATION_EKUS = {
    EKU_CLIENT_AUTHENTICATION,
    EKU_SMART_CARD_LOGON,
    EKU_PKINIT_CLIENT_AUTH,
}


# =============================================================================
# Certificate Name Flags (msPKI-Certificate-Name-Flag)
# =============================================================================

class CertificateNameFlag:
    """MS-CRTD 2.28 msPKI-Certificate-Name-Flag Attribute"""
    ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
    SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
    SUBJECT_ALT_REQUIRE_SPN = 0x00800000
    SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
    SUBJECT_ALT_REQUIRE_UPN = 0x02000000
    SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
    SUBJECT_ALT_REQUIRE_DNS = 0x08000000
    SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
    SUBJECT_REQUIRE_EMAIL = 0x20000000
    SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
    SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000

    FLAG_NAMES = {
        0x00000001: "ENROLLEE_SUPPLIES_SUBJECT",
        0x00010000: "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
        0x00400000: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
        0x00800000: "SUBJECT_ALT_REQUIRE_SPN",
        0x01000000: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
        0x02000000: "SUBJECT_ALT_REQUIRE_UPN",
        0x04000000: "SUBJECT_ALT_REQUIRE_EMAIL",
        0x08000000: "SUBJECT_ALT_REQUIRE_DNS",
        0x10000000: "SUBJECT_REQUIRE_DNS_AS_CN",
        0x20000000: "SUBJECT_REQUIRE_EMAIL",
        0x40000000: "SUBJECT_REQUIRE_COMMON_NAME",
        0x80000000: "SUBJECT_REQUIRE_DIRECTORY_PATH",
    }


# =============================================================================
# Enrollment Flags (msPKI-Enrollment-Flag)
# =============================================================================

class EnrollmentFlag:
    """MS-CRTD 2.26 msPKI-Enrollment-Flag Attribute"""
    INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
    PEND_ALL_REQUESTS = 0x00000002
    PUBLISH_TO_KRA_CONTAINER = 0x00000004
    PUBLISH_TO_DS = 0x00000008
    AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
    AUTO_ENROLLMENT = 0x00000020
    CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x00000080
    PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
    USER_INTERACTION_REQUIRED = 0x00000100
    ADD_TEMPLATE_NAME = 0x00000200
    REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
    ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
    ADD_OCSP_NOCHECK = 0x00001000
    ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
    NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
    INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
    ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
    ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
    SKIP_AUTO_RENEWAL = 0x00040000
    NO_SECURITY_EXTENSION = 0x00080000

    FLAG_NAMES = {
        0x00000001: "INCLUDE_SYMMETRIC_ALGORITHMS",
        0x00000002: "PEND_ALL_REQUESTS",
        0x00000004: "PUBLISH_TO_KRA_CONTAINER",
        0x00000008: "PUBLISH_TO_DS",
        0x00000010: "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
        0x00000020: "AUTO_ENROLLMENT",
        0x00000040: "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
        0x00000080: "CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED",
        0x00000100: "USER_INTERACTION_REQUIRED",
        0x00000200: "ADD_TEMPLATE_NAME",
        0x00000400: "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
        0x00000800: "ALLOW_ENROLL_ON_BEHALF_OF",
        0x00001000: "ADD_OCSP_NOCHECK",
        0x00002000: "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
        0x00004000: "NOREVOCATIONINFOINISSUEDCERTS",
        0x00008000: "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
        0x00010000: "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT",
        0x00020000: "ISSUANCE_POLICIES_FROM_REQUEST",
        0x00040000: "SKIP_AUTO_RENEWAL",
        0x00080000: "NO_SECURITY_EXTENSION",
    }


# =============================================================================
# Private Key Flags (msPKI-Private-Key-Flag)
# =============================================================================

class PrivateKeyFlag:
    """MS-CRTD 2.27 msPKI-Private-Key-Flag Attribute"""
    REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
    EXPORTABLE_KEY = 0x00000010
    STRONG_KEY_PROTECTION_REQUIRED = 0x00000020
    REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040
    REQUIRE_SAME_KEY_RENEWAL = 0x00000080
    USE_LEGACY_PROVIDER = 0x00000100
    ATTEST_NONE = 0x00000000
    ATTEST_REQUIRED = 0x00002000
    ATTEST_PREFERRED = 0x00001000
    ATTESTATION_WITHOUT_POLICY = 0x00004000
    EK_TRUST_ON_USE = 0x00000200
    EK_VALIDATE_CERT = 0x00000400
    EK_VALIDATE_KEY = 0x00000800
    HELLO_LOGON_KEY = 0x00200000

    FLAG_NAMES = {
        0x00000001: "REQUIRE_PRIVATE_KEY_ARCHIVAL",
        0x00000010: "EXPORTABLE_KEY",
        0x00000020: "STRONG_KEY_PROTECTION_REQUIRED",
        0x00000040: "REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM",
        0x00000080: "REQUIRE_SAME_KEY_RENEWAL",
        0x00000100: "USE_LEGACY_PROVIDER",
        0x00001000: "ATTEST_PREFERRED",
        0x00002000: "ATTEST_REQUIRED",
        0x00004000: "ATTESTATION_WITHOUT_POLICY",
        0x00000200: "EK_TRUST_ON_USE",
        0x00000400: "EK_VALIDATE_CERT",
        0x00000800: "EK_VALIDATE_KEY",
        0x00200000: "HELLO_LOGON_KEY",
    }


# =============================================================================
# Access Rights for Certificate Templates
# =============================================================================

# Certificate-Enrollment extended right GUID
CERTIFICATE_ENROLLMENT_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
CERTIFICATE_AUTOENROLLMENT_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# Access mask constants
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100  # Extended rights (includes Enroll)
GENERIC_ALL = 0x10000000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
GENERIC_WRITE = 0x40000000
WRITE_PROPERTY = 0x00000020

# CA-specific extended rights GUIDs
CA_ENROLL_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Enroll
CA_MANAGE_CA_GUID = "ee138286-6c22-11d2-8d5f-00a0c9441e89"  # Manage CA
CA_MANAGE_CERTIFICATES_GUID = "0e10c969-78fb-11d2-90d4-00c04f79dc55"  # Manage Certificates

# CA configuration flags (from registry)
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000


# =============================================================================
# ESC Vulnerability Definitions
# =============================================================================

# =============================================================================
# CertificateAuthority Class
# =============================================================================

class CertificateAuthority:
    """
    Represents a Certificate Authority with parsed attributes and permissions.
    """

    def __init__(self, entry):
        """
        Initialize from LDAP entry.

        Args:
            entry: Dict with 'dn' and 'attributes' keys from LDAP search
        """
        self.dn = entry.get('dn', '')
        attrs = entry.get('attributes', {})

        # Basic info
        self.name = self._get_attr(attrs, 'cn', '') or self._get_attr(attrs, 'name', '')
        self.dns_hostname = self._get_attr(attrs, 'dNSHostName', '')
        self.ca_certificate_dn = self._get_attr(attrs, 'cACertificateDN', '')

        # Certificate templates
        templates = attrs.get('certificateTemplates', [])
        if isinstance(templates, str):
            templates = [templates]
        self.certificate_templates = list(templates) if templates else []

        # Raw certificate for parsing
        self._ca_certificate_raw = attrs.get('cACertificate', None)
        if isinstance(self._ca_certificate_raw, list) and self._ca_certificate_raw:
            self._ca_certificate_raw = self._ca_certificate_raw[0]

        # Parsed certificate info
        self.certificate_serial_number = None
        self.certificate_validity_start = None
        self.certificate_validity_end = None
        self._parse_certificate()

        # Security descriptor (raw)
        self.security_descriptor_raw = attrs.get('nTSecurityDescriptor', None)
        if isinstance(self.security_descriptor_raw, list) and self.security_descriptor_raw:
            self.security_descriptor_raw = self.security_descriptor_raw[0]

        # Permissions
        self._owner = None
        self._owner_sid = None
        self._manage_ca_principals = []
        self._manage_certificates_principals = []
        self._enroll_principals = []
        self._manage_ca_sids = set()
        self._manage_certificates_sids = set()
        self._enroll_sids = set()

        # CA Configuration (from registry via RRP)
        self.web_enrollment = None  # None = unknown, True/False = detected
        self.user_specified_san = None  # EDITF_ATTRIBUTESUBJECTALTNAME2
        self.request_disposition = None  # Issue / Pending
        self.enforce_encryption = None  # IF_ENFORCEENCRYPTICERTREQUEST

        # Detected vulnerabilities
        self.vulnerabilities = []

    def _get_attr(self, attrs, name, default=None):
        """Get a single attribute value."""
        val = attrs.get(name, default)
        if isinstance(val, list):
            return val[0] if val else default
        return val if val is not None else default

    def _parse_certificate(self):
        """Parse the CA certificate to extract serial number and validity."""
        if not self._ca_certificate_raw or not HAS_CRYPTOGRAPHY:
            return

        try:
            cert = x509.load_der_x509_certificate(self._ca_certificate_raw, default_backend())

            # Serial number (as hex string)
            serial_hex = format(cert.serial_number, 'X')
            # Format like certipy: add spaces every 2 chars
            self.certificate_serial_number = serial_hex

            # Validity dates
            self.certificate_validity_start = cert.not_valid_before_utc
            self.certificate_validity_end = cert.not_valid_after_utc

        except Exception as e:
            logging.debug(f"Error parsing CA certificate: {e}")

    def parse_security_descriptor(self, conn=None):
        """
        Parse the security descriptor to extract CA permissions.

        Args:
            conn: LDAP connection for SID resolution (optional)
        """
        if not self.security_descriptor_raw:
            return

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.security_descriptor_raw)

            # Get owner SID
            owner_sid_raw = sd['OwnerSid']
            if owner_sid_raw:
                if hasattr(owner_sid_raw, 'formatCanonical'):
                    owner_sid = owner_sid_raw.formatCanonical()
                elif isinstance(owner_sid_raw, bytes):
                    owner_sid = format_sid(owner_sid_raw)
                else:
                    owner_sid = str(owner_sid_raw)

                self._owner_sid = owner_sid
                self._owner = self._resolve_sid(conn, owner_sid)

            if not sd['Dacl']:
                return

            for ace in sd['Dacl']['Data']:
                ace_type = ace['AceType']
                # Only process ALLOWED ACEs
                if ace_type not in (0x00, 0x05):  # ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT
                    continue

                sid = ace['Ace']['Sid'].formatCanonical()
                mask = ace['Ace']['Mask']['Mask']

                principal_name = self._resolve_sid(conn, sid)

                # Check for GenericAll (includes all rights)
                if mask & GENERIC_ALL:
                    if principal_name not in self._manage_ca_principals:
                        self._manage_ca_principals.append(principal_name)
                    if principal_name not in self._manage_certificates_principals:
                        self._manage_certificates_principals.append(principal_name)
                    if principal_name not in self._enroll_principals:
                        self._enroll_principals.append(principal_name)
                    self._manage_ca_sids.add(sid)
                    self._manage_certificates_sids.add(sid)
                    self._enroll_sids.add(sid)
                    continue

                # Check for specific extended rights (object ACE)
                if ace_type == 0x05:  # ACCESS_ALLOWED_OBJECT
                    try:
                        flags = ace['Ace']['Flags']
                        if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                            object_type = ace['Ace']['ObjectType']
                            guid_str = str(uuid.UUID(bytes_le=bytes(object_type))).lower()

                            if guid_str == CA_MANAGE_CA_GUID.lower():
                                if principal_name not in self._manage_ca_principals:
                                    self._manage_ca_principals.append(principal_name)
                                self._manage_ca_sids.add(sid)

                            elif guid_str == CA_MANAGE_CERTIFICATES_GUID.lower():
                                if principal_name not in self._manage_certificates_principals:
                                    self._manage_certificates_principals.append(principal_name)
                                self._manage_certificates_sids.add(sid)

                            elif guid_str == CA_ENROLL_GUID.lower():
                                if principal_name not in self._enroll_principals:
                                    self._enroll_principals.append(principal_name)
                                self._enroll_sids.add(sid)

                    except Exception as e:
                        logging.debug(f"Error parsing object ACE: {e}")

                # Check for ExtendedRight without specific object type (All Extended Rights)
                if ace_type == 0x00 and (mask & ADS_RIGHT_DS_CONTROL_ACCESS):
                    if principal_name not in self._enroll_principals:
                        self._enroll_principals.append(principal_name)
                    if principal_name not in self._manage_ca_principals:
                        self._manage_ca_principals.append(principal_name)
                    if principal_name not in self._manage_certificates_principals:
                        self._manage_certificates_principals.append(principal_name)
                    self._manage_ca_sids.add(sid)
                    self._manage_certificates_sids.add(sid)
                    self._enroll_sids.add(sid)

        except Exception as e:
            logging.debug(f"Error parsing CA security descriptor for {self.name}: {e}")

    def _resolve_sid(self, conn, sid):
        """Resolve SID to sAMAccountName."""
        well_known = {
            'S-1-1-0': 'Everyone',
            'S-1-5-11': 'Authenticated Users',
            'S-1-5-7': 'Anonymous',
            'S-1-5-18': 'SYSTEM',
            'S-1-5-32-544': 'BUILTIN\\Administrators',
            'S-1-5-9': 'Enterprise Domain Controllers',
        }
        if sid in well_known:
            return well_known[sid]
        if conn:
            try:
                name = conn.get_samaccountname_from_sid(sid)
                if name:
                    return name
            except Exception:
                pass
        return sid

    def get_ca_config_via_rrp(self, target, username, password, domain, lmhash='', nthash='', aesKey='', doKerberos=False, kdcHost=None):
        """
        Retrieve CA configuration via Remote Registry Protocol (RRP).

        This retrieves settings like:
        - Web Enrollment
        - User Specified SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)
        - Request Disposition
        - Enforce Encryption

        Args:
            target: Target hostname/IP (should be the CA server)
            username, password, domain: Authentication credentials
            lmhash, nthash: NTLM hashes
            aesKey: Kerberos AES key
            doKerberos: Use Kerberos authentication
            kdcHost: KDC hostname for Kerberos
        """
        if not HAS_RRP:
            logging.debug("RRP not available - cannot get CA configuration")
            return

        dce = None
        try:
            # Connect via DCE/RPC to the remote registry
            stringbinding = f'ncacn_np:{target}[\\pipe\\winreg]'
            rpctransport = transport.DCERPCTransportFactory(stringbinding)

            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(username, password, domain, lmhash, nthash, aesKey)
                if doKerberos:
                    rpctransport.set_kerberos(doKerberos, kdcHost)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            # Open HKEY_LOCAL_MACHINE
            resp = rrp.hOpenLocalMachine(dce)
            hRootKey = resp['phKey']

            # Path to CA configuration
            ca_config_path = f'SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{self.name}'

            try:
                resp = rrp.hBaseRegOpenKey(dce, hRootKey, ca_config_path)
                hKey = resp['phkResult']

                # Read InterfaceFlags (for ENFORCE_ENCRYPTION and Web Enrollment detection)
                try:
                    resp_val = rrp.hBaseRegQueryValue(dce, hKey, 'InterfaceFlags')
                    # hBaseRegQueryValue returns (regType, regValue)
                    flags = resp_val[1]
                    if isinstance(flags, bytes):
                        flags = int.from_bytes(flags[:4], 'little')
                    self.enforce_encryption = bool(flags & IF_ENFORCEENCRYPTICERTREQUEST)
                    logging.debug(f"InterfaceFlags: {flags}, EnforceEncryption: {self.enforce_encryption}")
                except Exception as e:
                    logging.debug(f"Could not read InterfaceFlags: {e}")
                    self.enforce_encryption = False

                # Read EditFlags (for EDITF_ATTRIBUTESUBJECTALTNAME2)
                try:
                    resp_val = rrp.hBaseRegQueryValue(dce, hKey, 'EditFlags')
                    flags = resp_val[1]
                    if isinstance(flags, bytes):
                        flags = int.from_bytes(flags[:4], 'little')
                    self.user_specified_san = bool(flags & EDITF_ATTRIBUTESUBJECTALTNAME2)
                    logging.debug(f"EditFlags: {flags}, UserSpecifiedSAN: {self.user_specified_san}")
                except Exception as e:
                    logging.debug(f"Could not read EditFlags: {e}")
                    self.user_specified_san = False

                # Try to read PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\RequestDisposition
                try:
                    policy_path = 'PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy'
                    resp_policy = rrp.hBaseRegOpenKey(dce, hKey, policy_path)
                    hPolicyKey = resp_policy['phkResult']

                    try:
                        resp_val = rrp.hBaseRegQueryValue(dce, hPolicyKey, 'RequestDisposition')
                        value = resp_val[1]
                        if isinstance(value, bytes):
                            value = int.from_bytes(value[:4], 'little')
                        self.request_disposition = "Issue" if value == 1 else "Pending"
                        logging.debug(f"RequestDisposition value: {value}, Result: {self.request_disposition}")
                    except Exception as e:
                        logging.debug(f"Could not read RequestDisposition: {e}")
                        self.request_disposition = "Issue"  # Default

                    rrp.hBaseRegCloseKey(dce, hPolicyKey)
                except Exception as e:
                    logging.debug(f"Could not open PolicyModules key: {e}")
                    self.request_disposition = "Issue"  # Default

                # Web Enrollment is checked separately via HTTP
                # Default to False here, will be checked via HTTP later if needed
                if self.web_enrollment is None:
                    self.web_enrollment = False

                rrp.hBaseRegCloseKey(dce, hKey)
                logging.info(f"Got CA configuration for '{self.name}' via RRP")

            except Exception as e:
                logging.debug(f"Could not open CA config registry key: {e}")

            rrp.hBaseRegCloseKey(dce, hRootKey)

        except Exception as e:
            logging.debug(f"Error getting CA config via RRP: {e}")
        finally:
            if dce:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    def check_web_enrollment(self, timeout=5):
        """
        Check if Web Enrollment is enabled by making an HTTP request.

        Args:
            timeout: Request timeout in seconds
        """
        if not self.dns_hostname:
            return

        import urllib.request
        import ssl

        # Try both HTTP and HTTPS endpoints
        endpoints = [
            f"http://{self.dns_hostname}/certsrv/",
            f"https://{self.dns_hostname}/certsrv/",
        ]

        # Create SSL context that doesn't verify certificates
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        for url in endpoints:
            try:
                req = urllib.request.Request(url, method='HEAD')
                req.add_header('User-Agent', 'Mozilla/5.0')
                response = urllib.request.urlopen(req, timeout=timeout, context=ssl_context)
                # If we get here without exception, web enrollment is likely enabled
                if response.status in (200, 401, 403):  # 401/403 means it exists but requires auth
                    self.web_enrollment = True
                    logging.debug(f"Web Enrollment detected at {url}")
                    return
            except urllib.error.HTTPError as e:
                # 401/403 means the endpoint exists but requires authentication
                if e.code in (401, 403):
                    self.web_enrollment = True
                    logging.debug(f"Web Enrollment detected at {url} (requires auth)")
                    return
            except Exception as e:
                logging.debug(f"Web Enrollment check failed for {url}: {e}")
                continue

        self.web_enrollment = False

    @property
    def owner(self):
        """Get the CA owner."""
        return self._owner

    @property
    def manage_ca_principals(self):
        """Get principals with ManageCA permission."""
        return self._manage_ca_principals

    @property
    def manage_certificates_principals(self):
        """Get principals with ManageCertificates permission."""
        return self._manage_certificates_principals

    @property
    def enroll_principals(self):
        """Get principals with Enroll permission."""
        return self._enroll_principals

    def detect_vulnerabilities(self, user_sids=None, templates=None):
        """Detect CA-level ESC vulnerabilities."""
        self.vulnerabilities = []
        if user_sids is None:
            user_sids = set()

        # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
        if self.user_specified_san:
            enrollable_auth = []
            if templates:
                for t in templates:
                    if t.name in self.certificate_templates and t._can_enroll and t.client_authentication:
                        enrollable_auth.append(t.name)
            if enrollable_auth:
                self.vulnerabilities.append({
                    "id": "ESC6",
                    **ESC_DEFINITIONS["ESC6"],
                    "detail": f"Enrollable templates with Client Auth: {', '.join(enrollable_auth[:5])}",
                })

        # ESC7: ManageCA or ManageCertificates for current user
        admin_sids = {'S-1-5-18', 'S-1-5-32-544', 'S-1-5-9'}
        user_non_admin = user_sids - admin_sids
        has_manage_ca = bool(user_non_admin & self._manage_ca_sids)
        has_manage_certs = bool(user_non_admin & self._manage_certificates_sids)
        if has_manage_ca or has_manage_certs:
            rights = []
            if has_manage_ca:
                rights.append('ManageCA')
            if has_manage_certs:
                rights.append('ManageCertificates')
            self.vulnerabilities.append({
                "id": "ESC7",
                **ESC_DEFINITIONS["ESC7"],
                "detail": f"You have: {', '.join(rights)}",
            })

        # ESC8: Web Enrollment enabled
        if self.web_enrollment:
            self.vulnerabilities.append({
                "id": "ESC8",
                **ESC_DEFINITIONS["ESC8"],
                "detail": f"HTTP enrollment at {self.dns_hostname}/certsrv/",
            })

        # ESC11: No encryption enforcement (RPC relay)
        if self.enforce_encryption is False:
            self.vulnerabilities.append({
                "id": "ESC11",
                **ESC_DEFINITIONS["ESC11"],
            })

        return self.vulnerabilities

    @property
    def is_vulnerable(self):
        return len(self.vulnerabilities) > 0

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'dn': self.dn,
            'name': self.name,
            'dns_hostname': self.dns_hostname,
            'ca_certificate_dn': self.ca_certificate_dn,
            'certificate_serial_number': self.certificate_serial_number,
            'certificate_validity_start': str(self.certificate_validity_start) if self.certificate_validity_start else None,
            'certificate_validity_end': str(self.certificate_validity_end) if self.certificate_validity_end else None,
            'certificate_templates': self.certificate_templates,
            'web_enrollment': self.web_enrollment,
            'user_specified_san': self.user_specified_san,
            'request_disposition': self.request_disposition,
            'enforce_encryption': self.enforce_encryption,
            'permissions': {
                'owner': self._owner,
                'manage_ca': self._manage_ca_principals,
                'manage_certificates': self._manage_certificates_principals,
                'enroll': self._enroll_principals,
            },
            'vulnerabilities': self.vulnerabilities,
            'is_vulnerable': self.is_vulnerable,
        }


ESC_DEFINITIONS = {
    "ESC1": {
        "name": "ESC1",
        "description": "Template allows requesters to specify a SAN (Subject Alternative Name)",
        "severity": "Critical",
        "color": "red",
        "conditions": "ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU + No manager approval + User can enroll",
    },
    "ESC2": {
        "name": "ESC2",
        "description": "Template has Any Purpose EKU or no EKU (SubCA)",
        "severity": "High",
        "color": "orange",
        "conditions": "Any Purpose EKU or no EKU defined + User can enroll",
    },
    "ESC3": {
        "name": "ESC3",
        "description": "Template has Certificate Request Agent EKU",
        "severity": "High",
        "color": "orange",
        "conditions": "Certificate Request Agent EKU + User can enroll",
    },
    "ESC4": {
        "name": "ESC4",
        "description": "Template has vulnerable DACL (WriteDACL/WriteOwner/GenericAll)",
        "severity": "High",
        "color": "orange",
        "conditions": "User has dangerous write permissions on template",
    },
    "ESC9": {
        "name": "ESC9",
        "description": "Template has NO_SECURITY_EXTENSION flag with Client Auth",
        "severity": "High",
        "color": "orange",
        "conditions": "CT_FLAG_NO_SECURITY_EXTENSION + Client Auth + User can enroll",
    },
    "ESC13": {
        "name": "ESC13",
        "description": "Issuance policy linked to privileged group via OID",
        "severity": "High",
        "color": "orange",
        "conditions": "msPKI-Certificate-Policy with msDS-OIDToGroupLink + User can enroll",
    },
    "ESC15": {
        "name": "ESC15",
        "description": "Schema Version 1 template with ENROLLEE_SUPPLIES_SUBJECT (CVE-2024-49019)",
        "severity": "Critical",
        "color": "red",
        "conditions": "Schema v1 + ENROLLEE_SUPPLIES_SUBJECT + User can enroll",
    },
    "ESC5": {
        "name": "ESC5",
        "description": "Vulnerable PKI AD object ACLs",
        "severity": "High",
        "color": "orange",
        "conditions": "User has write access to PKI containers (AIA, CDP, NTAuthCertificates, etc.)",
    },
    "ESC6": {
        "name": "ESC6",
        "description": "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
        "severity": "Critical",
        "color": "red",
        "conditions": "EDITF_ATTRIBUTESUBJECTALTNAME2 on CA + enrollable template with Client Auth EKU",
    },
    "ESC7": {
        "name": "ESC7",
        "description": "Vulnerable CA ACL (ManageCA or ManageCertificates)",
        "severity": "High",
        "color": "orange",
        "conditions": "User has ManageCA or ManageCertificates right on the CA",
    },
    "ESC8": {
        "name": "ESC8",
        "description": "NTLM relay to AD CS HTTP enrollment (certsrv)",
        "severity": "High",
        "color": "orange",
        "conditions": "Web Enrollment (certsrv) enabled on CA",
    },
    "ESC10": {
        "name": "ESC10",
        "description": "Weak certificate mapping allows impersonation",
        "severity": "High",
        "color": "orange",
        "conditions": "StrongCertificateBindingEnforcement=0 or CertificateMappingMethods includes UPN mapping (0x4)",
    },
    "ESC11": {
        "name": "ESC11",
        "description": "NTLM relay to AD CS RPC enrollment (ICertPassage)",
        "severity": "High",
        "color": "orange",
        "conditions": "CA does not enforce encryption (IF_ENFORCEENCRYPTICERTREQUEST not set)",
    },
}


# =============================================================================
# User SID Resolution Helper
# =============================================================================

def get_user_sids(conn):
    """
    Get the current user's SID and all group SIDs (via tokenGroups).

    This is essential to check if the user can enroll in a template.

    Args:
        conn: LDAP connection object

    Returns:
        set: Set of SID strings (user SID + all group SIDs)
    """
    user_sids = set()

    try:
        # Get the current user's DN
        username = getattr(conn, 'ldap_user', None) or getattr(conn, 'user', None)
        if not username:
            logging.warning("Cannot determine current user for enrollment check")
            return user_sids

        # Handle domain\user format
        if '\\' in username:
            username = username.split('\\')[-1]
        if '@' in username:
            username = username.split('@')[0]

        # Find user DN and SID
        conn._ldap_connection.search(
            search_base=conn._baseDN,
            search_filter=f"(sAMAccountName={escape_filter_chars(username)})",
            search_scope=SUBTREE,
            attributes=['objectSid', 'distinguishedName']
        )

        if not conn._ldap_connection.entries:
            logging.warning(f"User {username} not found in directory")
            return user_sids

        entry = conn._ldap_connection.entries[0]
        user_dn = entry.entry_dn

        # Get user's primary SID
        raw_sid = entry.entry_raw_attributes.get('objectSid')
        if raw_sid:
            user_sid = format_sid(raw_sid[0])
            user_sids.add(user_sid)
            logging.debug(f"User SID: {user_sid}")

        # Get all group memberships via tokenGroups (computed attribute)
        conn._ldap_connection.search(
            search_base=user_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=['tokenGroups']
        )

        if conn._ldap_connection.entries:
            token_entry = conn._ldap_connection.entries[0]
            raw_groups = token_entry.entry_raw_attributes.get('tokenGroups', [])
            for raw_group_sid in raw_groups:
                group_sid = format_sid(raw_group_sid)
                user_sids.add(group_sid)

        logging.debug(f"Total SIDs for user (including groups): {len(user_sids)}")

    except Exception as e:
        logging.error(f"Error getting user SIDs: {e}")

    return user_sids


# =============================================================================
# CertificateTemplate Class
# =============================================================================

class CertificateTemplate:
    """
    Represents a Certificate Template with parsed attributes and vulnerability detection.
    """

    def __init__(self, entry):
        """
        Initialize from LDAP entry.

        Args:
            entry: Dict with 'dn' and 'attributes' keys from LDAP search
        """
        self.dn = entry.get('dn', '')
        attrs = entry.get('attributes', {})

        # Basic info
        self.name = self._get_attr(attrs, 'cn', '')
        self.display_name = self._get_attr(attrs, 'displayName', self.name)
        self.object_guid = self._get_attr(attrs, 'objectGUID', '')

        # Schema version
        self.schema_version = self._get_int_attr(attrs, 'msPKI-Template-Schema-Version', 1)

        # Flags
        self.certificate_name_flag = self._get_int_attr(attrs, 'msPKI-Certificate-Name-Flag', 0)
        self.enrollment_flag = self._get_int_attr(attrs, 'msPKI-Enrollment-Flag', 0)
        self.private_key_flag = self._get_int_attr(attrs, 'msPKI-Private-Key-Flag', 0)

        # EKUs (Extended Key Usage)
        self.ekus = self._get_list_attr(attrs, 'pKIExtendedKeyUsage')

        # Application Policies (msPKI-Certificate-Application-Policy)
        self.application_policies = self._get_list_attr(attrs, 'msPKI-Certificate-Application-Policy')

        # RA (Registration Authority) requirements
        self.ra_signature = self._get_int_attr(attrs, 'msPKI-RA-Signature', 0)
        self.ra_application_policies = self._get_list_attr(attrs, 'msPKI-RA-Application-Policies')

        # Issuance policies (for ESC13)
        self.certificate_policy = self._get_list_attr(attrs, 'msPKI-Certificate-Policy')

        # Validity periods (raw bytes)
        self.validity_period_raw = attrs.get('pKIExpirationPeriod', None)
        self.renewal_period_raw = attrs.get('pKIOverlapPeriod', None)
        self.validity_period = self._parse_period(self.validity_period_raw)
        self.renewal_period = self._parse_period(self.renewal_period_raw)

        # Minimum key size
        self.min_key_size = self._get_int_attr(attrs, 'msPKI-Minimal-Key-Size', 2048)

        # Security descriptor (raw)
        self.security_descriptor_raw = attrs.get('nTSecurityDescriptor', None)
        if isinstance(self.security_descriptor_raw, list) and self.security_descriptor_raw:
            self.security_descriptor_raw = self.security_descriptor_raw[0]

        # Can current user enroll?
        self._can_enroll = False
        self._can_write = False  # For ESC4
        self._is_owner = False  # For ESC4 ownership check
        self._enrollment_principals = []  # Who can enroll (for display)
        self._write_owner_principals = []
        self._write_dacl_principals = []
        self._write_property_principals = []
        self._owner = None
        self._owner_sid = None
        self.dangerous_permissions = []

        # Detected vulnerabilities
        self.vulnerabilities = []

        # CAs that have this template enabled
        self.enabled_on_cas = []
        self.enabled = False  # Is template enabled on any CA?

    def _parse_period(self, raw_value):
        """Parse pKIExpirationPeriod/pKIOverlapPeriod to human-readable string."""
        if raw_value is None:
            return "Unknown"
        try:
            if isinstance(raw_value, list):
                raw_value = raw_value[0]
            if isinstance(raw_value, bytes):
                # These are stored as negative 100-nanosecond intervals
                import struct
                value = struct.unpack('<q', raw_value)[0]
                # Convert to positive seconds
                seconds = abs(value) / 10000000

                if seconds >= 31536000:  # 365 days
                    years = seconds / 31536000
                    return f"{int(years)} year{'s' if years > 1 else ''}"
                elif seconds >= 604800:  # 7 days
                    weeks = seconds / 604800
                    return f"{int(weeks)} week{'s' if weeks > 1 else ''}"
                elif seconds >= 86400:  # 1 day
                    days = seconds / 86400
                    return f"{int(days)} day{'s' if days > 1 else ''}"
                elif seconds >= 3600:
                    hours = seconds / 3600
                    return f"{int(hours)} hour{'s' if hours > 1 else ''}"
                else:
                    return f"{int(seconds)} seconds"
        except Exception:
            pass
        return "Unknown"

    def _get_attr(self, attrs, name, default=None):
        """Get a single attribute value."""
        val = attrs.get(name, default)
        if isinstance(val, list):
            return val[0] if val else default
        return val if val is not None else default

    def _get_int_attr(self, attrs, name, default=0):
        """Get an integer attribute value."""
        val = self._get_attr(attrs, name, default)
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _get_list_attr(self, attrs, name):
        """Get a list attribute value."""
        val = attrs.get(name, [])
        if isinstance(val, str):
            return [val]
        return list(val) if val else []

    # -------------------------------------------------------------------------
    # Properties for common checks
    # -------------------------------------------------------------------------

    @property
    def enrollee_supplies_subject(self):
        """Check if enrollee can supply subject name."""
        return bool(self.certificate_name_flag & CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT)

    @property
    def enrollee_supplies_san(self):
        """Check if enrollee can supply Subject Alternative Name."""
        return bool(self.certificate_name_flag & CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)

    @property
    def requires_manager_approval(self):
        """Check if manager approval is required."""
        return bool(self.enrollment_flag & EnrollmentFlag.PEND_ALL_REQUESTS)

    @property
    def no_security_extension(self):
        """Check if NO_SECURITY_EXTENSION flag is set."""
        return bool(self.enrollment_flag & EnrollmentFlag.NO_SECURITY_EXTENSION)

    @property
    def authorized_signatures_required(self):
        """Number of authorized signatures required."""
        return self.ra_signature

    @property
    def client_authentication(self):
        """Check if template enables client authentication."""
        # Check EKUs
        for eku in self.ekus:
            if eku in AUTHENTICATION_EKUS:
                return True
        # Check Application Policies (for Schema v2+)
        for policy in self.application_policies:
            if policy in AUTHENTICATION_EKUS:
                return True
        return False

    @property
    def any_purpose(self):
        """Check if template has Any Purpose EKU."""
        return EKU_ANY_PURPOSE in self.ekus or EKU_ANY_PURPOSE in self.application_policies

    @property
    def no_eku(self):
        """Check if template has no EKU (SubCA-like)."""
        return len(self.ekus) == 0 and len(self.application_policies) == 0

    @property
    def enrollment_agent(self):
        """Check if template has Certificate Request Agent EKU."""
        return (EKU_CERTIFICATE_REQUEST_AGENT in self.ekus or
                EKU_CERTIFICATE_REQUEST_AGENT in self.application_policies)

    @property
    def can_enroll(self):
        """Check if current user can enroll in this template."""
        return self._can_enroll

    @property
    def can_write(self):
        """Check if current user has write permissions (ESC4)."""
        return self._can_write

    # -------------------------------------------------------------------------
    # Security Descriptor Parsing
    # -------------------------------------------------------------------------

    def parse_security_descriptor(self, conn=None, user_sids=None):
        """
        Parse the security descriptor to extract enrollment permissions
        and check if the current user can enroll.

        Args:
            conn: LDAP connection for SID resolution (optional)
            user_sids: Set of SIDs for the current user (required for enrollment check)
        """
        if not self.security_descriptor_raw:
            return

        if user_sids is None:
            user_sids = set()

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.security_descriptor_raw)

            # Get owner SID
            # sd['OwnerSid'] can be bytes (raw) or an LDAP_SID object
            owner_sid_raw = sd['OwnerSid']
            if owner_sid_raw:
                # Handle both raw bytes and LDAP_SID object
                if hasattr(owner_sid_raw, 'formatCanonical'):
                    owner_sid = owner_sid_raw.formatCanonical()
                elif isinstance(owner_sid_raw, bytes):
                    owner_sid = format_sid(owner_sid_raw)
                else:
                    owner_sid = str(owner_sid_raw)

                self._owner_sid = owner_sid
                self._owner = self._resolve_sid(conn, owner_sid)
                # Check if current user is owner (ESC4)
                if owner_sid in user_sids:
                    self._is_owner = True
                    self._can_write = True
                    logging.debug(f"User is owner of {self.name} via SID {owner_sid}")

            if not sd['Dacl']:
                return

            for ace in sd['Dacl']['Data']:
                ace_type = ace['AceType']
                # Only process ALLOWED ACEs
                if ace_type not in (0x00, 0x05):  # ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT
                    continue

                sid = ace['Ace']['Sid'].formatCanonical()
                mask = ace['Ace']['Mask']['Mask']

                principal_name = self._resolve_sid(conn, sid)

                # Check for Certificate-Enrollment extended right (object ACE)
                if ace_type == 0x05:  # ACCESS_ALLOWED_OBJECT
                    try:
                        flags = ace['Ace']['Flags']
                        if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                            object_type = ace['Ace']['ObjectType']
                            guid_str = str(uuid.UUID(bytes_le=bytes(object_type))).lower()

                            if guid_str == CERTIFICATE_ENROLLMENT_GUID.lower():
                                self._enrollment_principals.append({
                                    'sid': sid,
                                    'principal': principal_name,
                                    'right': 'Enroll'
                                })
                                # Check if current user can enroll
                                if sid in user_sids:
                                    self._can_enroll = True
                                    logging.debug(f"User can enroll in {self.name} via SID {sid}")

                            elif guid_str == CERTIFICATE_AUTOENROLLMENT_GUID.lower():
                                self._enrollment_principals.append({
                                    'sid': sid,
                                    'principal': principal_name,
                                    'right': 'AutoEnroll'
                                })
                                # AutoEnroll also grants enrollment
                                if sid in user_sids:
                                    self._can_enroll = True

                    except Exception as e:
                        logging.debug(f"Error parsing object ACE: {e}")

                # Check for GenericAll (includes all rights including Enroll)
                if mask & GENERIC_ALL:
                    self._enrollment_principals.append({
                        'sid': sid,
                        'principal': principal_name,
                        'right': 'GenericAll'
                    })
                    self._write_owner_principals.append(principal_name)
                    self._write_dacl_principals.append(principal_name)
                    self._write_property_principals.append(principal_name)
                    if sid in user_sids:
                        self._can_enroll = True
                        self._can_write = True
                    continue  # Already processed all rights

                # Check for ExtendedRight without specific object type (All Extended Rights)
                if ace_type == 0x00 and (mask & ADS_RIGHT_DS_CONTROL_ACCESS):
                    # Non-object ACE with ControlAccess = All Extended Rights
                    self._enrollment_principals.append({
                        'sid': sid,
                        'principal': principal_name,
                        'right': 'AllExtendedRights'
                    })
                    if sid in user_sids:
                        self._can_enroll = True

                # Track write permissions for display
                # WRITE_OWNER and WRITE_DACL always apply globally (even in object ACEs)
                # WRITE_PROPERTY is only global for standard ACEs (type 0x00)
                if mask & WRITE_OWNER:
                    if principal_name not in self._write_owner_principals:
                        self._write_owner_principals.append(principal_name)
                if mask & WRITE_DACL:
                    if principal_name not in self._write_dacl_principals:
                        self._write_dacl_principals.append(principal_name)

                # WRITE_PROPERTY and GENERIC_WRITE: only for standard ACEs (not object ACEs)
                # Object ACEs with WRITE_PROPERTY are restricted to specific attributes
                if ace_type == 0x00:  # Standard ACE - rights apply globally
                    if mask & (WRITE_PROPERTY | GENERIC_WRITE):
                        if principal_name not in self._write_property_principals:
                            self._write_property_principals.append(principal_name)

                # Check for dangerous write permissions (ESC4)
                # WRITE_OWNER and WRITE_DACL are always dangerous (global)
                # WRITE_PROPERTY is only dangerous for standard ACEs
                dangerous_global = mask & (WRITE_DACL | WRITE_OWNER)
                dangerous_property = (ace_type == 0x00) and (mask & (GENERIC_WRITE | WRITE_PROPERTY))

                if (dangerous_global or dangerous_property) and sid in user_sids and not self._is_admin_sid(sid):
                    right_names = []
                    if mask & WRITE_DACL:
                        right_names.append('WriteDACL')
                    if mask & WRITE_OWNER:
                        right_names.append('WriteOwner')
                    if ace_type == 0x00:
                        if mask & GENERIC_WRITE:
                            right_names.append('GenericWrite')
                        if mask & WRITE_PROPERTY:
                            right_names.append('WriteProperty')

                    if right_names:
                        self._can_write = True
                        self.dangerous_permissions.append({
                            'sid': sid,
                            'principal': principal_name,
                            'right': ', '.join(right_names),
                            'issue': 'Can modify template'
                        })

        except Exception as e:
            logging.debug(f"Error parsing security descriptor for {self.name}: {e}")

    def _resolve_sid(self, conn, sid):
        """Resolve SID to sAMAccountName."""
        # Well-known SIDs
        well_known = {
            'S-1-1-0': 'Everyone',
            'S-1-5-11': 'Authenticated Users',
            'S-1-5-7': 'Anonymous',
            'S-1-5-18': 'SYSTEM',
            'S-1-5-32-544': 'BUILTIN\\Administrators',
            'S-1-5-9': 'Enterprise Domain Controllers',
        }
        if sid in well_known:
            return well_known[sid]
        if conn:
            try:
                name = conn.get_samaccountname_from_sid(sid)
                if name:
                    return name
            except Exception:
                pass
        return sid

    def _is_admin_sid(self, sid):
        """Check if SID is a known admin/system SID."""
        admin_sids = {
            'S-1-5-18',  # SYSTEM
            'S-1-5-32-544',  # Administrators
            'S-1-5-9',  # Enterprise Domain Controllers
        }
        if sid in admin_sids:
            return True
        # Domain Admins, Enterprise Admins end with -512, -519
        if sid.endswith('-512') or sid.endswith('-519') or sid.endswith('-500'):
            return True
        return False

    # -------------------------------------------------------------------------
    # Vulnerability Detection
    # -------------------------------------------------------------------------

    def detect_vulnerabilities(self, conn=None, oid_to_group_links=None):
        """
        Detect ESC vulnerabilities on this template.

        IMPORTANT: Only detects vulnerabilities if the current user can enroll
        or has write permissions (for ESC4).

        Args:
            conn: LDAP connection for DACL resolution (optional)
            oid_to_group_links: Dict of OID -> group DN for ESC13 (optional)

        Returns:
            List of vulnerability dicts
        """
        self.vulnerabilities = []

        # ESC1: ENROLLEE_SUPPLIES_SUBJECT + Client Auth + No approval + Can enroll
        if (self._can_enroll and
            self.enrollee_supplies_subject and
            self.client_authentication and
            not self.requires_manager_approval and
            self.authorized_signatures_required == 0):
            self.vulnerabilities.append({
                "id": "ESC1",
                **ESC_DEFINITIONS["ESC1"]
            })

        # ESC2: Any Purpose or no EKU + Can enroll
        if self._can_enroll:
            if self.any_purpose:
                self.vulnerabilities.append({
                    "id": "ESC2",
                    **ESC_DEFINITIONS["ESC2"],
                    "detail": "Any Purpose EKU enabled"
                })
            elif self.no_eku and self.schema_version == 1:
                self.vulnerabilities.append({
                    "id": "ESC2",
                    **ESC_DEFINITIONS["ESC2"],
                    "detail": "No EKU defined (Schema v1)"
                })

        # ESC3: Certificate Request Agent + Can enroll
        if self._can_enroll and self.enrollment_agent:
            self.vulnerabilities.append({
                "id": "ESC3",
                **ESC_DEFINITIONS["ESC3"]
            })

        # ESC4: Template ownership or dangerous DACL permissions
        if self._is_owner:
            self.vulnerabilities.append({
                "id": "ESC4",
                **ESC_DEFINITIONS["ESC4"],
                "detail": f"Template is owned by {self._owner}"
            })
        elif self._can_write and self.dangerous_permissions:
            self.vulnerabilities.append({
                "id": "ESC4",
                **ESC_DEFINITIONS["ESC4"],
                "detail": f"You have: {', '.join(p['right'] for p in self.dangerous_permissions)}"
            })

        # ESC9: NO_SECURITY_EXTENSION + Client Auth + Can enroll
        if self._can_enroll and self.no_security_extension and self.client_authentication:
            self.vulnerabilities.append({
                "id": "ESC9",
                **ESC_DEFINITIONS["ESC9"]
            })

        # ESC13: Issuance policy with OID to Group Link + Can enroll
        if self._can_enroll and oid_to_group_links and self.certificate_policy:
            for policy_oid in self.certificate_policy:
                if policy_oid in oid_to_group_links:
                    self.vulnerabilities.append({
                        "id": "ESC13",
                        **ESC_DEFINITIONS["ESC13"],
                        "detail": f"Policy {policy_oid} linked to {oid_to_group_links[policy_oid]}"
                    })
                    break

        # ESC15: Schema v1 + ENROLLEE_SUPPLIES_SUBJECT + Can enroll (CVE-2024-49019)
        if (self._can_enroll and
            self.schema_version == 1 and
            self.enrollee_supplies_subject and
            not self.requires_manager_approval):
            self.vulnerabilities.append({
                "id": "ESC15",
                **ESC_DEFINITIONS["ESC15"]
            })

        return self.vulnerabilities

    # -------------------------------------------------------------------------
    # Display helpers
    # -------------------------------------------------------------------------

    def get_eku_names(self):
        """Get human-readable EKU names."""
        names = []
        for eku in self.ekus:
            names.append(EKU_NAMES.get(eku, eku))
        return names

    def get_application_policy_names(self):
        """Get human-readable Application Policy names."""
        names = []
        for policy in self.application_policies:
            names.append(EKU_NAMES.get(policy, policy))
        return names

    def get_certificate_name_flags(self):
        """Get list of set certificate name flag names."""
        flags = []
        for flag_val, flag_name in CertificateNameFlag.FLAG_NAMES.items():
            if self.certificate_name_flag & flag_val:
                flags.append(flag_name)
        return flags

    def get_enrollment_flags(self):
        """Get list of set enrollment flag names."""
        flags = []
        for flag_val, flag_name in EnrollmentFlag.FLAG_NAMES.items():
            if self.enrollment_flag & flag_val:
                flags.append(flag_name)
        return flags

    def get_private_key_flags(self):
        """Get list of set private key flag names."""
        flags = []
        for flag_val, flag_name in PrivateKeyFlag.FLAG_NAMES.items():
            if self.private_key_flag & flag_val:
                flags.append(flag_name)
        return flags

    @property
    def requires_key_archival(self):
        """Check if private key archival is required."""
        return bool(self.private_key_flag & PrivateKeyFlag.REQUIRE_PRIVATE_KEY_ARCHIVAL)

    @property
    def owner(self):
        """Get the template owner."""
        return self._owner

    @property
    def enrollment_permissions(self):
        """Get enrollment permissions for display."""
        return self._enrollment_principals

    @property
    def write_owner_principals(self):
        """Get principals with WriteOwner permission."""
        return self._write_owner_principals

    @property
    def write_dacl_principals(self):
        """Get principals with WriteDacl permission."""
        return self._write_dacl_principals

    @property
    def write_property_principals(self):
        """Get principals with WriteProperty permission."""
        return self._write_property_principals

    @property
    def is_vulnerable(self):
        """Check if template has any vulnerabilities for the current user."""
        return len(self.vulnerabilities) > 0

    @property
    def highest_severity(self):
        """Get the highest severity among vulnerabilities."""
        if not self.vulnerabilities:
            return None
        severities = {'Critical': 3, 'High': 2, 'Medium': 1, 'Low': 0}
        max_sev = max(self.vulnerabilities, key=lambda v: severities.get(v.get('severity', 'Low'), 0))
        return max_sev.get('severity')

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'dn': self.dn,
            'name': self.name,
            'display_name': self.display_name,
            'schema_version': self.schema_version,
            'enabled': self.enabled,
            'enrollee_supplies_subject': self.enrollee_supplies_subject,
            'client_authentication': self.client_authentication,
            'any_purpose': self.any_purpose,
            'enrollment_agent': self.enrollment_agent,
            'requires_manager_approval': self.requires_manager_approval,
            'requires_key_archival': self.requires_key_archival,
            'no_security_extension': self.no_security_extension,
            'authorized_signatures_required': self.authorized_signatures_required,
            'validity_period': self.validity_period,
            'renewal_period': self.renewal_period,
            'minimum_rsa_key_length': self.min_key_size,
            'ekus': self.get_eku_names(),
            'application_policies': self.get_application_policy_names(),
            'certificate_name_flags': self.get_certificate_name_flags(),
            'enrollment_flags': self.get_enrollment_flags(),
            'private_key_flags': self.get_private_key_flags(),
            'enrollment_permissions': self._enrollment_principals,
            'owner': self._owner,
            'write_owner_principals': self._write_owner_principals,
            'write_dacl_principals': self._write_dacl_principals,
            'write_property_principals': self._write_property_principals,
            'can_enroll': self._can_enroll,
            'can_write': self._can_write,
            'vulnerabilities': self.vulnerabilities,
            'is_vulnerable': self.is_vulnerable,
            'highest_severity': self.highest_severity,
            'enabled_on_cas': self.enabled_on_cas,
        }


# =============================================================================
# Helper Functions
# =============================================================================

def get_certificate_templates(conn, parse_sd=True, user_sids=None):
    """
    Retrieve all certificate templates from the domain.

    Args:
        conn: LDAP connection object
        parse_sd: Whether to parse security descriptors (needed for enrollment check)
        user_sids: Set of user SIDs for enrollment check (if None, will be fetched)

    Returns:
        List of CertificateTemplate objects
    """
    templates = []
    config_path = conn.configuration_path
    search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_path}"

    # Get user SIDs if not provided
    if user_sids is None and parse_sd:
        user_sids = get_user_sids(conn)

    attributes = [
        'cn', 'displayName', 'objectGUID',
        'msPKI-Template-Schema-Version',
        'msPKI-Certificate-Name-Flag',
        'msPKI-Enrollment-Flag',
        'msPKI-Private-Key-Flag',
        'pKIExtendedKeyUsage',
        'msPKI-Certificate-Application-Policy',
        'msPKI-RA-Signature',
        'msPKI-RA-Application-Policies',
        'msPKI-Certificate-Policy',
        'pKIExpirationPeriod',
        'pKIOverlapPeriod',
        'msPKI-Minimal-Key-Size',
    ]

    if parse_sd:
        attributes.append('nTSecurityDescriptor')
        # SD flags: OWNER_SECURITY_INFORMATION (0x01) + DACL_SECURITY_INFORMATION (0x04)
        controls = security_descriptor_control(sdflags=0x05)
    else:
        controls = None

    try:
        conn._ldap_connection.search(
            search_base=search_base,
            search_filter='(objectClass=pKICertificateTemplate)',
            search_scope=SUBTREE,
            attributes=attributes,
            controls=controls,
        )

        for entry in conn._ldap_connection.response:
            if entry.get('type') != 'searchResEntry':
                continue

            template = CertificateTemplate({
                'dn': entry['dn'],
                'attributes': entry['attributes']
            })

            if parse_sd:
                template.parse_security_descriptor(conn, user_sids)

            templates.append(template)

    except Exception as e:
        logging.error(f"Error retrieving certificate templates: {e}")

    return templates


def get_enrollment_services(conn, parse_sd=True):
    """
    Retrieve all Certificate Authorities (Enrollment Services).

    Args:
        conn: LDAP connection object
        parse_sd: Whether to parse security descriptors for permissions

    Returns:
        List of CertificateAuthority objects
    """
    cas = []
    config_path = conn.configuration_path
    search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_path}"

    attributes = [
        'cn', 'name', 'dNSHostName',
        'cACertificateDN', 'cACertificate',
        'certificateTemplates',
        'objectGUID',
    ]

    controls = None
    if parse_sd:
        attributes.append('nTSecurityDescriptor')
        # SD flags: OWNER_SECURITY_INFORMATION (0x01) + DACL_SECURITY_INFORMATION (0x04)
        controls = security_descriptor_control(sdflags=0x05)

    try:
        conn._ldap_connection.search(
            search_base=search_base,
            search_filter='(objectClass=pKIEnrollmentService)',
            search_scope=SUBTREE,
            attributes=attributes,
            controls=controls,
        )

        for entry in conn._ldap_connection.response:
            if entry.get('type') != 'searchResEntry':
                continue

            ca = CertificateAuthority({
                'dn': entry['dn'],
                'attributes': entry['attributes']
            })

            if parse_sd:
                ca.parse_security_descriptor(conn)

            cas.append(ca)

    except Exception as e:
        logging.error(f"Error retrieving enrollment services: {e}")

    return cas


def get_enrollment_services_dict(conn):
    """
    Retrieve all Certificate Authorities as simple dicts (backward compatibility).

    Args:
        conn: LDAP connection object

    Returns:
        List of dicts with CA information
    """
    cas = get_enrollment_services(conn, parse_sd=False)
    return [
        {
            'dn': ca.dn,
            'name': ca.name,
            'dns_hostname': ca.dns_hostname,
            'ca_certificate_dn': ca.ca_certificate_dn,
            'certificate_templates': ca.certificate_templates,
        }
        for ca in cas
    ]


def get_oid_to_group_links(conn):
    """
    Retrieve OID objects with msDS-OIDToGroupLink for ESC13 detection.

    Args:
        conn: LDAP connection object

    Returns:
        Dict mapping OID string to linked group DN
    """
    links = {}
    config_path = conn.configuration_path
    search_base = f"CN=OID,CN=Public Key Services,CN=Services,{config_path}"

    try:
        conn._ldap_connection.search(
            search_base=search_base,
            search_filter='(msDS-OIDToGroupLink=*)',
            search_scope=SUBTREE,
            attributes=['msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink'],
        )

        for entry in conn._ldap_connection.response:
            if entry.get('type') != 'searchResEntry':
                continue

            attrs = entry['attributes']
            oid = attrs.get('msPKI-Cert-Template-OID', '')
            group_link = attrs.get('msDS-OIDToGroupLink', '')

            if oid and group_link:
                if isinstance(oid, list):
                    oid = oid[0]
                if isinstance(group_link, list):
                    group_link = group_link[0]
                links[oid] = group_link

    except Exception as e:
        logging.debug(f"Error retrieving OID to group links: {e}")

    return links


def check_pki_object_acls(conn, user_sids):
    """
    Check ACLs on PKI AD containers for ESC5.

    Returns:
        List of ESC5 findings (dicts with container, rights, principal)
    """
    findings = []
    if not user_sids:
        return findings

    config_path = conn.configuration_path
    pki_base = f"CN=Public Key Services,CN=Services,{config_path}"
    containers = [
        pki_base,
        f"CN=AIA,{pki_base}",
        f"CN=CDP,{pki_base}",
        f"CN=Certification Authorities,{pki_base}",
        f"CN=Certificate Templates,{pki_base}",
    ]

    try:
        dn_filter = f"(distinguishedName={escape_filter_chars(f'CN=NTAuthCertificates,{pki_base}')})"
        conn._ldap_connection.search(
            search_base=config_path,
            search_filter=dn_filter,
            attributes=['distinguishedName'],
        )
        if conn._ldap_connection.entries:
            containers.append(f"CN=NTAuthCertificates,{pki_base}")
    except Exception:
        pass

    admin_sids = {'S-1-5-18', 'S-1-5-32-544', 'S-1-5-9'}
    user_non_admin = user_sids - admin_sids

    controls = security_descriptor_control(sdflags=0x04)

    for container_dn in containers:
        try:
            conn._ldap_connection.search(
                search_base=container_dn,
                search_filter='(objectClass=*)',
                search_scope=BASE,
                attributes=['nTSecurityDescriptor'],
                controls=controls,
            )

            if not conn._ldap_connection.entries:
                continue

            raw_sd = conn._ldap_connection.entries[0].entry_raw_attributes.get('nTSecurityDescriptor')
            if not raw_sd:
                continue

            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd[0])
            if not sd['Dacl']:
                continue

            for ace in sd['Dacl']['Data']:
                ace_type = ace['AceType']
                if ace_type not in (0x00, 0x05):
                    continue

                sid = ace['Ace']['Sid'].formatCanonical()
                if sid not in user_non_admin:
                    continue

                # Skip admin domain SIDs (-500, -512, -519)
                if sid.endswith('-500') or sid.endswith('-512') or sid.endswith('-519'):
                    continue

                mask = ace['Ace']['Mask']['Mask']
                rights = []
                if mask & GENERIC_ALL:
                    rights.append('GenericAll')
                if mask & WRITE_DACL:
                    rights.append('WriteDACL')
                if mask & WRITE_OWNER:
                    rights.append('WriteOwner')
                if ace_type == 0x00 and (mask & (GENERIC_WRITE | WRITE_PROPERTY)):
                    if mask & GENERIC_WRITE:
                        rights.append('GenericWrite')
                    elif mask & WRITE_PROPERTY:
                        rights.append('WriteProperty')

                if rights:
                    cn = container_dn.split(',')[0].replace('CN=', '')
                    findings.append({
                        'container': cn,
                        'container_dn': container_dn,
                        'sid': sid,
                        'rights': rights,
                    })
        except Exception as e:
            logging.debug(f"Error checking ACL on {container_dn}: {e}")

    return findings


def check_certificate_mapping(conn, auth_info=None):
    """
    Check domain certificate mapping settings for ESC10.

    Reads StrongCertificateBindingEnforcement from DC and
    CertificateMappingMethods from Schannel.

    Returns:
        Dict with settings or None if not accessible
    """
    if not HAS_RRP:
        return None
    if not auth_info:
        auth_info = _extract_auth_info(conn)
    if not auth_info:
        return None

    target = conn.target
    result = {
        'strong_cert_binding': None,
        'cert_mapping_methods': None,
        'vulnerable': False,
    }

    dce = None
    try:
        stringbinding = f'ncacn_np:{target}[\\pipe\\winreg]'
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(
                auth_info.get('username', ''),
                auth_info.get('password', ''),
                auth_info.get('domain', ''),
                auth_info.get('lmhash', ''),
                auth_info.get('nthash', ''),
                auth_info.get('aesKey', ''),
            )
            if auth_info.get('doKerberos'):
                rpctransport.set_kerberos(True, kdcHost=auth_info.get('kdcHost'))

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        resp = rrp.hOpenLocalMachine(dce)
        hRoot = resp['phKey']

        # StrongCertificateBindingEnforcement
        try:
            resp_key = rrp.hBaseRegOpenKey(dce, hRoot,
                'SYSTEM\\CurrentControlSet\\Services\\Kdc')
            hKey = resp_key['phkResult']
            try:
                val = rrp.hBaseRegQueryValue(dce, hKey, 'StrongCertificateBindingEnforcement')
                v = val[1]
                if isinstance(v, bytes):
                    v = int.from_bytes(v[:4], 'little')
                result['strong_cert_binding'] = v
            except Exception:
                result['strong_cert_binding'] = 1  # default
            rrp.hBaseRegCloseKey(dce, hKey)
        except Exception:
            result['strong_cert_binding'] = 1

        # CertificateMappingMethods
        try:
            resp_key = rrp.hBaseRegOpenKey(dce, hRoot,
                'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel')
            hKey = resp_key['phkResult']
            try:
                val = rrp.hBaseRegQueryValue(dce, hKey, 'CertificateMappingMethods')
                v = val[1]
                if isinstance(v, bytes):
                    v = int.from_bytes(v[:4], 'little')
                result['cert_mapping_methods'] = v
            except Exception:
                result['cert_mapping_methods'] = 0x1F  # default (all methods)
            rrp.hBaseRegCloseKey(dce, hKey)
        except Exception:
            result['cert_mapping_methods'] = 0x1F

        rrp.hBaseRegCloseKey(dce, hRoot)

        # Vulnerable if enforcement is disabled OR UPN mapping enabled
        if result['strong_cert_binding'] == 0:
            result['vulnerable'] = True
        if result['cert_mapping_methods'] is not None and (result['cert_mapping_methods'] & 0x04):
            result['vulnerable'] = True

    except Exception as e:
        logging.debug(f"Error checking certificate mapping: {e}")
        return None
    finally:
        if dce:
            try:
                dce.disconnect()
            except Exception:
                pass

    return result


def get_templates_for_ca(ca_entry, all_templates):
    """
    Filter templates that are enabled on a specific CA.

    Args:
        ca_entry: CA dict from get_enrollment_services()
        all_templates: List of all CertificateTemplate objects

    Returns:
        List of CertificateTemplate objects enabled on this CA
    """
    ca_templates = ca_entry.get('certificate_templates', [])
    return [t for t in all_templates if t.name in ca_templates]


def _extract_auth_info(conn):
    """
    Extract authentication info from connection object for RRP.

    Args:
        conn: LDAP connection object

    Returns:
        Dict with auth info or None if not available
    """
    if getattr(conn, '_is_relayed', False):
        logging.warning('[!] Connection is relayed - no stored credentials for RPC operations')
        return None

    try:
        auth_info = {
            'username': getattr(conn, 'ldap_user', ''),
            'password': getattr(conn, 'ldap_pass', ''),
            'domain': getattr(conn, 'domain', ''),
            'lmhash': getattr(conn, 'lmhash', ''),
            'nthash': getattr(conn, 'nthash', ''),
            'aesKey': getattr(conn, 'aesKey', ''),
            'doKerberos': getattr(conn, 'use_kerberos', False),
            'kdcHost': getattr(conn, 'kdcHost', None),
        }
        return auth_info
    except Exception:
        return None


def analyze_adcs(conn, vulnerable_only=False, get_ca_config=True, auth_info=None):
    """
    Perform full ADCS analysis for the current user.

    Args:
        conn: LDAP connection object
        vulnerable_only: If True, only return vulnerable templates
        get_ca_config: If True (default), try to get CA config via RRP
        auth_info: Dict with authentication info for RRP (username, password, domain, etc.)

    Returns:
        Dict with CAs, templates, and summary
    """
    # Get user SIDs first (for enrollment check)
    user_sids = get_user_sids(conn)
    logging.debug(f"Checking enrollment permissions for user ({len(user_sids)} SIDs including groups)")

    # Get OID links for ESC13
    oid_links = get_oid_to_group_links(conn)

    # Get all templates with SD parsing
    templates = get_certificate_templates(conn, parse_sd=True, user_sids=user_sids)

    # Detect vulnerabilities (only for templates user can access)
    for template in templates:
        template.detect_vulnerabilities(conn, oid_links)

    # Get CAs with security descriptor parsing
    cas = get_enrollment_services(conn, parse_sd=True)

    # Always try to get CA configuration via RRP (like certipy does)
    if get_ca_config and HAS_RRP:
        # Extract auth info from connection if not provided
        if auth_info is None:
            auth_info = _extract_auth_info(conn)

        if auth_info:
            for ca in cas:
                if ca.dns_hostname:
                    logging.debug(f"Trying to get CA config for '{ca.name}' via RRP")
                    try:
                        ca.get_ca_config_via_rrp(
                            target=ca.dns_hostname,
                            username=auth_info.get('username', ''),
                            password=auth_info.get('password', ''),
                            domain=auth_info.get('domain', ''),
                            lmhash=auth_info.get('lmhash', ''),
                            nthash=auth_info.get('nthash', ''),
                            aesKey=auth_info.get('aesKey', ''),
                            doKerberos=auth_info.get('doKerberos', False),
                            kdcHost=auth_info.get('kdcHost', None)
                        )
                    except Exception as e:
                        logging.debug(f"Could not get CA config via RRP: {e}")

    # Check Web Enrollment for all CAs
    for ca in cas:
        if ca.dns_hostname:
            try:
                ca.check_web_enrollment()
            except Exception as e:
                logging.debug(f"Could not check web enrollment for {ca.name}: {e}")

    # Map templates to CAs
    for ca in cas:
        ca_template_names = ca.certificate_templates
        for template in templates:
            if template.name in ca_template_names:
                template.enabled_on_cas.append(ca.name)
                template.enabled = True

    # CA-level vulnerability detection (ESC6, ESC7, ESC8, ESC11)
    for ca in cas:
        ca.detect_vulnerabilities(user_sids=user_sids, templates=templates)

    # ESC5: PKI container ACLs
    esc5_findings = []
    try:
        esc5_findings = check_pki_object_acls(conn, user_sids)
    except Exception as e:
        logging.debug(f"ESC5 check failed: {e}")

    # ESC10: Certificate mapping settings
    cert_mapping = None
    if get_ca_config and HAS_RRP:
        try:
            cert_mapping = check_certificate_mapping(conn, auth_info)
        except Exception as e:
            logging.debug(f"ESC10 check failed: {e}")

    # Count stats
    enrollable_count = sum(1 for t in templates if t.can_enroll)
    vuln_count = sum(1 for t in templates if t.is_vulnerable)
    critical_count = sum(1 for t in templates if t.highest_severity == 'Critical')
    ca_vuln_count = sum(1 for ca in cas if ca.is_vulnerable)

    # Filter if needed
    if vulnerable_only:
        templates = [t for t in templates if t.is_vulnerable]

    return {
        'cas': cas,
        'templates': templates,
        'esc5_findings': esc5_findings,
        'cert_mapping': cert_mapping,
        'summary': {
            'total_templates': len(templates) if not vulnerable_only else vuln_count,
            'enrollable_templates': enrollable_count,
            'vulnerable_templates': vuln_count,
            'critical_templates': critical_count,
            'total_cas': len(cas),
            'vulnerable_cas': ca_vuln_count,
            'esc5_findings': len(esc5_findings),
            'esc10_vulnerable': cert_mapping['vulnerable'] if cert_mapping else None,
        }
    }
