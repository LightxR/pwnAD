"""
LDAP helper/resolver methods extracted from LDAPConnection.

LDAPHelpersMixin provides high-level lookup utilities on top of a bare
ldap3 connection. It expects the host class to expose:
  - self._ldap_connection  (ldap3.Connection)
  - self._baseDN           (str)
  - self.use_kerberos      (bool | None)
"""
import logging
from typing import Optional

import ldap3
from ldap3.utils.conv import escape_filter_chars


class LDAPHelpersMixin:
    """Mixin of LDAP resolver helpers. Not meant to be instantiated directly."""

    # --- SID utilities -------------------------------------------------------

    def sid_to_str(self, sid) -> str:
        # code from Netexec
        try:
            revision = int(sid[0])
            sub_authorities = int(sid[1])
            identifier_authority = int.from_bytes(sid[2:8], byteorder="big")
            if identifier_authority >= 2 ** 32:
                identifier_authority = hex(identifier_authority)
            sub_authority = "-" + "-".join(
                [str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder="little"))
                 for i in range(sub_authorities)]
            )
            return "S-" + str(revision) + "-" + str(identifier_authority) + sub_authority
        except Exception as e:
            logging.warning(f"Failed to convert SID to string ({e!r}); returning raw value")
        return sid

    def get_domain_sid(self) -> Optional[str]:
        self._ldap_connection.search(
            search_base=self._baseDN,
            search_filter="(&(objectClass=domainDNS))",
            search_scope=ldap3.SUBTREE,
            attributes=['objectSid'],
        )
        if self._ldap_connection.entries:
            domain_sid = self._ldap_connection.entries[0].objectSid.value
            if self.use_kerberos:
                domain_sid = self.sid_to_str(domain_sid)
            return domain_sid
        logging.error("Unable to retrieve domain SID")
        return None

    # --- Primary group / membership ------------------------------------------

    def get_group_from_primary_group_id(self, primary_group_id: int, object_class: str) -> Optional[str]:
        domain_sid = self.get_domain_sid()
        group_sid = f"{domain_sid}-{primary_group_id}"
        search_filter = f"(&(objectClass=group)(objectSid={group_sid}))"
        self._ldap_connection.search(
            search_base=self._baseDN,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['sAMAccountName'],
        )
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].sAMAccountName.value
        logging.error(f"No group found with RID '{primary_group_id}'")
        return None

    # --- sAMAccountName / DN / SID resolvers ---------------------------------

    def ldap_get_user(self, accountName: str):
        self._ldap_connection.search(
            self._baseDN,
            '(sAMAccountName=%s)' % ldap3.utils.conv.escape_filter_chars(accountName),
            attributes=['objectSid'],
        )
        try:
            dn = self._ldap_connection.entries[0].entry_dn
            sid = ldap3.protocol.formatters.formatters.format_sid(
                self._ldap_connection.entries[0]['objectSid'].raw_values[0]
            )
            return dn, sid
        except IndexError:
            logging.error('User not found in LDAP: %s' % accountName)
            return False, ''

    def get_samaccountname_from_dn(self, dn: str, object_class: str) -> Optional[str]:
        search_filter = (
            f"(&(objectClass={escape_filter_chars(object_class)})"
            f"(distinguishedName={escape_filter_chars(dn)}))"
        )
        self._ldap_connection.search(
            search_base=self._baseDN,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['samaccountname'],
        )
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].sAMAccountName.value
        logging.error(f"No sAMAccountName found for DN '{dn}'")
        return None

    def get_samaccountname_from_sid(self, sid: str) -> Optional[str]:
        search_filter = f"(objectSid={escape_filter_chars(sid)})"
        self._ldap_connection.search(
            search_base=self._baseDN,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['samaccountname'],
        )
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].sAMAccountName.value
        logging.error(f"No sAMAccountName found for SID '{sid}'")
        return None

    def get_dn_from_samaccountname(self, samaccountname: str, object_class: str) -> Optional[str]:
        search_filter = (
            f"(&(objectClass={escape_filter_chars(object_class)})"
            f"(sAMAccountName={escape_filter_chars(samaccountname)}))"
        )
        self._ldap_connection.search(
            search_base=self._baseDN,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName'],
        )
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].distinguishedName.value
        logging.error(f"No DN found for sAMAccountName '{samaccountname}'")
        return None

    def get_dn_from_displayname(self, display_name: str, object_class: str) -> Optional[str]:
        search_filter = (
            f"(&(objectClass={escape_filter_chars(object_class)})"
            f"(displayName={escape_filter_chars(display_name)}))"
        )
        self._ldap_connection.search(
            search_base=self._baseDN,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName'],
        )
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].distinguishedName.value
        logging.error(f"No DN found for displayName '{display_name}'")
        return None

    def get_dn_from_sid(self, sid: str) -> Optional[str]:
        search_filter = f"(objectSid={escape_filter_chars(sid)})"
        self._ldap_connection.search(
            search_base=self._baseDN,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName'],
        )
        if self._ldap_connection.entries:
            return self._ldap_connection.entries[0].distinguishedName.value
        logging.error(f"No DN found for SID '{sid}'")
        return None

    def get_sid_info(self, sid: str):
        self._ldap_connection.search(
            self._baseDN,
            '(objectSid=%s)' % escape_filter_chars(sid),
            attributes=['samaccountname'],
        )
        try:
            dn = self._ldap_connection.entries[0].entry_dn
            samname = self._ldap_connection.entries[0]['samaccountname']
            return dn, samname
        except IndexError:
            logging.error('SID not found in LDAP: %s' % sid)
            return False
