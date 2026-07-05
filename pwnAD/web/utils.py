"""Shared utilities for pwnAD web routes."""
import logging

import ldap3

# Re-exported for the route modules (single source of truth in lib.utils).
from pwnAD.lib.utils import LDAP_CONNECTION_ERRORS


def ldap_search_with_retry(conn, search_base, search_filter, attributes,
                           search_scope=ldap3.SUBTREE, size_limit=0, _retry=True):
    """Execute an LDAP search with automatic rebind on connection loss.

    Args:
        conn: LDAPConnection instance
        search_base: LDAP search base DN
        search_filter: LDAP filter string
        attributes: List of attributes to retrieve
        search_scope: LDAP search scope (BASE, LEVEL, SUBTREE)
        size_limit: Maximum number of results (0 = unlimited)
        _retry: Internal flag to prevent infinite retry loops

    Returns:
        tuple: (response list, result dict)

    Raises:
        LDAP_CONNECTION_ERRORS: If connection fails and rebind unsuccessful
    """
    try:
        conn._ldap_connection.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=search_scope,
            attributes=attributes,
            size_limit=size_limit,
        )
        return conn._ldap_connection.response, conn._ldap_connection.result

    except LDAP_CONNECTION_ERRORS as e:
        if _retry:
            logging.warning(f"[*] LDAP connection error: {e}, attempting rebind...")
            if conn.rebind():
                return ldap_search_with_retry(
                    conn, search_base, search_filter, attributes,
                    search_scope, size_limit, _retry=False
                )
        raise
