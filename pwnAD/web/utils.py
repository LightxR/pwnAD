"""Shared utilities for pwnAD web routes."""
import logging

import ldap3

# Re-exported for the route modules (single source of truth in lib.utils).
from pwnAD.lib.utils import LDAP_CONNECTION_ERRORS

LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"


def ldap_search_with_retry(conn, search_base, search_filter, attributes,
                           search_scope=ldap3.SUBTREE, size_limit=0, _retry=True):
    """Execute an LDAP search with automatic rebind on connection loss.

    Returns:
        tuple: (response list, result dict)
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


def ldap_search(conn, search_filter, attributes, search_base=None, size_limit=0, _retry=True, controls=None):
    """Execute a paged LDAP search and return list of result dicts.

    Returns:
        list[dict]: Each dict has 'dn' and 'attributes' keys.
    """
    if search_base is None:
        search_base = conn._baseDN

    results = []
    paged_cookie = None

    try:
        while True:
            conn._ldap_connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                paged_size=1000,
                paged_cookie=paged_cookie,
                size_limit=size_limit,
                controls=controls,
            )
            for entry in conn._ldap_connection.response:
                if entry.get('type') != 'searchResEntry':
                    continue
                results.append({
                    'dn': entry['dn'],
                    'attributes': entry['attributes'],
                })

            result_controls = conn._ldap_connection.result.get('controls', {})
            page_control = result_controls.get('1.2.840.113556.1.4.319')
            if page_control:
                cookie = page_control['value']['cookie']
                if cookie:
                    paged_cookie = cookie
                    continue
            break

    except LDAP_CONNECTION_ERRORS as e:
        if _retry:
            logging.warning(f"[*] LDAP connection error: {e}, attempting rebind...")
            if conn.rebind():
                return ldap_search(conn, search_filter, attributes, search_base, size_limit, _retry=False, controls=controls)
        raise

    return results


def ldap_search_deleted(conn, search_filter, attributes, _retry=True):
    """Execute an LDAP search in the Deleted Objects container."""
    deleted_objects_dn = f"CN=Deleted Objects,{conn._baseDN}"
    show_deleted_control = (LDAP_SERVER_SHOW_DELETED_OID, True, None)

    results = []

    try:
        conn._ldap_connection.search(
            search_base=deleted_objects_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            controls=[show_deleted_control],
        )
        for entry in conn._ldap_connection.response:
            if entry.get('type') != 'searchResEntry':
                continue
            results.append({
                'dn': entry['dn'],
                'attributes': entry['attributes'],
            })

    except LDAP_CONNECTION_ERRORS as e:
        if _retry:
            logging.warning(f"[*] LDAP connection error: {e}, attempting rebind...")
            if conn.rebind():
                return ldap_search_deleted(conn, search_filter, attributes, _retry=False)
        raise
    except Exception as e:
        if 'noSuchObject' in str(e):
            logging.debug("Deleted Objects container not found - AD Recycle Bin may not be enabled")
        else:
            raise

    return results
