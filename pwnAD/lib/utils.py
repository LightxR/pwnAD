import argparse
import base64
import hashlib
import importlib
import inspect
import logging
import re
import struct
import sys
from typing import Any, Optional, Union
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM, RESULT_ENTRY_ALREADY_EXISTS, RESULT_INSUFFICIENT_ACCESS_RIGHTS, RESULT_NO_SUCH_OBJECT, RESULT_CONSTRAINT_VIOLATION
from ldap3.utils.conv import escape_filter_chars

from pwnAD.lib.certificate import hash_digest, hashes
from pwnAD.lib.constants import (
    WIN_ERROR_PASSWORD_POLICY,
    WIN_ERROR_ACCOUNT_EXISTS,
    WIN_ERROR_PASSWORD_EXPIRED,
    WIN_ERROR_ACCOUNT_LOCKED,
)


class LDAPOperationError(Exception):
    """Exception raised when an LDAP operation fails."""
    pass


class Completer:
    """
    Code logic from @Podalirius ldapconsole tool
    """
    def __init__(self, parser):
        self.parser = parser  
        self.completions = {}

        def parse_action(subparser, command_name):
            subcommands = []
            for action in subparser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    subcommands.extend(action.choices.keys())
            return subcommands

        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for command, subparser in action.choices.items():
                    self.completions[command] = {"subcommands": parse_action(subparser, command)}


    def complete(self, text, state):
        if state == 0:
            if len(text) == 0:
                self.matches = [s for s in self.completions.keys()]
            elif len(text) != 0:

                if text.count(" ") == 0:
                    self.matches = [s for s in self.completions.keys() if s and s.startswith(text)]
                elif text.count(" ") == 1:
                    command, remainder = text.split(" ", 1)
                    if command in self.completions.keys():
                        self.matches = [command + " " + s for s in self.completions[command]["subcommands"] if s and s.startswith(remainder)]
                    else:
                        pass
                else:
                    self.matches = []
        try:
            return self.matches[state] + " "
        except IndexError:
            return None


def format_results(results: dict) -> None:
    for dn in sorted(list(results.keys())):
        print(dn)
        for key, value in results[dn].items():
            if not isinstance(value,list):
                print(f"  {key} : {value}")
            else:
                print(f"  {key} :")
                for item in value:
                    print(f"    {item}")

def format_list_results(results: list) -> None:
    print("\n")
    for dn in sorted(results):
        print(dn)
    print("\n")
    
def execute_action_function(options: Any, connection: Any) -> None:
    # Dynamically import the module based on the action
    module_name = f"pwnAD.commands.{options.action}"
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        logging.error(f"[!] Error loading module {module_name}: {e}")
        sys.exit(1)

    try:
        if options.action in ["getTGT", "getST", "getNThash", "getPFX"]:
            function_to_call = getattr(module, options.action)
            function_to_call(connection)
        else:
            if options.action == "query":
                function_to_call = getattr(module, "query")
            else:
                function_to_call = getattr(module, options.function)
            valid_params = set(inspect.signature(function_to_call).parameters)
            function_args = {k: v for k, v in vars(options).items() if v is not None and k in valid_params}
            function_to_call(connection, **function_args)

    except AttributeError as e:
        logging.error(e)
        sys.exit(1)

def check_error(conn: Any, error_code: int, e: Exception) -> None:
    error_msg = None
    if error_code == RESULT_ENTRY_ALREADY_EXISTS:
        error_msg = "Entry already exists"
    elif error_code == RESULT_INSUFFICIENT_ACCESS_RIGHTS:
        error_msg = f"User '{conn.user}' lacks permissions for this operation"
    elif error_code == RESULT_UNWILLING_TO_PERFORM:
        # Parse Windows error codes from LDAP message for more specific errors
        error_str = str(e)
        if WIN_ERROR_PASSWORD_POLICY in error_str:
            error_msg = "Password does not meet the domain password policy requirements"
        elif WIN_ERROR_ACCOUNT_EXISTS in error_str:
            error_msg = "Account already exists"
        elif WIN_ERROR_PASSWORD_EXPIRED in error_str:
            error_msg = "Password expired"
        elif WIN_ERROR_ACCOUNT_LOCKED in error_str:
            error_msg = "Account is locked out"
        else:
            error_msg = "Server refused the operation (possible causes: insufficient permissions, policy violation, no secure connection)"
            logging.debug(f"LDAP error details: {e}")
    elif error_code == RESULT_CONSTRAINT_VIOLATION:
        error_msg = f"Constraint violation: {e}"
    else:
        error_msg = f"Unexpected error: {e}"

    logging.debug(f"LDAP operation failed: {error_msg}")
    raise LDAPOperationError(error_msg)

def parse_lm_nt_hashes(lm_nt_hashes_string: Optional[str]) -> tuple[str, str]:
    lm_hash_value = "aad3b435b51404eeaad3b435b51404ee"
    nt_hash_value = "31d6cfe0d16ae931b73c59d7e0c089c0"
    
    if lm_nt_hashes_string:
        matched = re.match(r"^([0-9a-f]{32})?(:?)([0-9a-f]{32})?$", lm_nt_hashes_string.strip().lower())
        
        if matched:
            m_lm_hash, m_sep, m_nt_hash = matched.groups()
            
            if m_lm_hash:
                lm_hash_value = m_lm_hash
            if m_nt_hash:
                nt_hash_value = m_nt_hash
            elif not m_lm_hash and m_sep == ":":
                lm_hash_value = "aad3b435b51404eeaad3b435b51404ee" 

    return lm_hash_value, nt_hash_value

def nt_hash(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = bytes(data, 'utf-16-le')

    ctx = hashlib.new('md4', data)
    nt_hash_value = ctx.hexdigest()

    return nt_hash_value


def to_pascal_case(snake_str: str) -> str:
    components = snake_str.split("_")
    return "".join(x.title() for x in components)


def truncate_key(value: bytes, keysize: int) -> bytes:
    output = b""
    current_num = 0
    while len(output) < keysize:
        current_digest = hash_digest(bytes([current_num]) + value, hashes.SHA1)
        if len(output) + len(current_digest) > keysize:
            output += current_digest[: keysize - len(output)]
            break
        output += current_digest
        current_num += 1

    return output


def resolve_target(conn, target: str) -> str | None:
    """
    Resolve an identifier (sAMAccountName, DN, or SID) to its Distinguished Name.

    This function provides universal target resolution for LDAP operations,
    accepting multiple identifier formats and returning the canonical DN.

    Args:
        conn: LDAP connection object (LDAPConnection instance)
        target: Target identifier in one of the following formats:
                - Distinguished Name (starts with CN=, OU=, or DC=)
                - SID (starts with S-1-)
                - sAMAccountName (any other string)

    Returns:
        str: The Distinguished Name of the target object
        None: If the target could not be resolved

    Example:
        >>> resolve_target(conn, "Administrator")
        "CN=Administrator,CN=Users,DC=corp,DC=local"
        >>> resolve_target(conn, "S-1-5-21-xxx-500")
        "CN=Administrator,CN=Users,DC=corp,DC=local"
        >>> resolve_target(conn, "CN=Admin,CN=Users,DC=corp,DC=local")
        "CN=Admin,CN=Users,DC=corp,DC=local"
    """
    target = target.strip()
    target_lower = target.lower()

    # Case 1: Already a DN (starts with cn=, ou=, or dc=)
    if target_lower.startswith("cn=") or target_lower.startswith("ou=") or target_lower.startswith("dc="):
        # Verify the DN exists
        conn._ldap_connection.search(
            search_base=conn._baseDN,
            search_filter=f"(distinguishedName={escape_filter_chars(target)})",
            attributes=['distinguishedName']
        )
        if conn._ldap_connection.entries:
            return conn._ldap_connection.entries[0].distinguishedName.value
        else:
            logging.error(f"DN not found: {target}")
            return None

    # Case 2: SID (starts with S-1-)
    if target.startswith("S-1-"):
        conn._ldap_connection.search(
            search_base=conn._baseDN,
            search_filter=f"(objectSid={escape_filter_chars(target)})",
            attributes=['distinguishedName']
        )
        if conn._ldap_connection.entries:
            return conn._ldap_connection.entries[0].distinguishedName.value
        else:
            logging.error(f"SID not found: {target}")
            return None

    # Case 3: sAMAccountName (default)
    conn._ldap_connection.search(
        search_base=conn._baseDN,
        search_filter=f"(sAMAccountName={escape_filter_chars(target)})",
        attributes=['distinguishedName']
    )
    if conn._ldap_connection.entries:
        return conn._ldap_connection.entries[0].distinguishedName.value
    else:
        logging.error(f"sAMAccountName not found: {target}")
        return None


def encode_ldap_value(attribute: str, value: str, raw: bool = False, b64: bool = False):
    """
    Encode a value for LDAP modification based on the attribute type.

    This function handles automatic encoding for special AD attributes
    that require specific formats (UTF-16-LE, binary SID, etc.).

    Args:
        attribute: Name of the LDAP attribute being modified
        value: Value to encode (as string)
        raw: If True, return value as-is without encoding (default: False)
        b64: If True, decode value from base64 first (default: False)

    Returns:
        The encoded value ready for LDAP modification

    Special encodings:
        - unicodePwd: UTF-16-LE with surrounding quotes
        - userAccountControl: Integer
        - pwdLastSet: Integer
        - accountExpires: Integer
        - Other: String (default)
    """
    # First, handle base64 decoding if requested
    if b64:
        try:
            value = base64.b64decode(value)
            if raw:
                return value
        except Exception as e:
            logging.error(f"Failed to decode base64 value: {e}")
            return None

    # If raw mode, return as-is (or decoded bytes if b64 was used)
    if raw:
        return value

    attribute_lower = attribute.lower()

    # Special handling for unicodePwd (password changes)
    if attribute_lower == "unicodepwd":
        # Password must be enclosed in quotes and encoded as UTF-16-LE
        return f'"{value}"'.encode('utf-16-le')

    # Integer attributes
    integer_attributes = [
        "useraccountcontrol",
        "pwdlastset",
        "accountexpires",
        "logoncount",
        "badpwdcount",
        "primarygroupid",
        "msds-supportedencryptiontypes",
        "samaccounttype"
    ]
    if attribute_lower in integer_attributes:
        try:
            return int(value)
        except ValueError:
            logging.error(f"Invalid integer value for {attribute}: {value}")
            return None

    # Default: return as string
    return value