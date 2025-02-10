import argparse
import hashlib
import importlib
import logging
import re
import sys
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM, RESULT_ENTRY_ALREADY_EXISTS, RESULT_INSUFFICIENT_ACCESS_RIGHTS, RESULT_NO_SUCH_OBJECT, RESULT_CONSTRAINT_VIOLATION

from pwnAD.lib.certificate import hash_digest, hashes


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
            else:
                self.matches = self.completions.keys()[:]
        try:
            return self.matches[state] + " "
        except IndexError:
            return None


def format_results(results):
    for dn in sorted(list(results.keys())):
        print(dn)
        for key, value in results[dn].items():
            if not isinstance(value,list):
                print(f"  {key} : {value}")
            else:
                print(f"  {key} :")
                for item in value:
                    print(f"    {item}")

def format_list_results(results):
    print("\n")
    for dn in sorted(results):
        print(dn)
    print("\n")
    
def execute_action_function(options, connection):
    # Dynamically import the module based on the action
    module_name = f"pwnAD.commands.{options.action}"
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        print(f"[!] Error loading module {module_name}: {e}")
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
            function_args = {k: v for k, v in vars(options).items() if v is not None and k in function_to_call.__code__.co_varnames}
            function_to_call(connection, **function_args)

    except AttributeError as e:
        print(e)
        sys.exit(1)

def check_error(conn, error_code, e):
    if error_code == RESULT_ENTRY_ALREADY_EXISTS:
        logging.error(f"The entry already exists.")
    elif error_code == RESULT_INSUFFICIENT_ACCESS_RIGHTS:
        logging.error(f"User {conn.user} doesn't have right to perform this action !")
    elif error_code == RESULT_UNWILLING_TO_PERFORM:
        logging.error(f"Server unwilling to perform the operation: {e}")
    elif error_code == RESULT_CONSTRAINT_VIOLATION:
        logging.error(f"Could not modify object, the server reports a constrained violation: \n{e}")
    else:
        logging.error(f"An unexpected error occurred: {e}")

def parse_lm_nt_hashes(lm_nt_hashes_string):
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

def nt_hash(data):
    if type(data) == str:
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