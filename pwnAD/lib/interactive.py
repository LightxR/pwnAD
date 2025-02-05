import logging
import readline
import os
import shlex
import sys

import pwnAD.lib.parser as parser
from pwnAD.lib.auth import Authenticate
from pwnAD.lib.ldap import LDAPConnection
from pwnAD.lib.utils import execute_action_function, Completer
from pwnAD.lib.version import BANNER



def infos(conn):
    logging.info(f"Target: \t{conn.target}")
    logging.info(f"Port: \t{conn.port}")
    logging.info(f"Domain: \t{conn.domain}")
    logging.info(f"User: \t{conn.user if conn.use_kerberos == True and conn.ldap_user == None else conn.ldap_user}")
    logging.info(f"Password: \t{conn.ldap_pass}")
    logging.info(f"LM_hash: \t{conn.lmhash}")
    logging.info(f"NT_hash: \t{conn.nthash}")
    logging.info(f"aesKey: \t{conn.aesKey}")
    logging.info(f"pfx: \t{True if conn.pfx else None}")
    logging.info(f"key: \t{True if (conn.key and not conn.pfx) else None}")
    logging.info(f"cert: \t{True if (conn.cert and not conn.pfx) else None}")
    logging.info(f"kerberos: \t{conn.use_kerberos}")
    logging.info(f"TLS: \t{True if conn._do_tls is not None else False}")


def start_interactive_mode(conn):
    logging.debug("Starting interactive mode")
    print(BANNER)

    shell = True
    interactive_parser = parser.interactive_parser()

    interactive_completer = Completer(interactive_parser)
    readline.set_completer(interactive_completer.complete)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims("\n")


    while shell == True:
        try:

            user_input = input(f"pwnAD [\x1b[31m{conn.user}\x1b[0m]> ").strip()
            if not user_input:
                continue

            if user_input.startswith('!'):
                command_to_run = user_input[1:]
                os.system(command_to_run)
                continue

            user_input_list = shlex.split(user_input)  
            command, arguments = user_input_list[0], user_input_list[1:] # user_input_list[0].lower()
            logging.debug(f"command : {command}, arguments : {arguments}")

            if command == "exit":
                print("See you soon !")
                sys.exit(1)
            
            elif command == "start_tls":
                conn.start_tls()
                continue

            elif command == "rebind":
                try:
                    if conn._ldap_connection.bound:
                        logging.debug("Connection already bound")
                        conn._ldap_connection.unbind()
                    conn._ldap_connection.bind()
                    logging.info("Successfully performed a connection rebind.")

                except Exception as e:
                    try:
                        logging.debug("Simple rebind failed, launching a new connection with the current user and options")
                        new_conn = LDAPConnection(
                            target=conn.target,
                            domain=conn.domain,
                            ldap_user=conn.ldap_user,
                            ldap_pass=conn.ldap_pass,
                            lmhash=conn.lmhash,
                            nthash=conn.nthash,
                            aesKey=conn.aesKey,
                            pfx=conn.pfx,
                            pfx_pass=conn.pfx_pass,
                            key=conn.key,
                            cert=conn.cert,
                            use_kerberos=conn.use_kerberos,
                            kdcHost=conn.kdcHost,
                            _do_tls=conn._do_tls,
                            port=conn.port
                        )
                        new_conn.connect()
                        conn = new_conn
                        logging.info("Successfully performed a connection rebind.")
                    except:
                        logging.error(f"An error occurred when trying to rebind connection : {e}")
                continue

            elif command == "switch_user":
                args = interactive_parser.parse_args([command] + arguments)
                
                domain = conn.domain if args.domain == None else args.domain
                dc_ip = conn.target if args.dc_ip == None else args.dc_ip

                if not args.username and not (args.password or args.hashes or args.aesKey or args.pfx or (args.cert and args.key)):
                    logging.error("You need to provide at least a username and secret to perform switching operation")
                    continue

                try:
                    authenticate = Authenticate(
                        domain=domain,
                        dc_ip=dc_ip,
                        username=args.username,
                        password=args.password,
                        hashes=args.hashes,
                        aesKey=args.aesKey,
                        pfx=args.pfx,
                        pfx_pass=args.pfx_pass,
                        key=args.key,
                        cert=args.cert,
                        use_kerberos=args.use_kerberos,
                        kdcHost=args.kdcHost,
                        _do_tls=args._do_tls,
                        port=args.port
                        )
                        
                    conn = authenticate.ldap_authentication()
                    logging.info(f"Successfully switched user to {args.username}.")

                except Exception as e:
                    logging.error(f"An error occurred when trying to switch user : {e}")
                continue


            elif command == "infos":
                infos(conn)
                continue

            elif command == "help" or (arguments == [] and command not in ["getTGT", "getST", "getNThash", "getPFX"]):
                interactive_parser.print_help()
                continue

            try:
                args = interactive_parser.parse_args([command] + arguments)
                logging.debug(f"Command parsed successfully: {args}")


                if command in ["getTGT", "getST", "getNThash", "getPFX"]:
                    #refactor dirty code
                    domain = conn.domain if args.domain == None else args.domain
                    dc_ip = conn.target if args.dc_ip == None else args.dc_ip

                    if args.username == None:
                        args.username = conn.ldap_user
                        args.password = conn.ldap_pass
                        args.hashes = f"{conn.lmhash}:{conn.nthash}" if conn.nthash is not None else None
                        args.aesKey = conn.aesKey
                        args.pfx = conn.pfx
                        args.pfx_pass = conn.pfx_pass
                        args.key = conn.key
                        args.cert = conn.cert
                        args.use_kerberos = conn.use_kerberos
                        args.kdcHost = conn.kdcHost
                        args._do_tls = conn._do_tls
                        args.port = conn.port

                    authenticate_kwargs = {}
                    if args.action == "getTGT":
                        authenticate_kwargs = {
                            'principalType' : args.principalType,
                            'spn' : args.spn
                        }
                    elif args.action == "getST":
                        authenticate_kwargs = {
                            'spn' : args.spn,
                            'altservice' : args.altservice,
                            'impersonate' : args.impersonate,
                            'additional_ticket' : args.additional_ticket,
                            'u2u' : args.u2u,
                            'no_s4u2proxy' : args.no_s4u2proxy,
                            'force_forwardable' : args.force_forwardable,
                            'renew' : args.renew
        }
                    authenticate = Authenticate(
                        domain=domain,
                        dc_ip=dc_ip,
                        username=args.username,
                        password=args.password,
                        hashes=args.hashes,
                        aesKey=args.aesKey,
                        pfx=args.pfx,
                        pfx_pass=args.pfx_pass,
                        key=args.key,
                        cert=args.cert,
                        use_kerberos=args.use_kerberos,
                        kdcHost=args.kdcHost,
                        _do_tls=args._do_tls,
                        port=args.port,
                        **authenticate_kwargs
                    )
                    authenticate.kerberos_authentication()

                    execute_action_function(args, authenticate)
                else:
                    execute_action_function(args, conn)
            
            except SystemExit:
                pass

        except KeyboardInterrupt as e:
            print("\nAre you sure you want to quit? (Y/N): ", end="", flush=True)
            try:
                confirmation = input().strip().lower()
                if confirmation in ["n", "no", "nooooo"]:
                    print("Resuming interactive mode.")
                    continue  
            except KeyboardInterrupt as e:
                print("\nSee you soon!")
                sys.exit(1) 
            
            print("\nSee you soon!")
            sys.exit(1)  

        except Exception as e:
            logging.error(f"An error has occured : {e}")
            



        
        

