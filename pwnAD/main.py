import logging
import sys
from pwnAD.lib.auth import Authenticate
from pwnAD.lib.interactive import start_interactive_mode
from pwnAD.lib.utils import execute_action_function
import pwnAD.lib.parser as parser
import pwnAD.lib.logger as logger



def main():
    logger.init()

    options = parser.parseArgs()
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    if options.dc_ip is None:
        return "You need to specify a target with --dc-ip"

    if not options.interactive and (options.action == None or (options.action not in ["query", "getTGT", "getST", "getNThash", "getPFX"] and options.function == None)):
        logging.error("No action or function has been specified, use --help for more information")
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
        
        except Exception as e:
            logging.error(f"Error: {e}")
        
    
    else:
        logging.debug(f"Trying authentication as {options.username} on {options.dc_ip} ... ")
        try:
            connection = authenticate.ldap_authentication()        
            logging.debug("Finishing authentication, starting action now")

            if options.interactive:
                start_interactive_mode(connection)
            else:
                execute_action_function(options, connection)

        except Exception as e:
            logging.error(f"Error: {e}")

if __name__ == "__main__":
    main()