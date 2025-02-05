# Implementation from @p0dalirius https://github.com/p0dalirius/ldapconsole

import ldap3
import logging
import pwnAD.lib.utils as utils

# LDAP controls
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
LDAP_PAGED_RESULT_OID_STRING = "1.2.840.113556.1.4.319"
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f14f3610-ee22-4d07-8a24-1bf1466cba5f
LDAP_SERVER_NOTIFICATION_OID = "1.2.840.113556.1.4.528"


def query(conn, search_filter, attributes, search_base=None,page_size=1000, size_limit=0, search_scope=ldap3.SUBTREE, raw=False, simple=False, do_print=True):

    results = {}
    try:
        # https://ldap3.readthedocs.io/en/latest/searches.html#the-search-operation
        paged_response = True
        paged_cookie = None
        if search_base == None:
            search_base = conn._baseDN

        while paged_response == True:
            conn._ldap_connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=attributes,
                size_limit=size_limit,
                paged_size=page_size,
                paged_cookie=paged_cookie
            )
            if "controls" in conn._ldap_connection.result.keys():
                if LDAP_PAGED_RESULT_OID_STRING in conn._ldap_connection.result["controls"].keys():
                    next_cookie = conn._ldap_connection.result["controls"][LDAP_PAGED_RESULT_OID_STRING]["value"]["cookie"]
                    if len(next_cookie) == 0:
                        paged_response = False
                    else:
                        paged_response = True
                        paged_cookie = next_cookie
                else:
                    paged_response = False
            else:
                paged_response = False
            for entry in conn._ldap_connection.response:
                if entry["type"] != "searchResEntry":
                    continue
                results[entry["dn"]] = entry["attributes"]
    except ldap3.core.exceptions.LDAPInvalidFilterError as e:
        logging.error("Invalid Filter. (ldap3.core.exceptions.LDAPInvalidFilterError)")
    except ldap3.core.exceptions.LDAPAttributeError as e:
        logging.error("Invalid attribute. (ldap3.core.exceptions.LDAPAttributeError)")
    except Exception as e:
        logging.error(e)
    
    else:
        if raw:
            return results
        elif simple == False:
            utils.format_results(results)
        else:
            simple_results = []
            for _, attributes in results.items():
                for _, value in attributes.items():
                    if isinstance(value, list) and len(value) == 1:
                        print(value[0]) if do_print == True else simple_results.append(value[0])
                    else:
                        print(value) if do_print == True else simple_results.append(value)
            return simple_results

