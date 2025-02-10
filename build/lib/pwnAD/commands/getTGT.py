import logging
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal

from asn1crypto import cms, core
from impacket.krb5.asn1 import (
    AS_REP,
    EncASRepPart,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError, sendReceive

from impacket.krb5.types import Principal
from pyasn1.codec.der import decoder

from pwnAD.lib.kerberos import KRB5_ERROR_MESSAGES
from pwnAD.lib.utils import truncate_key
from pwnAD.lib.logger import logging
from pwnAD.lib.pkinit import PA_PK_AS_REP, Enctype, KDCDHKeyInfo, build_pkinit_as_req



def saveTicket(auth, ticket, sessionKey):
    logging.info('Saving ticket in %s' % (auth.username + '.ccache'))
    from impacket.krb5.ccache import CCache
    ccache = CCache()

    ccache.fromTGT(ticket, sessionKey, sessionKey)
    ccache.saveFile(auth.username + '.ccache')

def getTGT(auth):
    userName = Principal(auth.username, type=auth.principalType.value)
    if not (auth.cert and auth.key):
        try:
            logging.info("Trying to get TGT...")
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName = userName,
                                                                    password = auth.password,
                                                                    domain = auth.domain,
                                                                    lmhash = auth.lmhash,
                                                                    nthash = auth.nthash,
                                                                    aesKey = auth.aesKey,
                                                                    kdcHost = auth.kdcHost,
                                                                    serverName = auth.spn)
            
            saveTicket(auth, tgt, oldSessionKey)
            return tgt, cipher, oldSessionKey, sessionKey

        except Exception as e:
            logging.error(f"An error occurred while trying to get a TGT : {e}")


    else:
        as_req, diffie = build_pkinit_as_req(auth.username, auth.domain, auth.key, auth.cert)

        logging.info("Trying to get TGT...")

        try:
            tgt = sendReceive(as_req, auth.domain, auth.dc_ip)
        except KerberosError as e:
            if e.getErrorCode() not in KRB5_ERROR_MESSAGES:
                logging.error("Got unknown Kerberos error: %#x" % e.getErrorCode())
                return False

            if "KDC_ERR_CLIENT_NAME_MISMATCH" in str(e) and not is_key_credential:
                logging.error(
                    ("Name mismatch between certificate and user %s" % repr(auth.username))
                )
                if id_type is not None:
                    logging.error(
                        ("Verify that the username %s matches the certificate %s: %s")
                        % (repr(auth.username), id_type, identification)
                    )
            elif "KDC_ERR_WRONG_REALM" in str(e) and not is_key_credential:
                logging.error(("Wrong domain name specified %s" % repr(domain)))
                if id_type is not None:
                    logging.error(
                        ("Verify that the domain %s matches the certificate %s: %s")
                        % (repr(domain), id_type, identification)
                    )
            elif "KDC_ERR_CERTIFICATE_MISMATCH" in str(e) and not is_key_credential:
                logging.error(
                    (
                        "Object SID mismatch between certificate and user %s"
                        % repr(auth.username)
                    )
                )
                if object_sid is not None:
                    logging.error(
                        ("Verify that user %s has object SID %s")
                        % (repr(auth.username), repr(object_sid))
                    )
            else:
                logging.error("Got error while trying to request TGT: %s" % str(e))

            return False

        logging.info("Got TGT")

        as_rep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        for pa in as_rep["padata"]:
            if pa["padata-type"] == 17:
                pk_as_rep = PA_PK_AS_REP.load(bytes(pa["padata-value"])).native
                break
        else:
            logging.error("PA_PK_AS_REP was not found in AS_REP")
            return False

        ci = cms.ContentInfo.load(pk_as_rep["dhSignedData"]).native
        sd = ci["content"]
        key_info = sd["encap_content_info"]

        if key_info["content_type"] != "1.3.6.1.5.2.3.2":
            logging.error("Unexpected value for key info content type")
            return False

        auth_data = KDCDHKeyInfo.load(key_info["content"]).native
        pub_key = int(
            "".join(["1"] + [str(x) for x in auth_data["subjectPublicKey"]]), 2
        )
        pub_key = int.from_bytes(
            core.BitString(auth_data["subjectPublicKey"]).dump()[7:],
            "big",
            signed=False,
        )
        shared_key = diffie.exchange(pub_key)

        server_nonce = pk_as_rep["serverDHNonce"]
        full_key = shared_key + diffie.dh_nonce + server_nonce

        etype = as_rep["enc-part"]["etype"]
        cipher = _enctype_table[etype]
        if etype == Enctype.AES256:
            t_key = truncate_key(full_key, 32)
        elif etype == Enctype.AES128:
            t_key = truncate_key(full_key, 16)
        else:
            logging.error("Unexpected encryption type in AS_REP")
            return False

        key = Key(cipher.enctype, t_key)
        enc_data = as_rep["enc-part"]["cipher"]
        dec_data = cipher.decrypt(key, 3, enc_data)
        enc_as_rep_part = decoder.decode(dec_data, asn1Spec=EncASRepPart())[0]

        cipher = _enctype_table[int(enc_as_rep_part["key"]["keytype"])]
        session_key = Key(cipher.enctype, bytes(enc_as_rep_part["key"]["keyvalue"]))

        ccache = CCache()
        ccache.fromTGT(tgt, key, None)

        ccache_name = "%s.ccache" % auth.username.rstrip("$")
        ccache.saveFile(ccache_name)
        logging.info(
            "Saved credential cache to %s" % repr(ccache_name)
        )

        return as_rep, cipher, session_key, t_key
