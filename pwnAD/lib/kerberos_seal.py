"""
GSS-API / Kerberos SASL sealing socket wrapper for LDAP.

Applies per-PDU confidentiality and integrity protection to all LDAP
traffic using impacket's GSSAPI implementation (AES-128/256 or RC4-HMAC).

SASL wire framing: each PDU is prefixed with a 4-byte big-endian length.
"""
import struct


class KerberosSealSocket:
    """
    Socket wrapper that applies GSS-API sealing to all LDAP PDUs.

    Delegates to impacket's GSSAPI_AES* (RFC 4121, key_usages 22/24) or
    GSSAPI_RC4 (RFC 4757 old-format tokens) depending on the session cipher,
    ensuring the correct wire format for each enctype.
    """

    def __init__(self, sock, gss, session_key):
        self._sock = sock
        self._gss = gss
        self._session_key = session_key
        self._seq_num = 0
        self._buf = b''

    def _wrap(self, data: bytes) -> bytes:
        payload, header = self._gss.GSS_Wrap_LDAP(self._session_key, data, self._seq_num)
        self._seq_num += 1
        return header + payload

    def _unwrap(self, token: bytes) -> bytes:
        from impacket.krb5.gssapi import GSSAPI_RC4
        if isinstance(self._gss, GSSAPI_RC4):
            # impacket's MechIndepToken.from_bytes() has an off-by-one BER length
            # bug: for tokens with single-byte length encoding (content < 128 bytes)
            # it does not advance past the length byte, so the WRAP header is parsed
            # 4 bytes off → wrong SGN_CKSUM/SND_SEQ → wrong Kcrypt → garbage output.
            # Bypass it and parse the BER structure ourselves.
            return self._unwrap_rc4(token)
        data, _ = self._gss.GSS_Unwrap_LDAP(self._session_key, token, 0)
        return data

    def _unwrap_rc4(self, data: bytes) -> bytes:
        """Correct RC4-HMAC GSS_Unwrap for LDAP tokens (RFC 4757)."""
        from Cryptodome.Hash import HMAC as _HMAC, MD5 as _MD5
        from Cryptodome.Cipher import ARC4 as _ARC4

        # Parse outer GSSAPI APPLICATION token:
        # 0x60 [BER_len] 0x06 [oid_len] [oid_bytes] [WRAP_token]
        if not data or data[0] != 0x60:
            raise ValueError(f'Expected GSSAPI APPLICATION tag 0x60, got 0x{data[0]:02x}')
        i = 1
        if data[i] < 0x80:
            i += 1                      # single-byte length — skip it
        else:
            i += 1 + (data[i] & 0x7f)  # multi-byte — skip the extra length bytes too
        if data[i] != 0x06:
            raise ValueError(f'Expected OID tag 0x06, got 0x{data[i]:02x}')
        i += 2 + data[i + 1]            # skip OID tag + length + value

        # RC4 WRAP token layout (32-byte header + ciphertext):
        #   [0:2]   TOK_ID      (0x0102)
        #   [2:4]   SGN_ALG     (0x0000 = HMAC-MD5)
        #   [4:6]   SEAL_ALG    (0x0010 = RC4)
        #   [6:8]   Filler      (0xffff)
        #   [8:16]  SND_SEQ     (enc sequence number, 8 bytes)
        #   [16:24] SGN_CKSUM   (HMAC signature, 8 bytes)
        #   [24:32] Confounder  (encrypted, 8 bytes)
        #   [32:]   Ciphertext  (encrypted data + trailing 0x01 byte)
        wrap = data[i:]
        sgn_cksum = wrap[16:24]
        snd_seq_enc = wrap[8:16]
        confounder = wrap[24:32]
        ciphertext = wrap[32:]

        key = self._session_key
        Klocal = bytes(b ^ 0xF0 for b in key.contents)

        Kseq = _HMAC.new(key.contents, b'\x00\x00\x00\x00', _MD5).digest()
        Kseq = _HMAC.new(Kseq, sgn_cksum, _MD5).digest()
        snd_seq = _ARC4.new(Kseq).encrypt(snd_seq_enc)

        Kcrypt = _HMAC.new(Klocal, b'\x00\x00\x00\x00', _MD5).digest()
        Kcrypt = _HMAC.new(Kcrypt, snd_seq[:4], _MD5).digest()

        # Feed enc_confounder to advance RC4 state, then decrypt ciphertext from pos 8
        plaintext = _ARC4.new(Kcrypt).decrypt(confounder + ciphertext)[8:]
        return plaintext[:-1]  # strip trailing 0x01 added by GSS_Wrap_LDAP

    def sendall(self, data: bytes, *args, **kwargs) -> None:
        wrapped = self._wrap(data)
        return self._sock.sendall(struct.pack('>I', len(wrapped)) + wrapped, *args, **kwargs)

    def send(self, data: bytes, *args, **kwargs) -> int:
        wrapped = self._wrap(data)
        frame = struct.pack('>I', len(wrapped)) + wrapped
        sent = self._sock.send(frame, *args, **kwargs)
        return len(data) if sent == len(frame) else 0

    def recv(self, bufsize: int, *args, **kwargs) -> bytes:
        while len(self._buf) < 4:
            chunk = self._sock.recv(4096)
            if not chunk:
                return b''
            self._buf += chunk
        msg_len = struct.unpack('>I', self._buf[:4])[0]
        self._buf = self._buf[4:]
        while len(self._buf) < msg_len:
            chunk = self._sock.recv(4096)
            if not chunk:
                return b''
            self._buf += chunk
        wrapped, self._buf = self._buf[:msg_len], self._buf[msg_len:]
        return self._unwrap(wrapped)

    def __getattr__(self, name: str):
        return getattr(self._sock, name)


# Backward-compatible alias (was _KerberosSealSocket in ldap.py)
_KerberosSealSocket = KerberosSealSocket
