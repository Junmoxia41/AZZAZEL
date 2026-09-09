#!/usr/bin/env python3
"""
AZZAZEL VPN — security/ntlm.py
==============================

Autenticación **NTLMv2 nativa** (protocolo MS-NLMP) para hablar con
proxies corporativos estrictos SIN depender de relays externos
(cntlm/px).

Contenido del módulo:

- :class:`MD4` — implementación pura en Python. Es obligatoria porque
  OpenSSL ≥ 3.0 retiró MD4 del provider por defecto y ``hashlib`` ya no
  lo ofrece. MD4 es criptográficamente débil como hash de propósito
  general, pero es parte INELUDIBLE del protocolo NTLM (se usa para el
  NT hash); aquí solo se emplea dentro de MS-NLMP.
- ``hmac_md5`` / ``hmac_gen`` — HMAC genérico sobre cualquier clase de
  hash estilo hashlib (sin depender del provider de OpenSSL).
- Mensajes del handshake (MS-NLMP):
    - :func:`build_type1`  NEGOTIATE (cliente → servidor)
    - :func:`parse_type2`  CHALLENGE (servidor → cliente)
    - :func:`build_type3`  AUTHENTICATE con respuestas **NTLMv2/LMv2**
      (cliente → servidor)
- :func:`nt_hash`, :func:`ntlmv2_hash` y :func:`split_credentials` como
  helpers reutilizables.

Flujo NTLMv2 (simplificado)::

    NT-hash      = MD4( UTF-16LE(password) )
    NTLMv2-hash  = HMAC-MD5( NT-hash, UTF-16LE(UPPER(user) + domain) )
    blob         = 0x01010000 ‖ 0*4 ‖ FILETIME ‖ client_nonce ‖ 0*4
                   ‖ target_info(del servidor) ‖ 0*4
    NT-proof     = HMAC-MD5( NTLMv2-hash, server_challenge ‖ blob )
    NTLMv2-resp  = NT-proof ‖ blob
    LMv2-resp    = HMAC-MD5( NTLMv2-hash, server_chal ‖ client_nonce )
                   ‖ client_nonce

Consumidor principal: ``proxy/upstream_proxy.py`` con
``auth_type: ntlm`` en config.yaml.

Demo autocontenida (vectores MD4/HMAC + handshake completo contra un
fake proxy NTLM local)::

    python security/ntlm.py
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.logger import get_logger

__all__ = [
    "NtlmError",
    "MD4",
    "hmac_gen",
    "hmac_md5",
    "nt_hash",
    "ntlmv2_hash",
    "split_credentials",
    "NtlmChallenge",
    "build_type1",
    "parse_type2",
    "build_type3",
]

_log = get_logger("security.ntlm")

SIGNATURE = b"NTLMSSP\x00"
WORKSTATION_NAME = "AZZAZEL"


class NtlmError(Exception):
    """Mensaje NTLM malformado o escenario no soportado."""


# ---------------------------------------------------------------------------
# MD4 (RFC 1320) — implementación pura
# ---------------------------------------------------------------------------
def _lrot(value: int, bits: int) -> int:
    """Rotación circular de 32 bits a la izquierda."""
    value &= 0xFFFFFFFF
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


class MD4:
    """Hash MD4 (RFC 1320) con API estilo ``hashlib``.

    Atributos compatibles: ``digest_size`` (16), ``block_size`` (64),
    ``name`` ("md4"); métodos ``update()``, ``digest()``,
    ``hexdigest()`` y ``copy()``.

    MD4 es roto para uso general; aquí existe EXCLUSIVAMENTE porque
    NTLM lo requiere para el NT hash (MS-NLMP §3.3.1).
    """

    digest_size: int = 16
    block_size: int = 64
    name: str = "md4"

    _S1 = [3, 7, 11, 19] * 4
    _S2 = [3, 5, 9, 13] * 4
    _S3 = [3, 9, 11, 15] * 4
    _K1 = list(range(16))
    _K2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    _K3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]

    def __init__(self, data: bytes = b"") -> None:
        self._state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        self._buffer = b""
        self._count = 0  # bytes totales procesados (para el padding)
        if data:
            self.update(data)

    def update(self, data: bytes) -> "MD4":
        """Alimenta datos al hash (encadenable)."""
        self._count += len(data)
        self._buffer += data
        while len(self._buffer) >= 64:
            self._compress(self._buffer[:64])
            self._buffer = self._buffer[64:]
        return self

    def copy(self) -> "MD4":
        """Copia independiente del estado actual."""
        clone = MD4()
        clone._state = list(self._state)
        clone._buffer = self._buffer
        clone._count = self._count
        return clone

    @staticmethod
    def _f(x: int, y: int, z: int) -> int:
        return ((x & y) | (~x & z)) & 0xFFFFFFFF

    @staticmethod
    def _g(x: int, y: int, z: int) -> int:
        return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF

    @staticmethod
    def _h(x: int, y: int, z: int) -> int:
        return (x ^ y ^ z) & 0xFFFFFFFF

    def _compress(self, block: bytes) -> None:
        words = list(struct.unpack("<16I", block))
        v = list(self._state)

        def step(func, k: int, s: int, const: int, i: int) -> None:
            t = (-i) % 4  # ronda rodante A→D→C→B
            v[t] = _lrot(
                v[t] + func(v[(t + 1) % 4], v[(t + 2) % 4], v[(t + 3) % 4])
                + words[k] + const, s,
            )

        for i, k in enumerate(self._K1):
            step(self._f, k, self._S1[i], 0x00000000, i)
        for i, k in enumerate(self._K2):
            step(self._g, k, self._S2[i], 0x5A827999, i)
        for i, k in enumerate(self._K3):
            step(self._h, k, self._S3[i], 0x6ED9EBA1, i)

        self._state = [(a + b) & 0xFFFFFFFF
                       for a, b in zip(self._state, v)]

    def digest(self) -> bytes:
        """Finaliza y devuelve los 16 bytes de huella (no muta estado)."""
        clone = self.copy()
        bit_len = clone._count * 8
        pending = clone._buffer + b"\x80"
        # Ceros hasta que longitud ≡ 56 (mod 64); luego 8B de longitud.
        pending += b"\x00" * ((56 - len(pending)) % 64)
        pending += struct.pack("<Q", bit_len)
        clone.update(pending[len(clone._buffer):])
        return struct.pack("<4I", *clone._state)

    def hexdigest(self) -> str:
        """Huella como cadena hexadecimal."""
        return self.digest().hex()


# ---------------------------------------------------------------------------
# HMAC genérico (RFC 2104) — independiente del provider OpenSSL
# ---------------------------------------------------------------------------
def hmac_gen(hash_cls, key: bytes, message: bytes) -> bytes:
    """HMAC sobre cualquier callable hash estilo hashlib (MD4, MD5...).

    Args:
        hash_cls: Constructor de hash (``hashlib.md5``, :class:`MD4`…)
            cuyas instancias exponen ``block_size`` y ``digest()``.
        key: Clave HMAC.
        message: Mensaje a autenticar.

    Returns:
        Los bytes del MAC.
    """
    block_size = hash_cls().block_size  # instancia → atributo seguro
    if len(key) > block_size:
        key = hash_cls(key).digest()
    key = key.ljust(block_size, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = hash_cls(ipad + message).digest()
    return hash_cls(opad + inner).digest()


def hmac_md5(key: bytes, message: bytes) -> bytes:
    """HMAC-MD5 (wrapper de :func:`hmac_gen` con ``hashlib.md5``)."""
    return hmac_gen(hashlib.md5, key, message)


# ---------------------------------------------------------------------------
# Primitivas NTLMv2
# ---------------------------------------------------------------------------
def nt_hash(password: str) -> bytes:
    """NT hash: ``MD4(UTF-16LE(password))`` — MS-NLMP §3.3.1."""
    return MD4(password.encode("utf-16-le")).digest()


def ntlmv2_hash(user: str, password: str, domain: str) -> bytes:
    """Clave NTLMv2: ``HMAC-MD5(NT-hash, UTF-16LE(UPPER(user)+domain))``."""
    identity = (user.upper() + domain).encode("utf-16-le")
    return hmac_md5(nt_hash(password), identity)


def split_credentials(username: str, domain: str = "") -> tuple[str, str]:
    """Normaliza credenciales ``DOMINIO\\usuario`` → ``(dominio, usuario)``.

    El dominio explícito del parámetro gana al embebido en el usuario.
    """
    if domain:
        return domain, username.split("\\", 1)[-1]
    if "\\" in username:
        dom, user = username.split("\\", 1)
        return dom, user
    return "", username


# ---------------------------------------------------------------------------
# Mensajes MS-NLMP
# ---------------------------------------------------------------------------
# Flags de negociación (subconjunto relevante para proxy-auth NTLMv2)
FLAG_UNICODE = 0x00000001
FLAG_OEM = 0x00000002
FLAG_REQUEST_TARGET = 0x00000004
FLAG_SIGN = 0x00000010
FLAG_NTLM = 0x00000200
FLAG_DOMAIN_SUPPLIED = 0x00001000
FLAG_WORKSTATION_SUPPLIED = 0x00002000
FLAG_ALWAYS_SIGN = 0x00008000
FLAG_NTLM2_KEY = 0x00080000  # extended session security
FLAG_TARGET_INFO = 0x00800000
FLAG_VERSION = 0x02000000
FLAG_128BIT = 0x20000000
FLAG_56BIT = 0x80000000

_BASE_FLAGS = (
    FLAG_UNICODE | FLAG_OEM | FLAG_REQUEST_TARGET | FLAG_NTLM
    | FLAG_ALWAYS_SIGN | FLAG_NTLM2_KEY | FLAG_TARGET_INFO
    | FLAG_VERSION | FLAG_128BIT | FLAG_56BIT
)

# VERSION de MS-NLMP: major(1) minor(1) build(2) reserved(3) revision(1)
# = 8 bytes EXACTOS. (Un int de 4B en reserved rompería todos los
# offsets de payload posteriores — bug detectado por la batería QA.)
_OS_VERSION = struct.pack("<BBH3sB", 6, 1, 7601, b"\x00\x00\x00", 15)
assert len(_OS_VERSION) == 8


def _self_check_offsets() -> None:
    """Saneamiento interno: los builders deben ser byte-coherentes.

    Verifica que cada security-buffer declare offsets que encadenan
    exactamente hasta el final del mensaje (detecta corrupciones de
    cabecera como la del VERSION de 9 bytes). Se ejecuta en import solo
    la primera vez; es barato (~µs) y blinda regresiones futuras.
    """
    t1 = build_type1("TESTDOM")
    dom = struct.unpack_from("<HHI", t1, 16)
    wks = struct.unpack_from("<HHI", t1, 24)
    assert dom[2] == 40 and wks[2] == dom[2] + dom[0]
    assert len(t1) == wks[2] + wks[0], "Type1: offsets no cierran"

    chal = NtlmChallenge(server_challenge=b"\x00" * 8, flags=0,
                         target_name="", target_info=b"")
    t3 = build_type3("u", "p", "D", chal, client_nonce=b"\x00" * 8,
                     filetime=0)
    total = 72
    for i in range(6):
        ln, _, off = struct.unpack_from("<HHI", t3, 12 + 8 * i)
        assert off == total, f"Type3: campo {i} mal anclado"
        total += ln
    assert len(t3) == total, "Type3: offsets no cierran"


def _sec_field(data: bytes, offset: int) -> bytes:
    """Security buffer de NTLM: len/maxlen/offset (8 bytes)."""
    return struct.pack("<HHI", len(data), len(data), offset)


def build_type1(domain: str = "",
                workstation: str = WORKSTATION_NAME) -> bytes:
    """Construye el mensaje Type 1 (NEGOTIATE_MESSAGE).

    Args:
        domain: Dominio NT si se conoce (se envía en Type 1 para que el
            servidor no tenga que adivinarlo).
        workstation: Nombre de estación de trabajo a anunciar.

    Returns:
        Mensaje binario listo para base64 + header.
    """
    flags = _BASE_FLAGS
    dom_b = domain.upper().encode("ascii", errors="ignore")
    wks_b = workstation.upper().encode("ascii", errors="ignore")
    if dom_b:
        flags |= FLAG_DOMAIN_SUPPLIED
    if wks_b:
        flags |= FLAG_WORKSTATION_SUPPLIED

    offset = 40  # cabecera fija con VERSION incluido
    message = bytearray()
    message += SIGNATURE
    message += struct.pack("<I", 1)
    message += struct.pack("<I", flags)
    message += _sec_field(dom_b, offset)
    offset += len(dom_b)
    message += _sec_field(wks_b, offset)
    offset += len(wks_b)
    message += _OS_VERSION
    message += dom_b + wks_b
    return bytes(message)


@dataclass(frozen=True)
class NtlmChallenge:
    """Mensaje Type 2 (CHALLENGE_MESSAGE) parseado.

    Attributes:
        server_challenge: Nonce de 8 bytes del servidor.
        flags: Flags negociados por el servidor.
        target_name: Nombre del objetivo (puede ser vacío).
        target_info: Blob AV_PAIR del servidor (se reutiliza íntegro
            dentro del blob NTLMv2).
    """

    server_challenge: bytes
    flags: int
    target_name: str
    target_info: bytes


def parse_type2(data: bytes) -> NtlmChallenge:
    """Parsea el CHALLENGE_MESSAGE del servidor.

    Raises:
        NtlmError: Firma inválida, tipo incorrecto, mensaje truncado o
            ausencia de ``NTLMSSP_NEGOTIATE_NTLM``.
    """
    if len(data) < 32:
        raise NtlmError(f"Type 2 truncado ({len(data)} bytes).")
    if not data.startswith(SIGNATURE):
        raise NtlmError("Firma NTLMSSP inválida en Type 2.")
    msg_type = struct.unpack_from("<I", data, 8)[0]
    if msg_type != 2:
        raise NtlmError(f"Se esperaba Type 2, recibido Type {msg_type}.")
    flags = struct.unpack_from("<I", data, 20)[0]
    if not flags & FLAG_NTLM:
        raise NtlmError("El servidor no negocia NTLM (flag 0x200 ausente).")
    server_challenge = data[24:32]

    target_name = ""
    tname_len, _, tname_off = struct.unpack_from("<HHI", data, 12)
    if tname_len and tname_off + tname_len <= len(data):
        raw = data[tname_off:tname_off + tname_len]
        enc = "utf-16-le" if flags & FLAG_UNICODE else "ascii"
        target_name = raw.decode(enc, errors="replace").rstrip("\x00")

    target_info = b""
    if flags & FLAG_TARGET_INFO and len(data) >= 48:
        ti_len, _, ti_off = struct.unpack_from("<HHI", data, 40)
        if ti_len and ti_off + ti_len <= len(data):
            target_info = data[ti_off:ti_off + ti_len]

    return NtlmChallenge(
        server_challenge=server_challenge, flags=flags,
        target_name=target_name, target_info=target_info,
    )


def build_type3(
    user: str,
    password: str,
    domain: str,
    challenge: NtlmChallenge,
    *,
    workstation: str = WORKSTATION_NAME,
    client_nonce: Optional[bytes] = None,
    filetime: Optional[int] = None,
) -> bytes:
    """Construye el AUTHENTICATE_MESSAGE con respuestas NTLMv2/LMv2.

    Args:
        challenge: Type 2 parseado del servidor.
        client_nonce: 8 bytes aleatorios (inyectable para tests
            deterministas).
        filetime: Timestamp Windows FILETIME inyectable para tests.

    Returns:
        Mensaje Type 3 binario.
    """
    v2hash = ntlmv2_hash(user, password, domain)
    nonce = client_nonce or secrets.token_bytes(8)
    stamp = filetime if filetime is not None else int(
        (time.time() + 11644473600) * 10_000_000
    )

    blob = (
        b"\x01\x01\x00\x00"            # resp_data (versión blob NTLMv2)
        + b"\x00\x00\x00\x00"          # hi_resp_data
        + struct.pack("<Q", stamp)     # timestamp FILETIME
        + nonce                        # challenge del cliente
        + b"\x00\x00\x00\x00"          # reservado
        + challenge.target_info        # AV pairs del servidor, íntegros
        + b"\x00\x00\x00\x00"          # terminador
    )
    nt_proof = hmac_md5(v2hash, challenge.server_challenge + blob)
    nt_response = nt_proof + blob
    lm_response = hmac_md5(
        v2hash, challenge.server_challenge + nonce
    ) + nonce

    dom_b = domain.encode("utf-16-le")
    usr_b = user.encode("utf-16-le")
    wks_b = workstation.encode("utf-16-le")
    session_key = b""  # proxy-auth no requiere clave de sesión

    payload_parts = [lm_response, nt_response, dom_b, usr_b, wks_b,
                     session_key]
    offset = 72  # 8 sig + 4 type + 6×8 fields + 4 flags + 8 version
    message = bytearray()
    message += SIGNATURE
    message += struct.pack("<I", 3)
    for part in payload_parts:
        message += _sec_field(part, offset)
        offset += len(part)
    message += struct.pack("<I", challenge.flags)
    message += _OS_VERSION
    for part in payload_parts:
        message += part
    return bytes(message)


# ---------------------------------------------------------------------------
# Base64 helpers para headers HTTP
# ---------------------------------------------------------------------------
def b64_encode(message: bytes) -> str:
    """Base64 estándar lista para ``Proxy-Authorization: NTLM ...``."""
    return base64.b64encode(message).decode("ascii")


def b64_decode(token: str) -> bytes:
    """Decodifica el token NTLM de un header (tolerante con espacios)."""
    try:
        return base64.b64decode(token.strip(), validate=False)
    except Exception as exc:
        raise NtlmError("Token NTLM base64 inválido en la respuesta.") from exc


# ---------------------------------------------------------------------------
# Demo standalone
# ---------------------------------------------------------------------------
_self_check_offsets()  # auto-chequeo de coherencia binaria en import


def _check_md4_vectors() -> None:
    """Vectores oficiales RFC 1320 (¡MD4 pura verificada!)."""
    vectors = {
        b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
        b"a": "bde52cb31de33e46245e05fbdbd6fb24",
        b"abc": "a448017aaf21d8525fc10ae87aa6729d",
        b"message digest": "d9130a8164549fe818874806e1c7014b",
        b"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
            "043f8582f241db351ce627e153e7f0e4",
        b"12345678901234567890123456789012345678901234567890123456789012"
        b"345678901234567890": "e33b4ddc9c38f2199c3e7b164fcc0536",
    }
    for data, expected in vectors.items():
        got = MD4(data).hexdigest()
        assert got == expected, (data, got)
    # API hashlib-like: update encadenado
    h = MD4()
    h.update(b"ab").update(b"c")
    assert h.hexdigest() == vectors[b"abc"]
    print("    ✔ MD4: 7/7 vectores RFC 1320 + encadenado")

    # NT hash de valores publicados (MS-NLMP docs / referencias hashcat):
    published = {
        "Password": "a4f49c406510bdcab6824ee7c30fd852",
        "password": "8846f7eaee8fb117ad06bdd830b7586c",
    }
    for password, expected in published.items():
        got = nt_hash(password).hex()
        assert got == expected, (password, got)
    print("    ✔ NT hash: 'Password'→a4f49c40… y 'password'→8846f7ea… "
          "(valores publicados)")


def _demo() -> None:
    import asyncio

    _check_md4_vectors()

    # HMAC-MD5 RFC 2202 (caso 1): key=0x0b*16, "Hi There"
    got = hmac_md5(b"\x0b" * 16, b"Hi There").hex()
    assert got == "9294727a3638bb1c13f48ef8158bfc9d", got
    print("    ✔ HMAC-MD5 vector RFC 2202")

    print("─ Handshake NTLMv2 end-to-end contra fake proxy ─")
    asyncio.run(_demo_handshake())


async def _demo_handshake() -> None:
    """Fake proxy NTLM (servidor) + handshake real del cliente."""
    import asyncio
    from proxy.upstream_proxy import UpstreamProxyClient

    expected_user, expected_pass, expected_domain = "juan", "S3cr3to!", "EMPRESA"
    server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    target_info = (
        b"\x02\x00\x0c\x00E\x00M\x00P\x00R\x00E\x00S\x00A\x00"  # AV NB-DOMAIN
        b"\x00\x00\x00\x00"
    )

    async def echo(reader, writer):
        while (data := await reader.read(512)):
            writer.write(b"ECHO:" + data)
            await writer.drain()
        writer.close()

    echo_srv = await asyncio.start_server(echo, "127.0.0.1", 0)
    echo_port = echo_srv.sockets[0].getsockname()[1]
    state = {"step": 0}

    async def fake_ntlm_proxy(reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                state["step"] += 1
                hdrs = head.decode("iso-8859-1")
                token_line = next(
                    (l for l in hdrs.split("\r\n")
                     if l.lower().startswith("proxy-authorization: ntlm")),
                    None,
                )
                if token_line is None:
                    # Paso 1: petición sin auth → 407 NTLM
                    writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 b"Proxy-Authenticate: NTLM\r\n\r\n")
                    await writer.drain()
                    continue
                token = b64_decode(token_line.split("NTLM", 1)[1])
                if token[8:12] == struct.pack("<I", 1):
                    # Paso 2: Type1 → Type2 con challenge fijo
                    t2 = bytearray()
                    t2 += SIGNATURE
                    t2 += struct.pack("<I", 2)
                    t2 += _sec_field(b"", 56)
                    t2 += struct.pack("<I", _BASE_FLAGS | FLAG_TARGET_INFO)
                    t2 += server_challenge
                    t2 += b"\x00" * 8                     # context
                    t2 += _sec_field(target_info, 56)
                    t2 += _OS_VERSION
                    resp = b"HTTP/1.1 407 Proxy Authentication Required\r\n" \
                           b"Proxy-Authenticate: NTLM " + \
                           b64_encode(bytes(t2)).encode() + b"\r\n\r\n"
                    writer.write(resp)
                    await writer.drain()
                    continue
                if token[8:12] == struct.pack("<I", 3):
                    # Paso 3: Type3 → verificación SERVIDOR independiente
                    lm_len, _, lm_off = struct.unpack_from("<HHI", token, 12)
                    nt_len, _, nt_off = struct.unpack_from("<HHI", token, 20)
                    usr_len, _, usr_off = struct.unpack_from("<HHI", token, 36)
                    dom_len, _, dom_off = struct.unpack_from("<HHI", token, 28)
                    user = token[usr_off:usr_off + usr_len].decode("utf-16-le")
                    domain = token[dom_off:dom_off + dom_len].decode("utf-16-le")
                    nt_resp = token[nt_off:nt_off + nt_len]
                    # Verificación INDEPENDIENTE (hmac/stdlib del test):
                    import hmac as std_hmac
                    v2 = std_hmac.new(
                        MD4(expected_pass.encode("utf-16-le")).digest(),
                        (user.upper() + domain).encode("utf-16-le"),
                        hashlib.md5,
                    ).digest()
                    proof = std_hmac.new(
                        v2, server_challenge + nt_resp[16:], hashlib.md5,
                    ).digest()
                    ok = (
                        user == expected_user and domain == expected_domain
                        and proof == nt_resp[:16]
                        and lm_len == 24 and (lm_off + lm_len) <= len(token)
                        and nt_resp[16:20] == b"\x01\x01\x00\x00"
                    )
                    if not ok:
                        writer.write(b"HTTP/1.1 407 Denied\r\n\r\n")
                        await writer.drain()
                        writer.close()
                        return
                    # 200 + relay al echo server
                    _, target, _ = hdrs.split("\r\n", 1)[0].split(" ", 2)
                    host, _, p = target.partition(":")
                    r2, w2 = await asyncio.open_connection(host, int(p))
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()

                    async def pipe(r, w):
                        try:
                            while (chunk := await r.read(8192)):
                                w.write(chunk)
                                await w.drain()
                        except OSError:
                            pass
                        finally:
                            w.close()
                    await asyncio.gather(pipe(reader, w2), pipe(r2, writer))
                    return
                raise NtlmError("mensaje NTLM inesperado")
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return

    proxy_srv = await asyncio.start_server(fake_ntlm_proxy, "127.0.0.1", 0)
    proxy_port = proxy_srv.sockets[0].getsockname()[1]

    async with echo_srv, proxy_srv:
        client = UpstreamProxyClient(
            host="127.0.0.1", port=proxy_port,
            username=f"{expected_domain}\\{expected_user}",
            password=expected_pass, auth_type="ntlm",
        )
        reader, writer = await client.open_connect_tunnel("127.0.0.1",
                                                          echo_port)
        writer.write(b"hola ntlm")
        resp = await asyncio.wait_for(reader.read(64), timeout=5)
        assert resp == b"ECHO:hola ntlm", resp
        writer.close()
        print("    ✔ Handshake NTLMv2 (Type1→Type2→Type3) + túnel de datos")
        print(f"    ✔ Respuesta verificada por el lado servidor "
              f"({state['step']} mensajes)")
        print("─ demo ntlm OK ─")


if __name__ == "__main__":
    _demo()
