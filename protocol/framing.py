"""
AZZAZEL protocol/framing.py — Empaquetado binario y autenticación de frames AZZ1.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from core.crypto_engine import CryptoEngine
from protocol.constants import (
    FRAME_DATA,
    FRAME_HEADER_LEN,
    FRAME_KEEPALIVE,
    FRAME_MAGIC,
    MIN_ENCRYPTED_FRAME_LEN,
)
from protocol.replay import ReplayWindow


@dataclass
class Azz1Frame:
    """Estructura de un frame decodificado y autenticado del túnel AZZ1."""

    session_id: bytes
    ftype: int
    counter: int
    payload: bytes


def pack_frame(
    crypto: CryptoEngine,
    session_id: bytes,
    counter: int,
    payload: bytes,
    ftype: int = FRAME_DATA,
) -> bytes:
    """Construye y cifra un datagrama AZZ1 listo para transmisión UDP.

    Estructura en cable:
    [ FRAME_MAGIC (4B) | FTYPE (1B) | SESSION_ID (8B) ] (Cabecera en claro autenticada como AAD)
    [ CIPHERTEXT (Nonce 12B + Ciphertext(Counter 8B + Payload) + Tag 16B) ]

    Args:
        crypto: Motor criptográfico inicializado con la clave de sesión.
        session_id: 8 bytes del identificador de sesión.
        counter: Contador de transmisión de 64 bits (monótono incremental).
        payload: Carga útil binaria (paquete IP o vacío para keepalive).
        ftype: Tipo de frame (FRAME_DATA o FRAME_KEEPALIVE).

    Returns:
        Bytes listos para enviar por el socket UDP.
    """
    if len(session_id) != 8:
        raise ValueError(f"Longitud de session_id inválida: {len(session_id)} != 8")

    header = FRAME_MAGIC + bytes([ftype]) + session_id
    body = struct.pack("<Q", counter) + payload
    encrypted_blob = crypto.encrypt_bytes(body, aad=header)
    return header + encrypted_blob


def unpack_frame(
    crypto: CryptoEngine,
    datagram: bytes,
    expected_session_id: bytes,
    rx_window: Optional[ReplayWindow] = None,
) -> tuple[int, int, Optional[bytes]]:
    """Descifra, valida la integridad de cabecera (AAD) y verifica la ventana anti-replay.

    Args:
        crypto: Motor criptográfico inicializado con la clave de sesión.
        datagram: Bytes recibidos por UDP.
        expected_session_id: 8 bytes de la sesión esperada.
        rx_window: Ventana deslizante para protección contra ataques de repetición.

    Returns:
        Tupla ``(counter, ftype, payload)``. En caso de descarte o error, retorna ``(-1, -1, None)``.
    """
    if len(datagram) < MIN_ENCRYPTED_FRAME_LEN:
        return -1, -1, None

    if not datagram.startswith(FRAME_MAGIC):
        return -1, -1, None

    ftype = datagram[4]
    session_id = datagram[5:FRAME_HEADER_LEN]
    if session_id != expected_session_id:
        return -1, -1, None

    header = datagram[:FRAME_HEADER_LEN]
    encrypted_blob = datagram[FRAME_HEADER_LEN:]

    try:
        decrypted_body = crypto.decrypt_bytes(encrypted_blob, aad=header)
    except Exception:
        # Fallo de autenticación / manipulación de payload o cabecera
        return -1, -1, None

    if len(decrypted_body) < 8:
        return -1, -1, None

    counter = struct.unpack_from("<Q", decrypted_body, 0)[0]
    payload = decrypted_body[8:]

    if rx_window is not None and not rx_window.check_and_record(counter):
        # Descartado por replay o fuera de ventana
        return -1, -1, None

    return counter, ftype, payload
