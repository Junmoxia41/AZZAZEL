"""
AZZAZEL protocol/constants.py — Constantes operativas del protocolo AZZ1.
"""
from __future__ import annotations

from protocol.version import CONTROL_MAGIC, FRAME_MAGIC

# Tipos de datagramas y frames
FRAME_DATA: int = 0x01
FRAME_KEEPALIVE: int = 0x02
FRAME_DISCONNECT: int = 0x03

# Tipos de mensajes de control (Handshake)
MSG_HELLO: int = 0x01
MSG_CHALLENGE: int = 0x02
MSG_RESPONSE: int = 0x03
MSG_ACK: int = 0x04
MSG_ERROR: int = 0xFF

# Longitudes y offsets de cabecera
MAGIC_LEN: int = 4
SESSION_ID_LEN: int = 8
NONCE_LEN: int = 16
COUNTER_LEN: int = 8
FRAME_HEADER_LEN: int = 13  # MAGIC(4) + TYPE(1) + SESSION_ID(8)
MIN_ENCRYPTED_FRAME_LEN: int = FRAME_HEADER_LEN + COUNTER_LEN + 16  # Cabecera + Nonce/Counter + Tag GCM/Poly1305

# Contextos criptográficos (Domain separation)
SESSION_KEY_CONTEXT: bytes = b"AZZ-SESSION-v1"
AUTH_CONTEXT: bytes = b"AZZ-AUTH-v1"
PFS_CIPHER_SUITE: str = "X25519-HKDF-SHA256-AES256GCM"

# Parámetros de red y temporización
DEFAULT_MTU: int = 1420
REPLAY_WINDOW_SIZE: int = 128
HANDSHAKE_TIMEOUT: float = 10.0
KEEPALIVE_INTERVAL: float = 25.0
SESSION_IDLE_TIMEOUT: float = 120.0
