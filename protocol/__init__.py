"""
AZZAZEL protocol — Implementación desacoplada del protocolo de túnel AZZ1.
"""
from __future__ import annotations

from protocol.constants import (
    AUTH_CONTEXT,
    CONTROL_MAGIC,
    DEFAULT_MTU,
    FRAME_DATA,
    FRAME_HEADER_LEN,
    FRAME_KEEPALIVE,
    FRAME_MAGIC,
    HANDSHAKE_TIMEOUT,
    KEEPALIVE_INTERVAL,
    PFS_CIPHER_SUITE,
    REPLAY_WINDOW_SIZE,
    SESSION_IDLE_TIMEOUT,
    SESSION_KEY_CONTEXT,
)
from protocol.crypto import (
    HandshakeError,
    ProtocolCryptoError,
    compute_auth_proof,
    compute_ecdh_secret,
    derive_session_key,
    generate_ephemeral_keypair,
    verify_auth_proof,
)
from protocol.framing import Azz1Frame, pack_frame, unpack_frame
from protocol.handshake import (
    HandshakeState,
    create_challenge_message,
    create_hello_message,
    create_response_message,
    decode_control_message,
    encode_control_message,
)
from protocol.replay import ReplayWindow
from protocol.version import (
    MAX_SUPPORTED_VERSION,
    MIN_SUPPORTED_VERSION,
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    WIRE_VERSION,
    is_supported_version,
)

__all__ = [
    "AUTH_CONTEXT",
    "CONTROL_MAGIC",
    "DEFAULT_MTU",
    "FRAME_DATA",
    "FRAME_HEADER_LEN",
    "FRAME_KEEPALIVE",
    "FRAME_MAGIC",
    "HANDSHAKE_TIMEOUT",
    "KEEPALIVE_INTERVAL",
    "MAX_SUPPORTED_VERSION",
    "MIN_SUPPORTED_VERSION",
    "PFS_CIPHER_SUITE",
    "PROTOCOL_NAME",
    "PROTOCOL_VERSION",
    "REPLAY_WINDOW_SIZE",
    "SESSION_IDLE_TIMEOUT",
    "SESSION_KEY_CONTEXT",
    "WIRE_VERSION",
    "Azz1Frame",
    "HandshakeError",
    "HandshakeState",
    "ProtocolCryptoError",
    "ReplayWindow",
    "compute_auth_proof",
    "compute_ecdh_secret",
    "create_challenge_message",
    "create_hello_message",
    "create_response_message",
    "decode_control_message",
    "derive_session_key",
    "encode_control_message",
    "generate_ephemeral_keypair",
    "is_supported_version",
    "pack_frame",
    "unpack_frame",
    "verify_auth_proof",
]
