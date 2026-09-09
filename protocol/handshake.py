"""
AZZAZEL protocol/handshake.py — Máquina de estados y mensajes de control AZZ1.
"""
from __future__ import annotations

import enum
import json
import secrets
from typing import Any, Optional

from protocol.constants import (
    AUTH_CONTEXT,
    CONTROL_MAGIC,
    PFS_CIPHER_SUITE,
    SESSION_KEY_CONTEXT,
)
from protocol.crypto import (
    HandshakeError,
    compute_auth_proof,
    compute_ecdh_secret,
    derive_session_key,
    generate_ephemeral_keypair,
    verify_auth_proof,
)
from protocol.version import PROTOCOL_VERSION, is_supported_version


class HandshakeState(enum.Enum):
    """Estados del ciclo de vida del handshake AZZ1."""
    IDLE = "IDLE"
    HELLO_SENT = "HELLO_SENT"
    CHALLENGE_RECEIVED = "CHALLENGE_RECEIVED"
    CHALLENGE_SENT = "CHALLENGE_SENT"
    RESPONSE_SENT = "RESPONSE_SENT"
    ESTABLISHED = "ESTABLISHED"
    FAILED = "FAILED"


def encode_control_message(payload: dict[str, Any]) -> bytes:
    """Serializa un mensaje de control JSON con el prefijo mágico de protocolo."""
    return CONTROL_MAGIC + json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_control_message(datagram: bytes) -> Optional[dict[str, Any]]:
    """Deserializa y valida un datagrama de control entrante.

    Returns:
        Diccionario con el payload decodificado o ``None`` si el prefijo o JSON son inválidos.
    """
    if not datagram.startswith(CONTROL_MAGIC):
        return None
    try:
        raw_json = datagram[len(CONTROL_MAGIC):].decode("utf-8")
        parsed = json.loads(raw_json)
        if isinstance(parsed, dict):
            return parsed
        return None
    except Exception:
        return None


def create_hello_message(
    client_nonce: bytes,
    client_pub_bytes: bytes,
    client_version: int = PROTOCOL_VERSION,
) -> dict[str, Any]:
    """Genera el mensaje MSG_HELLO del cliente."""
    return {
        "msg": "hello",
        "ver": client_version,
        "client_nonce": client_nonce.hex(),
        "client_pub": client_pub_bytes.hex(),
        "cipher_suite": PFS_CIPHER_SUITE,
    }


def create_challenge_message(
    server_nonce: bytes,
    session_id: bytes,
    server_pub_bytes: bytes,
    server_proof: bytes,
    assigned_ip: str,
    server_version: int = PROTOCOL_VERSION,
) -> dict[str, Any]:
    """Genera el mensaje MSG_CHALLENGE del servidor."""
    return {
        "msg": "challenge",
        "ver": server_version,
        "session_id": session_id.hex(),
        "server_nonce": server_nonce.hex(),
        "server_pub": server_pub_bytes.hex(),
        "server_proof": server_proof.hex(),
        "assigned_ip": assigned_ip,
    }


def create_response_message(client_proof: bytes) -> dict[str, Any]:
    """Genera el mensaje MSG_RESPONSE del cliente."""
    return {
        "msg": "response",
        "client_proof": client_proof.hex(),
    }
