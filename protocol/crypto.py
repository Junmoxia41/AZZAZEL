"""
AZZAZEL protocol/crypto.py — Criptografía de sesión, intercambio X25519 PFS y HKDF.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from core.crypto_engine import secure_compare
from protocol.constants import AUTH_CONTEXT, SESSION_KEY_CONTEXT


class ProtocolCryptoError(Exception):
    """Error en las operaciones criptográficas del protocolo AZZ1."""


class HandshakeError(ProtocolCryptoError):
    """Fallo en el establecimiento del canal seguro o intercambio de claves."""


def generate_ephemeral_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Genera un par de claves efímeras X25519 para Perfect Forward Secrecy (PFS).

    Returns:
        Tupla ``(clave_privada, clave_publica_bytes_raw)`` de 32 bytes.
    """
    try:
        priv = X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv, pub_bytes
    except Exception as exc:
        raise ProtocolCryptoError(f"Error generando par de claves X25519: {exc}") from exc


def compute_ecdh_secret(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """Calcula el secreto compartido ECDH X25519 a partir de la clave pública del par.

    Args:
        private_key: Clave privada X25519 local.
        peer_public_bytes: 32 bytes de la clave pública remota.

    Returns:
        32 bytes de secreto compartido Diffie-Hellman.
    """
    if len(peer_public_bytes) != 32:
        raise HandshakeError(f"Longitud de clave pública X25519 inválida: {len(peer_public_bytes)} != 32")
    try:
        peer_pub_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
        return private_key.exchange(peer_pub_key)
    except Exception as exc:
        raise HandshakeError(f"Fallo en intercambio de claves X25519 ECDH: {exc}") from exc


def derive_session_key(
    psk: str,
    client_nonce: bytes,
    server_nonce: bytes,
    ecdh_secret: Optional[bytes] = None,
    require_pfs: bool = True,
) -> bytes:
    """Deriva la clave simétrica de sesión de 256 bits mediante HKDF-SHA256 con PFS.

    Args:
        psk: Clave precompartida maestra (PSK).
        client_nonce: 16 bytes de nonce generados por el cliente.
        server_nonce: 16 bytes de nonce generados por el servidor.
        ecdh_secret: Secreto compartido efímero X25519.
        require_pfs: Si es ``True``, exige un secreto ECDH válido y no permite fallback degradado.

    Returns:
        32 bytes de clave simétrica para cifrado autenticado de frames.

    Raises:
        HandshakeError: Si PFS es obligatorio pero el secreto ECDH no está presente o falla.
    """
    if not psk:
        raise HandshakeError("La clave precompartida (PSK) no puede estar vacía")

    psk_blob = hashlib.sha256(psk.encode("utf-8")).digest()
    info = client_nonce + server_nonce + SESSION_KEY_CONTEXT

    if require_pfs:
        if ecdh_secret is None:
            raise HandshakeError("Handshake PFS obligatorio pero el secreto ECDH X25519 no fue provisto")
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=psk_blob,
                info=info,
            )
            return hkdf.derive(ecdh_secret)
        except Exception as exc:
            raise HandshakeError(f"Fallo en derivación HKDF-SHA256 para PFS: {exc}") from exc

    # Modo sin PFS (explícito únicamente si require_pfs=False)
    if ecdh_secret is not None:
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=psk_blob,
                info=info,
            )
            return hkdf.derive(ecdh_secret)
        except Exception:
            pass

    return hmac.new(psk_blob, info, hashlib.sha256).digest()[:32]


def compute_auth_proof(
    session_key: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    session_id: bytes,
) -> bytes:
    """Calcula la prueba de autenticación HMAC-SHA256 para validación mutua de posesión de clave."""
    ctx = client_nonce + server_nonce + session_id + AUTH_CONTEXT
    return hmac.new(session_key, ctx, hashlib.sha256).digest()


def verify_auth_proof(
    session_key: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    session_id: bytes,
    received_proof: bytes,
) -> bool:
    """Verifica en tiempo constante la prueba de autenticación mutua."""
    expected = compute_auth_proof(session_key, client_nonce, server_nonce, session_id)
    return secure_compare(expected, received_proof)
