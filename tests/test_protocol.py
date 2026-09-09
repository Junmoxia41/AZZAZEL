"""
Tests exhaustivos y de propiedades para el protocolo AZZ1 (protocol/).
"""
from __future__ import annotations

import secrets
import pytest
from hypothesis import given, strategies as st

from core.crypto_engine import CryptoEngine
from protocol.constants import (
    FRAME_DATA,
    FRAME_HEADER_LEN,
    FRAME_KEEPALIVE,
    FRAME_MAGIC,
    REPLAY_WINDOW_SIZE,
)
from protocol.crypto import (
    HandshakeError,
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
from protocol.version import is_supported_version


def test_version_support():
    assert is_supported_version(1) is True
    assert is_supported_version(0) is False
    assert is_supported_version(2) is False


def test_ephemeral_x25519_pfs_exchange():
    # Par A (Cliente) y Par B (Servidor)
    client_priv, client_pub = generate_ephemeral_keypair()
    server_priv, server_pub = generate_ephemeral_keypair()

    assert len(client_pub) == 32
    assert len(server_pub) == 32

    # Intercambio Diffie-Hellman
    secret_c = compute_ecdh_secret(client_priv, server_pub)
    secret_s = compute_ecdh_secret(server_priv, client_pub)

    assert secret_c == secret_s
    assert len(secret_c) == 32


def test_session_key_derivation_pfs_strict():
    psk = "SuperSecretMasterKey123"
    client_nonce = secrets.token_bytes(16)
    server_nonce = secrets.token_bytes(16)

    client_priv, client_pub = generate_ephemeral_keypair()
    server_priv, server_pub = generate_ephemeral_keypair()
    shared_ecdh = compute_ecdh_secret(client_priv, server_pub)

    # Derivación correcta con PFS
    key_client = derive_session_key(psk, client_nonce, server_nonce, ecdh_secret=shared_ecdh, require_pfs=True)
    key_server = derive_session_key(psk, client_nonce, server_nonce, ecdh_secret=shared_ecdh, require_pfs=True)

    assert key_client == key_server
    assert len(key_client) == 32

    # Si se exige PFS y no se envía secreto ECDH, debe fallar con HandshakeError
    with pytest.raises(HandshakeError, match="Handshake PFS obligatorio"):
        derive_session_key(psk, client_nonce, server_nonce, ecdh_secret=None, require_pfs=True)


def test_auth_proof_verification():
    session_key = secrets.token_bytes(32)
    client_nonce = secrets.token_bytes(16)
    server_nonce = secrets.token_bytes(16)
    session_id = secrets.token_bytes(8)

    proof = compute_auth_proof(session_key, client_nonce, server_nonce, session_id)
    assert len(proof) == 32

    # Verificación válida
    assert verify_auth_proof(session_key, client_nonce, server_nonce, session_id, proof) is True

    # Verificación con clave errónea
    wrong_key = secrets.token_bytes(32)
    assert verify_auth_proof(wrong_key, client_nonce, server_nonce, session_id, proof) is False

    # Verificación con prueba manipulada
    corrupted_proof = bytearray(proof)
    corrupted_proof[0] ^= 0xFF
    assert verify_auth_proof(session_key, client_nonce, server_nonce, session_id, bytes(corrupted_proof)) is False


def test_framing_pack_unpack_roundtrip():
    key = secrets.token_bytes(32)
    crypto = CryptoEngine(key)
    session_id = secrets.token_bytes(8)
    window = ReplayWindow(size=128)

    original_payload = b"GET /vpn-packet HTTP/1.1\r\nHost: internal\r\n\r\n"
    datagram = pack_frame(crypto, session_id, counter=1, payload=original_payload, ftype=FRAME_DATA)

    assert datagram.startswith(FRAME_MAGIC)
    assert datagram[4] == FRAME_DATA
    assert datagram[5:13] == session_id

    counter, ftype, payload = unpack_frame(crypto, datagram, expected_session_id=session_id, rx_window=window)
    assert counter == 1
    assert ftype == FRAME_DATA
    assert payload == original_payload


def test_framing_tamper_detection_and_rejection():
    key = secrets.token_bytes(32)
    crypto = CryptoEngine(key)
    session_id = secrets.token_bytes(8)
    window = ReplayWindow(size=128)

    payload = b"TopSecretData"
    datagram = bytearray(pack_frame(crypto, session_id, counter=5, payload=payload, ftype=FRAME_DATA))

    # 1. Modificar cabecera (AAD) -> Debe ser rechazado
    datagram[4] = FRAME_KEEPALIVE
    counter, ftype, dec_payload = unpack_frame(crypto, bytes(datagram), expected_session_id=session_id, rx_window=window)
    assert counter == -1
    assert dec_payload is None

    # 2. Modificar payload cifrado -> Debe ser rechazado
    datagram = bytearray(pack_frame(crypto, session_id, counter=6, payload=payload, ftype=FRAME_DATA))
    datagram[-1] ^= 0x01
    counter, ftype, dec_payload = unpack_frame(crypto, bytes(datagram), expected_session_id=session_id, rx_window=window)
    assert counter == -1
    assert dec_payload is None

    # 3. Session ID incorrecto -> Debe ser rechazado
    wrong_sid = secrets.token_bytes(8)
    datagram = pack_frame(crypto, session_id, counter=7, payload=payload, ftype=FRAME_DATA)
    counter, ftype, dec_payload = unpack_frame(crypto, datagram, expected_session_id=wrong_sid, rx_window=window)
    assert counter == -1
    assert dec_payload is None


def test_replay_window_sliding_and_duplicates():
    window = ReplayWindow(size=64)

    # Paquetes en orden
    assert window.check_and_record(0) is True
    assert window.check_and_record(1) is True
    assert window.check_and_record(2) is True

    # Duplicados (Replay attack)
    assert window.check_and_record(1) is False
    assert window.check_and_record(2) is False

    # Paquetes desordenados pero dentro de la ventana
    assert window.check_and_record(10) is True
    assert window.check_and_record(5) is True
    assert window.check_and_record(5) is False  # Replay de paquete fuera de orden

    # Salto hacia adelante que expulsa los primeros paquetes
    assert window.check_and_record(100) is True
    # Ahora la ventana es [100 - 64, 100] = [36, 100]
    assert window.check_and_record(35) is False  # Fuera de ventana (muy antiguo)
    assert window.check_and_record(40) is True   # Dentro de la nueva ventana
    assert window.check_and_record(40) is False  # Ya visto en la nueva ventana


def test_handshake_control_message_codec():
    hello = create_hello_message(secrets.token_bytes(16), secrets.token_bytes(32))
    encoded = encode_control_message(hello)
    decoded = decode_control_message(encoded)

    assert decoded is not None
    assert decoded["msg"] == "hello"
    assert decoded["ver"] == 1
    assert "client_nonce" in decoded
    assert "client_pub" in decoded

    # Mensaje corrupto
    assert decode_control_message(b"INVALID_MAGIC_HEADER") is None
    assert decode_control_message(b"AZZ-C1\n{not_valid_json") is None


@given(st.binary(min_size=0, max_size=1500))
def test_hypothesis_framing_roundtrip(payload: bytes):
    key = b"0" * 32
    crypto = CryptoEngine(key)
    session_id = b"12345678"
    window = ReplayWindow(size=128)

    datagram = pack_frame(crypto, session_id, counter=42, payload=payload)
    counter, ftype, recovered = unpack_frame(crypto, datagram, session_id, window)

    assert counter == 42
    assert ftype == FRAME_DATA
    assert recovered == payload
