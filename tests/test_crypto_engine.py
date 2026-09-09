"""
AZZAZEL tests/test_crypto_engine.py — Batería de pruebas de CryptoEngine.
"""
from pathlib import Path
import pytest
from core.crypto_engine import (
    CryptoEngine,
    generate_key,
    generate_pin,
    random_token,
    secure_compare,
)


def test_crypto_engine_encryption_decryption(temp_dir: Path):
    engine = CryptoEngine.for_machine(temp_dir)
    secret = "SuperSecretPassword123!@#"
    encrypted = engine.encrypt_str(secret)
    assert isinstance(encrypted, str)
    assert len(encrypted) > 10
    decrypted = engine.decrypt_str(encrypted)
    assert decrypted == secret


def test_crypto_engine_tamper_detection(temp_dir: Path):
    engine = CryptoEngine.for_machine(temp_dir)
    encrypted = engine.encrypt_str("Payload")
    # Mutar el ciphertext
    tampered = encrypted[:-4] + "AAAA"
    with pytest.raises(Exception):
        engine.decrypt_str(tampered)


def test_crypto_engine_wrong_key(temp_dir: Path):
    engine1 = CryptoEngine(generate_key())
    engine2 = CryptoEngine(generate_key())
    encrypted = engine1.encrypt_str("SecretMessage")
    with pytest.raises(Exception):
        engine2.decrypt_str(encrypted)


def test_crypto_engine_file_encryption(temp_dir: Path):
    engine = CryptoEngine.for_machine(temp_dir)
    src = temp_dir / "plain.txt"
    enc = temp_dir / "plain.txt.enc"
    dec = temp_dir / "plain.dec.txt"

    src.write_text("Hello AZZAZEL Secure Storage!", encoding="utf-8")
    engine.encrypt_file(src, enc)
    assert enc.exists() and enc.stat().st_size > 0
    engine.decrypt_file(enc, dec)
    assert dec.read_text(encoding="utf-8") == "Hello AZZAZEL Secure Storage!"


def test_pin_generation():
    pin6 = generate_pin(6)
    assert len(pin6) == 6
    assert pin6.isdigit()

    pin8 = generate_pin(8)
    assert len(pin8) == 8
    assert pin8.isdigit()


def test_random_token():
    tok = random_token(32)
    assert len(tok) >= 32
    assert isinstance(tok, str)


def test_secure_compare():
    assert secure_compare("secret_123", "secret_123") is True
    assert secure_compare("secret_123", "wrong_pass") is False
    assert secure_compare("secret_123", "secret_124") is False
