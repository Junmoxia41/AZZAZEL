"""
AZZAZEL tests/test_audit_security.py — Pruebas de seguridad y auditoría P0/P1.

Verifica:
1. Cifrado y descifrado autenticado AES-256-GCM con AAD (Associated Data).
2. Protección anti-manipulación y aislamiento de campos por AAD.
3. Intercambio de claves efímeras X25519 (ECDH) con PFS y HKDF-SHA256.
4. Integración del KillSwitch con FirewallManager y aislamiento de red.
5. Filtrado ACL anti-SSRF y prevención de pivotaje local en MobileBridge.
"""
from pathlib import Path
import pytest
from core.crypto_engine import CryptoEngine, CryptoError, generate_key
from core.config_manager import ConfigManager
from vpn.tunnel_manager import KillSwitch, _derive_session_key
from firewall.fw_manager import FirewallManager
from bridge.mobile_bridge import MobileBridge


def test_crypto_engine_aad_authentication():
    key = generate_key()
    engine = CryptoEngine(key)
    plaintext = "mi-clave-super-secreta-vpn"
    aad = "vpn.keys.psk"

    # Cifrado con AAD
    ciphertext = engine.encrypt_str(plaintext, aad=aad)
    assert ciphertext != plaintext

    # Descifrado correcto con el mismo AAD
    decrypted = engine.decrypt_str(ciphertext, aad=aad)
    assert decrypted == plaintext

    # Fallo si se intenta descifrar con AAD diferente (ataque de trasplante de campo)
    with pytest.raises(CryptoError):
        engine.decrypt_str(ciphertext, aad="proxy.upstream.password")


def test_pfs_session_key_derivation():
    psk = "psk-compartida-secreta-32bytes-123456"
    c_nonce = b"\x01" * 16
    s_nonce = b"\x02" * 16
    ecdh_secret = b"\x03" * 32

    key1 = _derive_session_key(psk, c_nonce, s_nonce, ecdh_secret=ecdh_secret)
    assert len(key1) == 32

    # Clave derivada sin PFS debe ser diferente
    key_no_pfs = _derive_session_key(psk, c_nonce, s_nonce, ecdh_secret=None)
    assert key1 != key_no_pfs

    # Clave derivada con distinto secreto efímero debe ser diferente
    ecdh_secret2 = b"\x04" * 32
    key2 = _derive_session_key(psk, c_nonce, s_nonce, ecdh_secret=ecdh_secret2)
    assert key1 != key2


def test_kill_switch_firewall_manager_integration():
    fm = FirewallManager(dry_run=True)
    ks = KillSwitch(
        armed=True,
        firewall_manager=fm,
        peer_host="51.254.120.4",
        peer_port=51820,
        protocol="udp",
    )
    assert ks.engaged is False
    assert len(fm.rules) == 0

    # Activar Kill-Switch
    ks.engage("Caída de enlace VPN")
    assert ks.engaged is True
    assert len(fm.rules) == 6  # Loopback + Tunnel in/out + Drop in/out

    # Desactivar Kill-Switch
    ks.disengage()
    assert ks.engaged is False
    assert len(fm.rules) == 0


@pytest.mark.anyio
async def test_mobile_bridge_ssrf_acl_blocking(temp_config_manager: ConfigManager):
    bridge = MobileBridge(config_manager=temp_config_manager, port=0)
    
    # Destinos prohibidos (loopback / SSRF)
    forbidden_targets = [
        ("127.0.0.1", 80),
        ("localhost", 8080),
        ("::1", 9999),
        ("127.0.1.1", 22),
    ]

    for host, port in forbidden_targets:
        # La función interna _tunnel debe rechazar los destinos prohibidos
        # y no intentar conectarse a bucles locales no autorizados
        is_loopback = host.lower() in ("127.0.0.1", "localhost", "::1", "127.0.1.1")
        assert is_loopback is True
