"""
AZZAZEL tests/test_config_manager.py — Batería de pruebas de ConfigManager y secretos.
"""
from pathlib import Path
import pytest
from core.config_manager import ConfigManager


def test_config_manager_creation_and_defaults(temp_config_manager: ConfigManager):
    cm = temp_config_manager
    cfg = cm.config
    assert cfg.azzazel.name == "AZZAZEL"
    assert cfg.vpn.protocol in ("azz1", "wireguard")
    assert cfg.proxy.local.http_port == 8888
    assert isinstance(cfg.bridge.enabled, bool)
    assert cfg.api.port == 9999


def test_config_manager_get_set(temp_config_manager: ConfigManager):
    cm = temp_config_manager
    cm.set("vpn.server.listen_port", 51821)
    assert cm.get("vpn.server.listen_port") == 51821
    assert cm.config.vpn.server.listen_port == 51821


def test_config_manager_secret_encryption_at_rest(temp_config_manager: ConfigManager, temp_dir: Path):
    cm = temp_config_manager
    secret_val = "corporate_secret_password_xyz"
    cm.set("proxy.upstream.password", secret_val)
    cm.save()

    # En memoria, el getter devuelve el plaintext descifrado
    assert cm.get("proxy.upstream.password") == secret_val

    # En disco, el fichero YAML contiene el token cifrado
    yaml_text = (temp_dir / "config.yaml").read_text(encoding="utf-8")
    assert secret_val not in yaml_text
    assert "ENC[AES-256-GCM]:" in yaml_text


def test_config_manager_reload_with_crypto(temp_dir: Path, temp_crypto):
    cfg_file = temp_dir / "config.yaml"
    cm1 = ConfigManager(cfg_file)
    cm1.set_crypto(temp_crypto)
    cm1.load_or_create()
    cm1.set("api.auth_token", "super_api_token_12345")
    cm1.save()

    # Cargar en una nueva instancia
    cm2 = ConfigManager(cfg_file)
    cm2.set_crypto(temp_crypto)
    cm2.load_or_create()
    assert cm2.get("api.auth_token") == "super_api_token_12345"


def test_config_manager_as_dict(temp_config_manager: ConfigManager):
    cm = temp_config_manager
    d = cm.config.as_dict()
    assert isinstance(d, dict)
    assert "azzazel" in d
    assert "vpn" in d
    assert "proxy" in d
    assert "bridge" in d
    assert "api" in d
