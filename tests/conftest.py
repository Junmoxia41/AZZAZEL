"""
AZZAZEL tests/conftest.py — Fixtures comunes para la suite formal de pytest (S8).
"""
import os
import socket
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest

# Asegurar path raíz de azzazel-vpn en sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.config_manager import ConfigManager
from core.crypto_engine import CryptoEngine


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Crea un directorio temporal limpio para pruebas."""
    with tempfile.TemporaryDirectory(prefix="azz-test-") as tmp:
        p = Path(tmp)
        p.chmod(0o700)
        yield p


@pytest.fixture
def temp_crypto(temp_dir: Path) -> CryptoEngine:
    """Instancia un CryptoEngine con clave en directorio temporal."""
    return CryptoEngine.for_machine(temp_dir)


@pytest.fixture
def temp_config_manager(temp_dir: Path, temp_crypto: CryptoEngine) -> ConfigManager:
    """Instancia un ConfigManager cargado con CryptoEngine en entorno temporal."""
    cfg_file = temp_dir / "config.yaml"
    cm = ConfigManager(cfg_file)
    cm.set_crypto(temp_crypto)
    cm.load_or_create()
    return cm


@pytest.fixture
def dummy_psk() -> str:
    """Clave PSK predeterminada de 256 bits para pruebas de túnel."""
    return "azzazel_test_psk_secret_key_32_bytes_len_ok!"


@pytest.fixture
def ephemeral_port() -> int:
    """Encuentra un puerto TCP/UDP efímero libre en localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
