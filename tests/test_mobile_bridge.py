"""
AZZAZEL tests/test_mobile_bridge.py — Batería de pruebas de MobileBridge y DeviceRegistry.
"""
from pathlib import Path
import pytest
from bridge.mobile_bridge import (
    DeviceRegistry,
    PairedDevice,
    MobileBridge,
)
from core.config_manager import ConfigManager


def test_device_registry_crud(temp_dir: Path):
    reg_file = temp_dir / "devices.json"
    reg = DeviceRegistry(reg_file)
    assert len(reg.list()) == 0

    # Agregar dispositivo
    dev = reg.add("dev-1", "Pixel 8 Pro", "secret_token_123", max_devices=5)
    assert dev.name == "Pixel 8 Pro"
    assert len(reg.list()) == 1

    # Verificar token correcto
    verified = reg.verify("dev-1", "secret_token_123")
    assert verified is not None
    assert verified.device_id == "dev-1"

    # Verificar token erróneo
    assert reg.verify("dev-1", "wrong_token") is None

    # Persistencia en disco tras reload
    reg2 = DeviceRegistry(reg_file)
    assert len(reg2.list()) == 1
    assert reg2.verify("dev-1", "secret_token_123") is not None

    # Eliminar dispositivo
    assert reg2.remove("dev-1") is True
    assert len(reg2.list()) == 0


@pytest.mark.anyio
async def test_mobile_bridge_status_and_lifecycle(temp_config_manager: ConfigManager):
    cm = temp_config_manager
    bridge = MobileBridge(config_manager=cm, host="127.0.0.1", port=0)
    await bridge.start()
    st = bridge.status()
    assert st["port"] > 0
    assert st["sessions"] == 0
    await bridge.stop()
