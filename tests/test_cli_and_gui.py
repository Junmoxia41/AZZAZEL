"""
AZZAZEL tests/test_cli_and_gui.py — Batería de pruebas de CLI, GUI y Temas.
"""
import pytest
from azzazel import build_command_table
from ui.gui.app import check_gui_support, TrafficSampler, split_host_port
from ui.gui.theme import AZZAZEL_THEME


def test_cli_command_table_registration():
    table = build_command_table()
    assert "help" in table
    assert "status" in table
    assert "version" in table
    assert "theme" in table
    # Comandos numéricos integrados
    for d in "123456789":
        assert d in table


def test_gui_helpers():
    # TrafficSampler
    sampler = TrafficSampler(history_len=20, use_real_psutil=False)
    rx, tx = sampler.sample()
    assert rx >= 0 and tx >= 0
    assert len(sampler.series_rx()) == 20

    # split_host_port
    h, p = split_host_port("10.0.0.1:8080")
    assert h == "10.0.0.1" and p == 8080

    h, p = split_host_port("google.com", default_port=443)
    assert h == "google.com" and p == 443

    with pytest.raises(ValueError):
        split_host_port("")

    with pytest.raises(ValueError):
        split_host_port("host:invalid_port")


def test_gui_theme_palette():
    t = AZZAZEL_THEME
    assert t.text_main == "#00ff41"  # Matrix Green
    assert t.text_cyan == "#0abdc6"
    assert t.text_magenta == "#ea00d9"
    assert t.accent_red == "#ff003c"
    assert t.warn_amber == "#ffb700"
    assert t.accent_cyan == "#0abdc6"
    assert t.accent_magenta == "#ea00d9"
    assert t.accent_green == "#00ff41"


def test_crypto_engine_class_methods():
    from core.crypto_engine import CryptoEngine
    pin = CryptoEngine.generate_pin(6)
    assert len(pin) == 6 and pin.isdigit()

    token = CryptoEngine.random_token(32)
    assert isinstance(token, str) and len(token) >= 32

    assert CryptoEngine.secure_compare("test", "test") is True
    assert CryptoEngine.secure_compare("test", "wrong") is False

    key = CryptoEngine.generate_key()
    assert len(key) == 32
