"""
AZZAZEL tests/test_cli.py — Batería de pruebas de la CLI y utilidades
compartidas.

(Antes vivían junto a pruebas de la GUI legada de CustomTkinter en
``test_cli_and_gui.py``; esa GUI y su tema "hacker" Matrix fueron
eliminados por completo — la única ventana de escritorio soportada ahora
es ``ui.webapp`` (WebView con el mismo diseño que la web). Estas pruebas
de CLI/crypto no dependían de esa GUI y se conservan aquí.)
"""
from azzazel import build_command_table


def test_cli_command_table_registration():
    table = build_command_table()
    assert "help" in table
    assert "status" in table
    assert "version" in table
    assert "theme" in table
    # Comandos numéricos integrados
    for d in "123456789":
        assert d in table


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
