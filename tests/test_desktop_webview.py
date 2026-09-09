"""
AZZAZEL tests/test_desktop_webview.py
======================================
Pruebas de la ventana de escritorio basada en WebView (ui.webapp), que
reemplaza el tema "hacker" de CustomTkinter por el mismo diseño gráfico
que la app web/PWA.
"""
from __future__ import annotations

import threading
from unittest.mock import patch

import pytest

from ui.webapp.desktop_window import DesktopBridgeAPI, DIST_DIR, check_desktop_webview_support


def test_dist_build_exists():
    """El build de la PWA debe existir para que la ventana pueda cargarlo."""
    assert DIST_DIR.exists(), (
        f"Falta compilar la PWA en {DIST_DIR}. Ejecuta: "
        "cd web_pwa && npm install && npm run build"
    )
    assert (DIST_DIR / "index.html").is_file()


def test_dist_has_no_hardcoded_credentials():
    """El HTML/JS compilado no debe contener credenciales de proxy quemadas."""
    forbidden = ["airienrr", "123k20@A", "192.105.34.1"]
    for path in DIST_DIR.rglob("*"):
        if path.is_file() and path.suffix in (".html", ".js", ".css", ".json"):
            text = path.read_text(errors="ignore")
            for token in forbidden:
                assert token not in text, f"Credencial quemada '{token}' encontrada en {path}"


def test_check_desktop_webview_support_reports_missing_dist(tmp_path, monkeypatch):
    import ui.webapp.desktop_window as mod
    monkeypatch.setattr(mod, "DIST_DIR", tmp_path / "no-existe")
    ok, reason = mod.check_desktop_webview_support()
    assert ok is False
    assert "No se encontró" in reason


def test_check_desktop_webview_support_ok():
    ok, reason = check_desktop_webview_support()
    assert ok is True
    assert reason == "ok"


def test_bridge_api_initial_status():
    api = DesktopBridgeAPI()
    status = api.get_status()
    assert status == {"active": False, "tunnel_url": None, "last_error": None}


def test_bridge_api_stop_tunnel_when_not_running():
    api = DesktopBridgeAPI()
    result = api.stop_tunnel()
    assert result == {"ok": True}
    assert api.get_status()["active"] is False


def test_bridge_api_start_tunnel_success_path():
    """start_tunnel debe invocar run_with_session con la sesión recibida y
    reportar la URL de vuelta cuando el callback on_url_found se dispara."""
    api = DesktopBridgeAPI()

    class FakeBridge:
        def run_with_session(self, access_token, user_id, email, on_url_found=None, on_error=None):
            assert access_token == "tok-123"
            assert user_id == "user-abc"
            assert email == "demo@correo.com"
            on_url_found("https://fake-tunnel.example.com")

    with patch("reverse_tunnel.ReverseTunnelBridge", return_value=FakeBridge()):
        result = api.start_tunnel("tok-123", "user-abc", "demo@correo.com")

    assert result["ok"] is True
    assert result["tunnel_url"] == "https://fake-tunnel.example.com"
    assert api.get_status()["active"] is False  # el hilo finaliza y limpia el estado


def test_bridge_api_start_tunnel_error_path():
    """Si el proxy no está configurado, on_error debe propagar el mensaje."""
    api = DesktopBridgeAPI()

    class FakeBridge:
        def run_with_session(self, access_token, user_id, email, on_url_found=None, on_error=None):
            on_error("Falta configurar el proxy corporativo.")

    with patch("reverse_tunnel.ReverseTunnelBridge", return_value=FakeBridge()):
        result = api.start_tunnel("tok-123", "user-abc")

    assert result["ok"] is False
    assert "proxy corporativo" in result["error"]


def test_bridge_api_rejects_concurrent_start():
    """No debe permitirse iniciar dos túneles a la vez desde la UI."""
    api = DesktopBridgeAPI()
    started = threading.Event()
    release = threading.Event()

    class SlowFakeBridge:
        def run_with_session(self, access_token, user_id, email, on_url_found=None, on_error=None):
            started.set()
            release.wait(timeout=5.0)
            on_url_found("https://slow-tunnel.example.com")

    with patch("reverse_tunnel.ReverseTunnelBridge", return_value=SlowFakeBridge()):
        t = threading.Thread(target=api.start_tunnel, args=("tok", "user"))
        t.start()
        started.wait(timeout=5.0)

        # Mientras el primero sigue "conectando", un segundo intento debe rechazarse.
        second = api.start_tunnel("tok2", "user2")
        assert second == {"ok": False, "error": "El túnel ya está activo."}

        release.set()
        t.join(timeout=10.0)
