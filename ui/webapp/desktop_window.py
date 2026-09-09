"""
AZZAZEL ui/webapp/desktop_window.py — ventana de escritorio con el mismo
diseño gráfico que la app web (PWA React/Tailwind).

Reemplaza la GUI antigua de CustomTkinter (tema "hacker" verde matriz) por
una ventana nativa basada en pywebview que carga directamente
``web_pwa/dist`` — el mismo HTML/CSS/JS que corre en el navegador y en el
móvil. El login, los ajustes y la configuración del proxy se hacen con la
MISMA interfaz que ve cualquier usuario en la web: no hay una pantalla de
configuración separada ni un estilo visual distinto para la app de PC.

Puente Python ↔ JavaScript (``window.pywebview.api``):
- ``start_tunnel(access_token, user_id, email)``: inicia el túnel inverso
  real usando la sesión de Supabase que el usuario ya inició en el propio
  formulario web embebido. El proxy corporativo se lee de la tabla
  ``proxy_configs`` de ESE usuario (o se guarda ahí si se acaba de
  configurar en el panel "Estado PC" de la app) — nunca hay credenciales
  precargadas en este archivo ni en ningún otro del proyecto.
- ``stop_tunnel()``: detiene el túnel activo.
- ``get_status()``: estado actual para refrescos manuales.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any, Optional

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.logger import get_logger

_log = get_logger("ui.webapp")

DIST_DIR = _PROJECT_ROOT / "web_pwa" / "dist"


class DesktopBridgeAPI:
    """Objeto expuesto a JavaScript como ``window.pywebview.api``."""

    def __init__(self) -> None:
        self._tunnel = None
        self._tunnel_thread: Optional[threading.Thread] = None
        self._tunnel_url: Optional[str] = None
        self._last_error: Optional[str] = None
        self._lock = threading.Lock()

    def start_tunnel(self, access_token: str, user_id: str, email: str = "") -> dict[str, Any]:
        """Inicia el túnel inverso usando la sesión de Supabase ya autenticada.

        No recibe ni requiere usuario/contraseña de proxy: se resuelven
        desde la tabla ``proxy_configs`` del usuario autenticado.
        """
        with self._lock:
            if self._tunnel is not None:
                return {"ok": False, "error": "El túnel ya está activo."}

            from reverse_tunnel import ReverseTunnelBridge

            bridge = ReverseTunnelBridge(server="a.pinggy.io", server_port=443, bridge_port=8765)
            self._tunnel = bridge
            self._tunnel_url = None
            self._last_error = None

        result_event = threading.Event()
        result: dict[str, Any] = {}

        def _on_url(url: str) -> None:
            self._tunnel_url = url
            result["ok"] = True
            result["tunnel_url"] = url
            result_event.set()

        def _on_error(msg: str) -> None:
            self._last_error = msg
            result["ok"] = False
            result["error"] = msg
            result_event.set()

        def _worker() -> None:
            try:
                bridge.run_with_session(
                    access_token, user_id, email,
                    on_url_found=_on_url, on_error=_on_error,
                )
            except Exception as exc:  # noqa: BLE001 - reportar cualquier fallo a la UI
                _log.error("Fallo iniciando el túnel: %s", exc, exc_info=True)
                if not result_event.is_set():
                    result["ok"] = False
                    result["error"] = str(exc)
                    result_event.set()
            finally:
                with self._lock:
                    self._tunnel = None

        self._tunnel_thread = threading.Thread(target=_worker, daemon=True)
        self._tunnel_thread.start()

        # Espera acotada a que el handshake produzca URL o error, para dar
        # una respuesta síncrona al botón "Iniciar Túnel Nube" de la UI.
        got_result = result_event.wait(timeout=25.0)
        if not got_result:
            return {"ok": False, "error": "Tiempo de espera agotado conectando con el proxy."}
        return result

    def stop_tunnel(self) -> dict[str, Any]:
        with self._lock:
            self._tunnel = None
            self._tunnel_url = None
        return {"ok": True}

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active": self._tunnel is not None,
                "tunnel_url": self._tunnel_url,
                "last_error": self._last_error,
            }


def check_desktop_webview_support() -> tuple[bool, str]:
    """Comprueba si el entorno soporta abrir la ventana WebView de escritorio."""
    if not DIST_DIR.exists():
        return False, (
            f"No se encontró {DIST_DIR}. Compila la PWA primero: "
            "cd web_pwa && npm install && npm run build"
        )
    try:
        import webview  # noqa: F401
    except ImportError:
        return False, "Falta 'pywebview'. Instala con: pip install pywebview"
    return True, "ok"


def run_desktop_app(start_url: Optional[str] = None) -> int:
    """Abre la ventana de escritorio AZZAZEL con el mismo diseño que la web."""
    ok, reason = check_desktop_webview_support()
    if not ok:
        print(f"[✗] No se pudo abrir la ventana de escritorio: {reason}")
        return 1

    import webview

    api = DesktopBridgeAPI()
    target = start_url or str(DIST_DIR / "index.html")

    window = webview.create_window(
        "AZZAZEL — Nube Privada & Control PC",
        target,
        js_api=api,
        width=430,
        height=860,
        min_size=(380, 640),
        background_color="#070a13",
    )
    webview.start(debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_desktop_app())
