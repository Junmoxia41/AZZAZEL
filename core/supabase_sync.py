"""
AZZAZEL VPN — core/supabase_sync.py
===================================
Sincroniza en tiempo real el enlace activo del túnel inverso, el estado del
PC y la configuración del proxy corporativo con el backend de Supabase, para
que la PWA móvil los consuma.

Modelo de seguridad (multi-usuario real):
- Cada usuario de AZZAZEL inicia sesión con SU PROPIA cuenta de Supabase Auth
  (la misma cuenta que usa en la app web). Nunca hay un usuario ni contraseña
  precargados en el código.
- Todas las escrituras usan el JWT de sesión del usuario autenticado, nunca
  la clave anónima "pelada": las políticas RLS de Supabase garantizan que
  cada usuario solo puede leer/escribir SUS PROPIAS filas (tunnels, devices,
  proxy_configs, audit_logs), identificadas por auth.uid().
- El proxy corporativo (host/puerto/usuario/contraseña) ya no vive en
  config.yaml local: se guarda y se lee de la tabla `proxy_configs`,
  asociada al usuario autenticado.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from core.logger import get_logger

_log = get_logger("supabase.sync")

DEFAULT_SUPABASE_URL = "https://vqbtuzauqchopdlbgylk.supabase.co"
DEFAULT_SUPABASE_ANON_KEY = "sb_publishable_3J7GWLlBDikRmzXaDnTFoQ_1oAXwKyM"


class SupabaseAuthError(RuntimeError):
    """Fallo de autenticación contra Supabase Auth (credenciales o red)."""


class SupabaseSyncManager:
    """Gestiona la sesión, el túnel activo y la config de proxy en Supabase.

    Requiere que el usuario inicie sesión (:meth:`sign_in`) con el mismo
    correo/contraseña que usa en la PWA. Sin sesión, ninguna operación de
    escritura/lectura de datos propios es posible (RLS lo impide).
    """

    def __init__(
        self,
        supabase_url: str = DEFAULT_SUPABASE_URL,
        supabase_anon_key: str = DEFAULT_SUPABASE_ANON_KEY,
    ) -> None:
        self.supabase_url = supabase_url.rstrip("/")
        self.supabase_anon_key = supabase_anon_key
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.user_id: Optional[str] = None
        self.email: Optional[str] = None

        self.current_tunnel_url: Optional[str] = None
        self._running = False
        self._sync_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Autenticación
    # ------------------------------------------------------------------
    @property
    def is_authenticated(self) -> bool:
        return bool(self.access_token and self.user_id)

    def sign_in(self, email: str, password: str) -> None:
        """Inicia sesión con Supabase Auth usando las credenciales del usuario.

        Lanza :class:`SupabaseAuthError` si las credenciales son inválidas o
        hay un problema de red. Nunca hay valores por defecto: el usuario
        siempre debe introducir su propio correo y contraseña.
        """
        if not email or not password:
            raise SupabaseAuthError("Correo y contraseña son obligatorios.")

        req = urllib.request.Request(
            f"{self.supabase_url}/auth/v1/token?grant_type=password",
            data=json.dumps({"email": email, "password": password}).encode("utf-8"),
            headers={
                "apikey": self.supabase_anon_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise SupabaseAuthError(f"Credenciales rechazadas por Supabase: {body}") from exc
        except Exception as exc:
            raise SupabaseAuthError(f"No se pudo contactar a Supabase: {exc}") from exc

        self.access_token = data.get("access_token")
        self.refresh_token = data.get("refresh_token")
        user = data.get("user") or {}
        self.user_id = user.get("id")
        self.email = user.get("email")

        if not self.access_token or not self.user_id:
            raise SupabaseAuthError("Respuesta de Supabase incompleta al iniciar sesión.")

        _log.info("Sesión de Supabase iniciada como %s.", self.email)

    def use_session(
        self, access_token: str, user_id: str, email: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> None:
        """Reutiliza una sesión de Supabase ya iniciada en otro contexto.

        Usado por la app de escritorio (ventana WebView): el login real lo
        hace el propio front-end web con Supabase Auth (mismo formulario que
        la PWA), y el JWT resultante se pasa aquí para que el proceso Python
        pueda leer/escribir las tablas del usuario respetando RLS — nunca se
        piden ni se guardan credenciales de correo/contraseña en Python.
        """
        if not access_token or not user_id:
            raise SupabaseAuthError("Sesión inválida: falta access_token o user_id.")
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.user_id = user_id
        self.email = email

    def sign_out(self) -> None:
        self.access_token = None
        self.refresh_token = None
        self.user_id = None
        self.email = None

    def _auth_headers(self) -> dict[str, str]:
        if not self.is_authenticated:
            raise SupabaseAuthError("No hay sesión activa; llama a sign_in() primero.")
        return {
            "apikey": self.supabase_anon_key,
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Configuración de proxy (reemplaza los defaults quemados en config.yaml)
    # ------------------------------------------------------------------
    def fetch_proxy_config(self) -> Optional[dict[str, Any]]:
        """Lee la configuración de proxy del usuario autenticado, si existe."""
        headers = self._auth_headers()
        url = (
            f"{self.supabase_url}/rest/v1/proxy_configs"
            f"?user_id=eq.{self.user_id}&select=*"
        )
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                rows = json.loads(resp.read().decode("utf-8"))
                return rows[0] if rows else None
        except Exception as exc:
            _log.debug("No se pudo leer proxy_configs: %s", exc)
            return None

    def save_proxy_config(
        self, host: str, port: int, username: str, password: str
    ) -> bool:
        """Guarda (upsert) la configuración de proxy del usuario en Supabase."""
        headers = self._auth_headers()
        headers["Prefer"] = "resolution=merge-duplicates"
        payload = {
            "user_id": self.user_id,
            "proxy_host": host,
            "proxy_port": port,
            "proxy_username": username,
            "proxy_password": password,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        req = urllib.request.Request(
            f"{self.supabase_url}/rest/v1/proxy_configs",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=8.0):
                return True
        except Exception as exc:
            _log.warning("No se pudo guardar proxy_configs: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Túnel activo
    # ------------------------------------------------------------------
    def publish_tunnel(self, tunnel_url: str, vitals: Optional[dict[str, Any]] = None) -> bool:
        """Envía la URL del túnel activo a Supabase, atada a auth.uid()."""
        if not self.is_authenticated:
            _log.debug("Sin sesión de Supabase; no se publica el túnel.")
            return False

        self.current_tunnel_url = tunnel_url
        headers = self._auth_headers()
        headers["Prefer"] = "resolution=merge-duplicates"
        payload = {
            "user_id": self.user_id,
            "tunnel_url": tunnel_url,
            "status": "online",
            "pc_name": "PC-Trabajo",
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "vitals": vitals or {},
        }

        req = urllib.request.Request(
            f"{self.supabase_url}/rest/v1/tunnels",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                _log.info("Túnel sincronizado con Supabase (%s): %s", resp.status, tunnel_url)
                return True
        except urllib.error.HTTPError as exc:
            _log.debug("Supabase rechazó la escritura (%s) - %s", exc.code, exc.reason)
            return False
        except Exception as exc:
            _log.debug("Error sincronizando con Supabase: %s", exc)
            return False

    def start_heartbeat(self, interval: float = 30.0) -> None:
        """Mantiene el estado 'online' activo periódicamente en Supabase."""
        self._running = True

        def _loop() -> None:
            while self._running:
                if self.current_tunnel_url:
                    self.publish_tunnel(self.current_tunnel_url)
                time.sleep(interval)

        self._sync_thread = threading.Thread(target=_loop, daemon=True)
        self._sync_thread.start()

    def stop(self) -> None:
        self._running = False
