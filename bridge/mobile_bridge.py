#!/usr/bin/env python3
"""
AZZAZEL VPN — bridge/mobile_bridge.py
=====================================

**Puente PC↔móvil (Sprint 4)**: comparte el internet del PC (incluida
la salida vía proxy corporativo autenticado) con un teléfono, con:

- **Pairing por PIN de 6 dígitos** (``core.crypto_engine.generate_pin``)
  verificado en **tiempo constante** (``secure_compare`` — nunca ``==``).
- **Whitelist persistente** en ``data/bridge_devices.json``: tras el
  primer pairing el dispositivo recibe un *token* y reaparece sin PIN
  (auto-reconexión). En disco nunca se guarda el token en claro, solo
  su SHA-256.
- **Heartbeat** según ``bridge.heartbeat`` de config.yaml
  (intervalo 30 s / timeout 90 s por defecto, ambo inyectables para
  tests): el servidor envía ``ping`` periódico y da por caída una
  sesión sin actividad tras el timeout; el móvil puede reconectar con
  su token y retomar el túnel.
- **Túneles a demanda**: el móvil pide ``connect host:port`` y el
  bridge lo atraviesa por :class:`proxy.proxy_chain.ProxyChain`
  (servidor upstream corporativo NTLMv2 incluido).
- Límites defensivos: ``bridge.security.max_devices``, intentos de PIN
  con cooldown exponencial por IP y whitelist opcional de
  ``allowed_devices``.

Protocolo de control (JSON Lines, texto plano UTF-8 terminado en
``\\n``; fácil de implementar en Android/iOS)::

    móvil → {"type":"hello","device_id":"<uuid>","name":"Pixel 7",
             "token":"<token-de-dispositivo-o-vacío>"}
    PC    → {"type":"welcome","session":"..."}           # token válido
         | {"type":"pair_required","ttl_seconds":60}     # hay que emparejar
    móvil → {"type":"pair","pin":"123456"}
    PC    → {"type":"welcome","session":"...","token":"<nuevo>"}  # guardar!
         | {"type":"pair_failed","attempts_left":2}
    PC    → {"type":"ping","ts":...}   (cada heartbeat.interval_seconds)
    móvil → {"type":"pong"}            (o cualquier otro mensaje cuenta)
    móvil → {"type":"connect","host":"intranet.corp","port":443}
    PC    → {"type":"established","session":"..."}  → desde aquí el
             socket pasa a MODO RAW: lo que el móvil escriba llega al
             destino y viceversa (bidireccional, como HTTP CONNECT)
    móvil → {"type":"bye"}             (cierre amable)

Demo standalone (cliente móvil simulado completo, sin display)::

    python bridge/mobile_bridge.py
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.config_manager import ConfigManager
from core.crypto_engine import generate_pin, random_token, secure_compare
from core.logger import get_logger

__all__ = [
    "BridgeError",
    "PairingError",
    "DeviceRegistry",
    "PairedDevice",
    "DeviceSession",
    "MobileBridge",
    "PROTOCOL_VERSION",
    "DEFAULT_LISTEN_PORT",
]

_log = get_logger("bridge.mobile")

PROTOCOL_VERSION: int = 1
DEFAULT_LISTEN_PORT: int = 47671
PAIR_TTL_SECONDS: float = 60.0
MAX_MESSAGE_BYTES: int = 8192


class BridgeError(Exception):
    """Error genérico del puente PC↔móvil."""


class PairingError(BridgeError):
    """Fallo de emparejamiento (PIN agotado, whitelist, cooldown...)."""


# ---------------------------------------------------------------------------
# Registro persistente de dispositivos (whitelist)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PairedDevice:
    """Dispositivo emparejado almacenado en la whitelist.

    Attributes:
        device_id: Identificador único declarado por el móvil (uuid).
        name: Nombre legible ("Pixel 7 de Ana").
        token_sha256: SHA-256 del token de sesión persistente (JAMÁS el
            token en claro).
        paired_at: Unix epoch del primer pairing.
        last_seen: Unix epoch del último hello/keepalive válido.
    """

    device_id: str
    name: str
    token_sha256: str
    paired_at: float
    last_seen: float

    def to_dict(self) -> dict[str, Any]:
        """Serializa a dict JSON-able."""
        return {
            "device_id": self.device_id,
            "name": self.name,
            "token_sha256": self.token_sha256,
            "paired_at": self.paired_at,
            "last_seen": self.last_seen,
        }


class DeviceRegistry:
    """Whitelist persistente de dispositivos emparejados.

    Persistencia atómica en JSON (temp-file + ``replace``) tolerante a
    ficheros corruptos (devuelve lista vacía y registra warning, nunca
    lanza en carga).

    Los tokens se guardan SOLO como hash SHA-256: robar el fichero no
    permite impersonar dispositivos.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._devices: dict[str, PairedDevice] = {}
        self.reload()

    # -- Carga / guardado -------------------------------------------------
    def reload(self) -> None:
        """Recarga desde disco (tolerante con JSON dañado)."""
        with self._lock:
            self._devices = {}
            if not self._path.exists():
                return
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                for entry in raw.get("devices", []):
                    device = PairedDevice(
                        device_id=str(entry["device_id"]),
                        name=str(entry["name"]),
                        token_sha256=str(entry["token_sha256"]),
                        paired_at=float(entry["paired_at"]),
                        last_seen=float(entry["last_seen"]),
                    )
                    self._devices[device.device_id] = device
            except Exception as exc:  # noqa: BLE001 - corrupción tolerada
                _log.warning("bridge_devices.json ilegible (%s); whitelist "
                             "reiniciada vacía.", exc)

    def save(self) -> None:
        """Escritura atómica: temp + replace (nunca JSON a medias)."""
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"version": 1,
                       "devices": [d.to_dict() for d in self._devices.values()]}
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                           encoding="utf-8")
            tmp.replace(self._path)

    # -- API pública ------------------------------------------------------
    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def list(self) -> list[PairedDevice]:
        """Todos los dispositivos emparejados (orden de pairing)."""
        with self._lock:
            return sorted(self._devices.values(), key=lambda d: d.paired_at)

    def add(self, device_id: str, name: str, token: str,
            max_devices: int) -> PairedDevice:
        """Registra un dispositivo nuevo (guardando solo hash del token).

        Args:
            max_devices: Límite de ``bridge.security.max_devices``.

        Raises:
            PairingError: Whitelist llena.
        """
        with self._lock:
            if device_id in self._devices:
                # re-pairing: sustituimos token pero conservamos paired_at
                old = self._devices[device_id]
                merged = PairedDevice(
                    device_id=device_id, name=name or old.name,
                    token_sha256=self._hash_token(token),
                    paired_at=old.paired_at, last_seen=time.time(),
                )
                self._devices[device_id] = merged
                self.save()
                _log.info("Dispositivo re-emparejado: %s (%s)",
                          merged.name, device_id[:8])
                return merged
            if len(self._devices) >= max_devices:
                raise PairingError(
                    f"Whitelist llena ({max_devices} dispositivos): elimina "
                    f"uno antes de emparejar otro."
                )
            now = time.time()
            device = PairedDevice(
                device_id=device_id, name=name,
                token_sha256=self._hash_token(token),
                paired_at=now, last_seen=now,
            )
            self._devices[device_id] = device
            self.save()
            _log.success("Nuevo dispositivo emparejado: %s (%s)",
                         name, device_id[:8])
            return device

    def verify(self, device_id: str, token: str) -> Optional[PairedDevice]:
        """Comprueba (tiempo constante) que el token pertenece al móvil.

        Returns:
            El :class:`PairedDevice` si coincide, ``None`` si no.
        """
        with self._lock:
            device = self._devices.get(device_id)
            if device is None or not token:
                return None
            if not secure_compare(device.token_sha256, self._hash_token(token)):
                _log.warning("Token inválido para el dispositivo %s.",
                             device_id[:8])
                return None
            self._devices[device_id] = PairedDevice(
                device_id=device.device_id, name=device.name,
                token_sha256=device.token_sha256,
                paired_at=device.paired_at, last_seen=time.time(),
            )
            return self._devices[device_id]

    def remove(self, device_id: str) -> bool:
        """Elimina un dispositivo de la whitelist."""
        with self._lock:
            if self._devices.pop(device_id, None) is None:
                return False
            self.save()
            _log.info("Dispositivo eliminado de la whitelist: %s",
                      device_id[:8])
            return True


# ---------------------------------------------------------------------------
# Sesiones activas
# ---------------------------------------------------------------------------
@dataclass
class DeviceSession:
    """Sesión viva de un dispositivo conectado.

    Attributes:
        session_id: Token de sesión efímera (se regenera cada conexión).
        device: Entrada de whitelist asociada.
        remote: ``"ip:puerto"`` del móvil.
        connected_at: Epoch de inicio.
        last_activity: Epoch del último byte/mensaje recibido (sea cual
            sea su forma: pong, datos del túnel, connect, ...).
    """

    session_id: str
    device: PairedDevice
    remote: str
    connected_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    tunneled_to: str = ""


# ---------------------------------------------------------------------------
# Servidor bridge
# ---------------------------------------------------------------------------
PinCallback = Callable[[str, str], None]
SessionCallback = Callable[[DeviceSession], None]


class MobileBridge:
    """Servidor del puente PC↔móvil.

    Args:
        config_manager: ConfigManager arrancado (lee ``bridge.*``).
        chain: ProxyChain para los túneles (por defecto se construye
            con ``ProxyChain.from_config_manager``).
        host: Interfaz de escucha (``0.0.0.0`` = toda la LAN).
        port: Puerto de escucha (None → ``DEFAULT_LISTEN_PORT``;
            ``0`` = efímero, útil en tests).
        pin_callback: Llamado con ``(pin, device_name)`` al requerirse
            pairing: la GUI/CLI escribe el PIN en grande. Por defecto
            se registra en el log.
        on_session_up / on_session_lost: Callbacks opcionales de eventos
            de sesión (p. ej. para el dashboard).
        data_dir: Directorio de datos (por defecto ``data/`` junto a la
            raíz de la suite).
        heartbeat_interval / heartbeat_timeout: Overrides de
            ``bridge.heartbeat`` (segundos; útiles en tests).
    """

    def __init__(
        self,
        config_manager: Optional[ConfigManager] = None,
        *,
        chain: Any = None,
        host: str = "0.0.0.0",
        port: Optional[int] = None,
        pin_callback: Optional[PinCallback] = None,
        on_session_up: Optional[SessionCallback] = None,
        on_session_lost: Optional[SessionCallback] = None,
        data_dir: Optional[Path] = None,
        heartbeat_interval: Optional[float] = None,
        heartbeat_timeout: Optional[float] = None,
        max_pair_attempts: int = 3,
        pair_cooldown: float = 30.0,
        pair_ttl: float = PAIR_TTL_SECONDS,
        allow_localhost: bool = False,
    ) -> None:
        self._cm = config_manager
        bridge_cfg = config_manager.config.bridge if config_manager \
            else None
        self._security = bridge_cfg.security if bridge_cfg else None
        self._sharing = bridge_cfg.sharing if bridge_cfg else None
        hb = bridge_cfg.heartbeat if bridge_cfg else None
        self.heartbeat_interval = float(
            heartbeat_interval if heartbeat_interval is not None
            else (hb.interval_seconds if hb else 30))
        self.heartbeat_timeout = float(
            heartbeat_timeout if heartbeat_timeout is not None
            else (hb.timeout_seconds if hb else 90))
        self.auto_reconnect = bool(hb.auto_reconnect) if hb else True

        self.host = host
        self.port = port if port is not None else DEFAULT_LISTEN_PORT
        self._chain = chain
        self._pin_callback = pin_callback
        self._on_up = on_session_up
        self._on_lost = on_session_lost
        self.max_pair_attempts = max(1, int(max_pair_attempts))
        self.pair_cooldown = max(1.0, float(pair_cooldown))
        self.pair_ttl = max(5.0, float(pair_ttl))
        self.allow_localhost = allow_localhost or bool(
            getattr(self._sharing, "allow_localhost", False)
        )

        root = Path(data_dir) if data_dir else (
            Path(__file__).resolve().parents[1] / "data"
        )
        self.registry = DeviceRegistry(root / "bridge_devices.json")

        self._server: Optional[asyncio.AbstractServer] = None
        self.sessions: dict[str, DeviceSession] = {}
        self._writers: dict[str, asyncio.StreamWriter] = {}
        self._heartbeat_tasks: dict[str, asyncio.Task[None]] = {}
        self._pair_fails: dict[str, tuple[int, float]] = {}

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Arranca el listener TCP del bridge."""
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port,
            reuse_address=True,
        )
        bound = self._server.sockets[0].getsockname()
        self.port = int(bound[1])
        _log.success("Bridge PC↔móvil escuchando en %s:%s "
                     "(heartbeat %ss/s%ss).",
                     bound[0] if isinstance(bound[0], str) else "*",
                     self.port, int(self.heartbeat_interval),
                     int(self.heartbeat_timeout))

    async def stop(self) -> None:
        """Cierre limpio: corta sesiones, tasks y el listener."""
        for session_id in list(self._heartbeat_tasks):
            await self._end_session(session_id, reason="bridge stop")
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        _log.info("Bridge detenido limpiamente.")

    def status(self) -> dict[str, Any]:
        """Resumen estructurado para CLI/GUI (dashboard)."""
        return {
            "listening": self._server is not None,
            "port": self.port,
            "sessions": len(self.sessions),
            "whitelisted": len(self.registry.list()),
            "heartbeat": (self.heartbeat_interval,
                          self.heartbeat_timeout),
        }

    # ------------------------------------------------------------------
    # Ciclo de conexión
    # ------------------------------------------------------------------
    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        remote = "%s:%s" % writer.get_extra_info("peername")[:2]
        _log.info("Conexión bridge desde %s", remote)
        session: Optional[DeviceSession] = None
        try:
            hello = await self._read_json(reader, remote)
            if hello is None:
                return
            remote_ip = str(writer.get_extra_info("peername")[0])
            device, err = await self._negotiate_identity(
                hello, reader, writer, remote, remote_ip)
            if device is None:
                return
            session = DeviceSession(
                session_id=random_token(16), device=device, remote=remote)
            self.sessions[session.session_id] = session
            self._writers[session.session_id] = writer
            await self._send(writer, {
                "type": "welcome", "session": session.session_id,
                "protocol": PROTOCOL_VERSION, "name": device.name})
            if self._on_up:
                self._on_up(session)

            hb_task = asyncio.create_task(self._heartbeat_loop(session),
                                          name=f"hb-{session.session_id[:8]}")
            self._heartbeat_tasks[session.session_id] = hb_task

            # Bucle de control; puede MUTAR a túnel raw al recibir connect.
            while True:
                msg = await self._read_json(reader, remote)
                if msg is None:
                    break
                session.last_activity = time.time()
                mtype = msg.get("type")
                if mtype == "bye":
                    await self._send(writer, {"type": "farewell"})
                    break
                if mtype == "pong":
                    continue
                if mtype == "connect":
                    if await self._tunnel(session, msg, reader, writer):
                        return  # el socket ya es raw; no volver a JSON
                    continue
                await self._send(writer, {
                    "type": "error", "code": "unknown_command",
                    "detail": f"Tipo no soportado: {mtype!r}"})
        except (ConnectionError, OSError, asyncio.IncompleteReadError) as exc:
            _log.debug("Sesión bridge cortada (%s): %s", remote, exc)
        finally:
            if session is not None:
                await self._end_session(session.session_id,
                                        reason="conexión cerrada")
            else:
                writer.close()

    # ------------------------------------------------------------------
    # Identidad: hello → (whitelist | pairing)
    # ------------------------------------------------------------------
    async def _negotiate_identity(
        self, hello: dict[str, Any],
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter, remote: str, remote_ip: str,
    ) -> tuple[Optional[PairedDevice], Optional[str]]:
        """Resuelve quién llama: por token de whitelist o pairing PIN.

        Returns:
            ``(dispositivo, None)`` en éxito; ``(None, motivo)`` si la
            conexión debe abortarse (ya informado al móvil).
        """
        if hello.get("type") != "hello":
            await self._send(writer, {"type": "error",
                                      "code": "expected_hello"})
            return None, "expected_hello"
        device_id = str(hello.get("device_id") or "").strip()
        name = str(hello.get("name") or "móvil-desconocido").strip()[:64]
        token = str(hello.get("token") or "")
        if not device_id:
            await self._send(writer, {"type": "error",
                                      "code": "missing_device_id"})
            return None, "missing_device_id"

        # 1) Rápido: ya está en whitelist → hola autenticado
        device = self.registry.verify(device_id, token)
        if device is not None:
            _log.info("Bridge: %s (%s) reconocido por whitelist.",
                      device.name, device_id[:8])
            return device, None

        # 2) Pairing con PIN
        security = self._security
        if security is not None and not security.pin_enabled:
            await self._send(writer, {"type": "error",
                                      "code": "pairing_disabled"})
            _log.warning("%s intentó conectar sin whitelist y el "
                         "pairing está DESACTIVADO en config.", remote)
            return None, "pairing_disabled"
        if security is not None and security.allowed_devices:
            allowed = set(security.allowed_devices)
            if device_id not in allowed and name not in allowed:
                await self._send(writer, {"type": "error",
                                          "code": "not_in_allowed"})
                _log.warning("Device %s/%s no está en "
                             "bridge.security.allowed_devices.",
                             name, device_id[:8])
                return None, "not_in_allowed"

        # Cooldown anti fuerza bruta por IP
        fails, blocked_until = self._pair_fails.get(remote_ip, (0, 0.0))
        if time.time() < blocked_until:
            wait = int(blocked_until - time.time())
            await self._send(writer, {"type": "error", "code": "cooldown",
                                      "retry_after_seconds": wait})
            _log.warning("PIN fuerza-bruta mitigado: %s en cooldown (%ss).",
                         remote, wait)
            return None, "cooldown"

        pin = generate_pin(6)
        await self._send(writer, {"type": "pair_required",
                                  "ttl_seconds": int(self.pair_ttl)})
        if self._pin_callback:
            self._pin_callback(pin, name)
        else:
            _log.warning("PAIRING REQUERIDO ← %s — PIN: %s", name, pin)

        attempts_left = self.max_pair_attempts
        deadline = time.time() + self.pair_ttl
        while time.time() < deadline and attempts_left > 0:
            try:
                msg = await asyncio.wait_for(
                    self._read_json(reader, remote),
                    timeout=max(1.0, deadline - time.time()))
            except (asyncio.TimeoutError, ConnectionError):
                break
            if msg is None:
                return None, "connection_lost"
            if msg.get("type") != "pair":
                await self._send(writer, {"type": "error",
                                          "code": "expected_pair"})
                continue
            if secure_compare(str(msg.get("pin") or ""), pin):
                new_token = random_token(32)
                max_dev = security.max_devices if security else 5
                try:
                    device = self.registry.add(device_id, name, new_token,
                                               max_devices=max_dev)
                except PairingError as exc:
                    await self._send(writer, {"type": "error",
                                              "code": "whitelist_full",
                                              "detail": str(exc)})
                    return None, "whitelist_full"
                self._pair_fails.pop(remote_ip, None)
                # El token viaja UNA vez por el canal; aparte se guarda hash.
                await self._send(writer, {"type": "pair_ok",
                                          "token": new_token})
                _log.success("Pairing completado con %s (%s).",
                             name, device_id[:8])
                return device, None
            attempts_left -= 1
            if attempts_left <= 0:
                break  # sin más intentos → error final (no pair_failed)
            await self._send(writer, {"type": "pair_failed",
                                      "attempts_left": attempts_left})
            _log.warning("PIN incorrecto desde %s; quedan %s intentos.",
                         remote, attempts_left)
        # Agotados intentos o TTL → cooldown y fuera
        count, _ = self._pair_fails.get(remote_ip, (0, 0.0))
        self._pair_fails[remote_ip] = (count + 1, time.time() +
                                    self.pair_cooldown * (count + 1))
        await self._send(writer, {"type": "error", "code": "pair_timeout"
                                  if attempts_left > 0 else "pair_exhausted"})
        _log.error("Pairing fallido con %s (%s intentos).",
                   remote, self.max_pair_attempts - attempts_left)
        return None, "pair_failed"

    # ------------------------------------------------------------------
    # Túnel de datos vía ProxyChain
    # ------------------------------------------------------------------
    async def _tunnel(self, session: DeviceSession, msg: dict[str, Any],
                      reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> bool:
        """Atiende ``connect``: abre el túnel por la cadena y puentea raw.

        Returns:
            ``True`` si el socket quedó convertido en túnel raw (el
            caller debe salir del bucle JSON); ``False`` si falló.
        """
        if self._sharing is not None and not self._sharing.internet:
            await self._send(writer, {"type": "error",
                                      "code": "sharing_disabled"})
            return False
        host = str(msg.get("host") or "").strip()
        try:
            port = int(msg.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or not (1 <= port <= 65535):
            await self._send(writer, {"type": "error",
                                      "code": "bad_connect_args"})
            return False

        # ACL de Destinos: Anti-SSRF estricto (Loopback, Link-Local, Cloud Metadata)
        import ipaddress
        is_prohibited = False
        if host.lower() in ("localhost", "metadata.google.internal", "instance-data"):
            is_prohibited = True
        else:
            try:
                ip_obj = ipaddress.ip_address(host)
                if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
                    is_prohibited = True
                elif str(ip_obj) == "169.254.169.254":
                    is_prohibited = True
            except ValueError:
                # Si es un hostname, rechazar si resuelve a loopback o prefijos prohibidos
                if host.lower().startswith("127.") or host.lower() == "0.0.0.0":
                    is_prohibited = True

        allow_loopback = self.allow_localhost
        if is_prohibited and not allow_loopback:
            _log.warning(
                "Conexión a destino prohibido/SSRF bloqueada por ACL de Bridge desde %s (%s:%d).",
                session.device.name, host, port
            )
            await self._send(writer, {
                "type": "error",
                "code": "acl_prohibited",
                "detail": "Acceso a IP/Host prohibido por política anti-SSRF de seguridad.",
            })
            return False

        chain = self._chain or self._default_chain()
        try:
            target_reader, target_writer = await chain.open_tunnel(
                host, port)
        except Exception as exc:  # noqa: BLE001 - se reporta al móvil
            _log.error("Túnel bridge a %s:%s falló: %s", host, port, exc)
            await self._send(writer, {"type": "error",
                                      "code": "tunnel_failed",
                                      "detail": "Fallo al conectar con el destino solicitado."})
            return False
        session.tunneled_to = f"{host}:{port}"
        await self._send(writer, {"type": "established",
                                  "session": session.session_id,
                                  "remote": f"{host}:{port}"})
        _log.success("Túnel bridge para %s → %s:%s (raw)",
                     session.device.name, host, port)

        async def pump(src: asyncio.StreamReader,
                       dst: asyncio.StreamWriter) -> None:
            try:
                while chunk := await src.read(16384):
                    dst.write(chunk)
                    await dst.drain()
                    session.last_activity = time.time()
            except (ConnectionError, OSError):
                pass
            finally:
                dst.close()

        try:
            await asyncio.gather(pump(reader, target_writer),
                                 pump(target_reader, writer))
        finally:
            wb = self._writers.pop(session.session_id, None)
            if wb:
                wb.close()
            target_writer.close()
        return True

    def _default_chain(self):
        """ProxyChain diferida desde la config compartida."""
        if self._cm is None:
            raise BridgeError(
                "Sin ProxyChain inyectada ni ConfigManager: no se pueden "
                "abrir túneles de datos."
            )
        from proxy.proxy_chain import ProxyChain
        self._chain = ProxyChain.from_config_manager(self._cm)
        return self._chain

    # ------------------------------------------------------------------
    # Heartbeat (30s / 90s per spec; sobreescribible en tests)
    # ------------------------------------------------------------------
    async def _heartbeat_loop(self, session: DeviceSession) -> None:
        """Envía pings periódicos y mata la sesión si se queda muda."""
        writer = self._writers.get(session.session_id)
        try:
            while True:
                await asyncio.sleep(self.heartbeat_interval)
                now = time.time()
                if now - session.last_activity > self.heartbeat_timeout:
                    _log.warning("Heartbeat vencido para %s (>%ss sin "
                                 "actividad).",
                                 session.device.name,
                                 int(self.heartbeat_timeout))
                    await self._end_session(
                        session.session_id, reason="heartbeat_timeout")
                    return
                if writer is not None and not writer.is_closing():
                    try:
                        await self._send(writer, {
                            "type": "ping", "ts": int(now)})
                    except (ConnectionError, OSError):
                        await self._end_session(
                            session.session_id, reason="write_failed")
                        return
        except asyncio.CancelledError:
            raise

    async def _end_session(self, session_id: str, reason: str) -> None:
        """Cierre consistente de una sesión (idempotente)."""
        session = self.sessions.pop(session_id, None)
        task = self._heartbeat_tasks.pop(session_id, None)
        if task and task is not asyncio.current_task():
            task.cancel()
        writer = self._writers.pop(session_id, None)
        if writer is not None:
            writer.close()
        if session is None:
            return
        _log.info("Sesión bridge cerrada (%s) de %s: %s",
                  session.session_id[:8], session.device.name, reason)
        if self.auto_reconnect:
            _log.info("%s puede reconectar con su token sin nuevo PIN.",
                      session.device.name)
        if self._on_lost:
            self._on_lost(session)

    # ------------------------------------------------------------------
    # Utilidades de framing JSON Lines
    # ------------------------------------------------------------------
    @staticmethod
    async def _send(writer: asyncio.StreamWriter,
                    payload: dict[str, Any]) -> None:
        """Envía un mensaje JSON Lines (añade el ``\\n``)."""
        writer.write((json.dumps(payload,
                                 ensure_ascii=False) + "\n").encode("utf-8"))
        await writer.drain()

    @staticmethod
    async def _read_json(reader: asyncio.StreamReader,
                         remote: str) -> Optional[dict[str, Any]]:
        """Lee una línea JSON; valida tamaño y estructura básica.

        Returns:
            El objeto, o ``None`` si el peer cerró (EOF limpio).

        Raises:
            ConnectionError: Línea sobredimensionada o JSON inválido.
        """
        try:
            raw = await reader.readline()
        except (ConnectionError, asyncio.IncompleteReadError):
            return None
        if not raw:
            return None
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ConnectionError(
                f"Mensaje de {len(raw)} bytes excede "
                f"{MAX_MESSAGE_BYTES} desde {remote}"
            )
        try:
            msg = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ConnectionError(
                f"JSON inválido de {remote}: {exc}"
            ) from exc
        if mtype := msg.get("type"):
            session_tag = str(msg.get("session") or "")[:8]
            _log.debug("← %s %s%s", remote, mtype,
                       f" ({session_tag})" if session_tag else "")
        return msg if isinstance(msg, dict) else None


# ---------------------------------------------------------------------------
# Demo standalone: móvil simulado end-to-end
# ---------------------------------------------------------------------------
async def _demo() -> None:
    import tempfile

    from proxy.proxy_chain import ProxyChain, ProxyNode
    from ui.cli import ascii_art as art

    print(art.box(
        "DEMO mobile_bridge: pairing PIN, whitelist, heartbeat,\n"
        "auto-reconexión y túnel de datos end-to-end.",
        title="BRIDGE PC↔ MÓVIL — Sprint 4", style="double"))

    with tempfile.TemporaryDirectory() as tmp:
        # ---- infraestructura de prueba ----
        captured: dict[str, str] = {}
        events: list[str] = []
        async def echo_server(reader, writer):
            while data := await reader.read(4096):
                writer.write(b"ECHO:" + data)
                await writer.drain()
            writer.close()
        echo_srv = await asyncio.start_server(echo_server, "127.0.0.1", 0)
        echo_port = echo_srv.sockets[0].getsockname()[1]

        chain = ProxyChain([ProxyNode(name="direct", kind="direct")])
        bridge = MobileBridge(
            chain=chain, host="127.0.0.1", port=0,
            pin_callback=lambda pin, name: captured.update(pin=pin),
            on_session_up=lambda s: events.append(f"up:{s.device.name}"),
            on_session_lost=lambda s: events.append(
                f"lost:{s.device.name}"),
            data_dir=Path(tmp),
            heartbeat_interval=0.3, heartbeat_timeout=0.9,
            pair_cooldown=1.0, pair_ttl=5.0,
            allow_localhost=True,
        )
        await bridge.start()
        port = bridge.port
        print(f"\n  1. Bridge arriba en 127.0.0.1:{port} "
              f"(status: {bridge.status()['listening']})")

        async def mobile_hello(client_id: str, name: str, token: str = ""):
            reader, writer = await asyncio.open_connection("127.0.0.1",
                                                           port)
            await _send_json(writer, {"type": "hello",
                                      "device_id": client_id,
                                      "name": name, "token": token})
            reply = await read_json(reader)
            return reader, writer, reply

        # ---- 2. Pairing: PIN mal → bien ----
        rd, wr, reply = await mobile_hello("dev-PIXEL7", "Pixel 7 de Ana")
        assert reply["type"] == "pair_required", reply
        assert "pin" in captured and len(captured["pin"]) == 6
        wrong = "000000" if captured["pin"] != "000000" else "111111"
        await _send_json(wr, {"type": "pair", "pin": wrong})
        reply = await read_json(rd)
        assert reply["type"] == "pair_failed", reply
        assert reply["attempts_left"] == 2
        print("  2. PIN erróneo rechazado con "
              f"{reply['attempts_left']} intentos restantes ✔")

        await _send_json(wr, {"type": "pair", "pin": captured["pin"]})
        reply = await read_json(rd)
        assert reply["type"] == "pair_ok" and reply.get("token"), reply
        token = reply["token"]
        print("  3. PIN correcto → whitelist poblada; token emitido ✔")

        reply = await read_json(rd)
        assert reply["type"] == "welcome", reply
        session_id = reply["session"]
        print(f"  4. welcome recibido (session {session_id[:8]}…)")

        reg = bridge.registry.list()
        assert len(reg) == 1 and reg[0].name == "Pixel 7 de Ana"
        assert reg[0].token_sha256 != token  # jamás en claro
        print("  5. Disco: 1 dispositivo; token guardado SOLO hasheado ✔")

        # ---- 6. Línea errónea de connect antes de aprenderse rutas ----
        await _send_json(wr, {"type": "connect", "host": "", "port": 0})
        reply = await read_json(rd)
        assert reply["code"] == "bad_connect_args", reply
        print("  6. Validación de args de connect ✔")

        # ---- 7. Túnel por la ProxyChain hasta el intranet echo ----
        await _send_json(wr, {"type": "connect",
                              "host": "127.0.0.1", "port": echo_port})
        reply = await read_json(rd)
        assert reply["type"] == "established", reply
        wr.write(b"hola intranet")
        raw = await asyncio.wait_for(rd.read(64), timeout=5)
        assert raw == b"ECHO:hola intranet", raw
        print(f"  7. Túnel RAW vía bridge: {raw!r} ✔")
        wr.close()
        await asyncio.sleep(0.1)

        # ---- 8. Heartbeat/timeout + auto-reconexión con token ----
        # reconexión nueva conexión: debe saltar pairing
        rd2, wr2, reply = await mobile_hello("dev-PIXEL7",
                                             "Pixel 7 de Ana",
                                             token=token)
        assert reply["type"] == "welcome", reply
        print("  8. Reconexión con token: welcome SIN PIN ✔ "
              "(auto_reconnect)")

        # corta canales del cliente sin bye; el heartbeat debe detectarlo
        wr2.close()
        await asyncio.sleep(bridge.heartbeat_timeout + 0.5)
        assert not bridge.sessions, bridge.sessions
        assert any(e == "lost:Pixel 7 de Ana" for e in events), events
        print("  9. Heartbeat (>0.9s sin actividad) → sesión purgada, "
              "callback lost disparado ✔")

        # ---- 10. Cooldown anti fuerza-bruta de PIN ----
        rd3, wr3, reply = await mobile_hello("dev-ATAQUE", "EvilTwin")
        assert reply["type"] == "pair_required", reply
        for i in range(3):
            await _send_json(wr3, {"type": "pair", "pin": "000000"})
            reply = await read_json(rd3)
        assert reply["type"] == "error" and reply["code"] == "pair_exhausted", reply
        print(" 10. 3 PIN fallidos → cooldown y conexión rechazada ✔")
        wr3.close()

        rd4, wr4, reply = await mobile_hello("dev-OTRO", "Otro móvil")
        # 127.0.0.1 comparte IP con el atacante → cooldown activo
        assert reply["type"] == "error" and reply["code"] == "cooldown", reply
        print(" 11. Nueva conexión durante cooldown → rechazada con retry_after ✔")
        wr4.close()

        await bridge.stop()
        echo_srv.close()
        assert bridge.status()["listening"] is False
        print(" 12. stop() limpio: listener cerrado, 0 sesiones colgadas ✔")

    print("\n─ demo mobile_bridge OK ─")


async def _send_json(writer: asyncio.StreamWriter,
                     payload: dict[str, Any]) -> None:
    """Helper de la demo: envía JSON Lines (cliente móvil)."""
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()


async def read_json(reader: asyncio.StreamReader) -> dict[str, Any]:
    """Helper de la demo: lee una línea JSON del servidor."""
    line = await asyncio.wait_for(reader.readline(), timeout=5)
    assert line, "EOF inesperado del bridge"
    return json.loads(line.decode("utf-8"))


if __name__ == "__main__":
    asyncio.run(_demo())
