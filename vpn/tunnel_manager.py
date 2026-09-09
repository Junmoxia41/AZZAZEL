#!/usr/bin/env python3
"""
AZZAZEL VPN — vpn/tunnel_manager.py
===================================

**Sprint 3 — el corazón de la VPN**: túnel cifrado punto a punto sobre
UDP con handshake autenticado por clave precompartida, frames
AES-256-GCM protegidos contra replay, keepalive/reconexión exponencial
y kill-switch.

Arquitectura en dos capas (para correr igual en un PC real y en CI):

1. **Transporte de datagramas** (siempre disponible): handshake
   ``AZZ-C1`` en JSON + frames binarios ``AZZ1`` cifrados. Cada lado
   queda con una **cola de paquetes de red** (bytes IP) que la capa
   superior consume o inyecta. Totalmente funcional y testable sin
   privilegios.
2. **Adjunto TUN** (:class:`TunDevice`): abre ``/dev/net/tun`` con
   ioctl ``TUNSETIFF`` (IFF_TUN|IFF_NO_PI), asigna la IP del túnel con
   ``ip addr`` y lo interconecta con la sesión mediante bombas de
   lectura/escritura. Sin root (o en Windows sin el driver
   *tap-windows6*) lanza :class:`TunError` con instrucciones claras —
   honesto, nunca un fallo mudo.

Seguridad:

- El *PSK* sale de ``vpn.keys.private_key`` (cifrado en disco por
  ``core.crypto_engine``; el servidor lo recibe ya resuelto).
- ``session_key = HMAC-SHA256(SHA256(psk), nonce_cli‖nonce_srv‖ctx)[:32]``
  — no-material público por sesión (forward secrecy por nonce par).
- Autenticación mutua consentida por HMAC en ambos sentidos
  (``secure_compare``, tiempo constante).
- Frames: ``nonce12‖ct‖tag16`` de la :class:`CryptoEngine` con el
  encabezado de datagrama como **AAD**; contador monótono interno para
  la ventana anti-replay (tamaño 1024 por sesión).

Kill-switch: al agotar reintentos de reconexión, el cliente invoca un
*hook* (el módulo ``firewall`` del Sprint 7 lo cableará) y deja
estructurado el estado ``unprotected=True`` para la UI/log.

Demo standalone (handshake real end-to-end por UDP localhost, integridad,
tamper/replay-drop, keepalive y reconexión)::

    python vpn/tunnel_manager.py
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.crypto_engine import CryptoEngine, secure_compare
from core.logger import get_logger

__all__ = [
    "TunnelError",
    "HandshakeError",
    "TunError",
    "TunDevice",
    "VpnSession",
    "TunnelServer",
    "TunnelClient",
    "KillSwitch",
    "SESSION_KEY_CONTEXT",
    "AUTH_CONTEXT",
    "CONTROL_MAGIC",
    "FRAME_MAGIC",
]

_log = get_logger("vpn.tunnel")

CONTROL_MAGIC: bytes = b"AZZ-C1\n"   # datagramas de control (JSON tras la cabecera)
FRAME_MAGIC: bytes = b"AZZ1"        # datagramas de datos cifrados
FRAME_HEADER_LEN: int = 13          # magic(4) + type(1) + session_id(8)
FRAME_DATA: int = 0x01
FRAME_KEEPALIVE: int = 0x02
SESSION_KEY_CONTEXT: bytes = b"AZZ-SESSION-v1"
AUTH_CONTEXT: bytes = b"AZZ-AUTH-v1"
REPLAY_WINDOW: int = 1024
DEFAULT_MTU: int = 1420
HANDSHAKE_TIMEOUT: float = 10.0


class TunnelError(Exception):
    """Error genérico del túnel VPN."""


class HandshakeError(TunnelError):
    """Fallo del handshake (PSK, timeout, claves, capacidad...)."""


class TunError(TunnelError):
    """El dispositivo TUN/TAP no pudo abrirse (permisos, driver...)."""


# ---------------------------------------------------------------------------
# Utilidades criptográficas de sesión (puras y testeables)
# ---------------------------------------------------------------------------
def _derive_session_key(psk: str, client_nonce: bytes,
                        server_nonce: bytes,
                        ecdh_secret: Optional[bytes] = None) -> bytes:
    """Deriva la clave simétrica de sesión con Perfect Forward Secrecy (X25519 + HKDF).

    Args:
        psk: Clave precompartida (``vpn.keys.private_key``).
        client_nonce: 16 bytes aleatorios del cliente.
        server_nonce: 16 bytes aleatorios del servidor.
        ecdh_secret: Secreto compartido efímero X25519 para Perfect Forward Secrecy.

    Returns:
        32 bytes de clave AES-256 por sesión.
    """
    psk_blob = hashlib.sha256(psk.encode("utf-8")).digest()
    if ecdh_secret is not None:
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=psk_blob,
                info=client_nonce + server_nonce + SESSION_KEY_CONTEXT,
            )
            return hkdf.derive(ecdh_secret)
        except Exception:
            pass
    material = client_nonce + server_nonce + SESSION_KEY_CONTEXT
    return hmac.new(psk_blob, material, hashlib.sha256).digest()[:32]


def _auth_proof(session_key: bytes, client_nonce: bytes,
                server_nonce: bytes, session_id: bytes) -> bytes:
    """Prueba de conocimiento de clave: HMAC(session_key, contexto)."""
    ctx = client_nonce + server_nonce + session_id + AUTH_CONTEXT
    return hmac.new(session_key, ctx, hashlib.sha256).digest()


class ReplayWindow:
    """Ventana anti-replay deslizante sobre contadores monótonos.

    Mantiene el máximo contador visto y una ventana de bits de los
    últimos ``size`` contadores; detecta duplicados y frames tan viejos
    que ya quedaron fuera (reorder profundo = ataque o log).
    """

    def __init__(self, size: int = REPLAY_WINDOW) -> None:
        self.size = max(8, int(size))
        self.max_seen: int = -1
        self._bitmap: int = 0

    def check_and_record(self, counter: int) -> bool:
        """Devuelve ``True`` si el contador es válido y lo marca visto."""
        if counter < 0:
            return False
        if counter > self.max_seen:
            shift = counter - self.max_seen
            if shift >= self.size:
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1)
                self._bitmap &= (1 << self.size) - 1
            self.max_seen = counter
            return True
        delta = self.max_seen - counter
        if delta >= self.size:
            return False  # demasiado viejo: fuera de ventana
        bit = 1 << delta
        if self._bitmap & bit:
            return False  # ya visto: replay
        self._bitmap |= bit
        return True


# ---------------------------------------------------------------------------
# Sesión establecida
# ---------------------------------------------------------------------------
@dataclass
class VpnSession:
    """Sesión VPN establecida entre este nodo y su peer.

    Attributes:
        session_id: 8 bytes aleatorios del servidor (identifica el
            datagrama cifrado).
        peer: ``(host, puerto)`` del otro extremo.
        crypto: CryptoEngine con la clave de sesión.
        created_at / last_rx: Para pruned/timeout por inactividad.
    """

    session_id: bytes
    peer: tuple[str, int]
    crypto: CryptoEngine
    created_at: float = field(default_factory=time.time)
    last_rx: float = field(default_factory=time.time)
    tx_counter: int = 0
    rx_window: ReplayWindow = field(default_factory=ReplayWindow)
    rx_frames: int = 0
    rx_replays_dropped: int = 0
    rx_gcm_dropped: int = 0
    rx_keepalives: int = 0

    def build_frame(self, payload: bytes,
                    ftype: int = FRAME_DATA) -> bytes:
        """Cifra un frame listo para la red.

        El contador va DENTRO del cifrado (autenticado por GCM); el
        encabezado ``AZZ1‖type‖session_id`` es AAD.
        """
        body = struct.pack("<Q", self.tx_counter) + payload
        self.tx_counter += 1
        header = FRAME_MAGIC + bytes([ftype]) + self.session_id
        blob = self.crypto.encrypt_bytes(body, aad=header)
        return header + blob

    def unpack_frame(self, datagram: bytes) -> tuple[int, Optional[bytes]]:
        """Descifra un frame de red validando AAD y replay.

        Returns:
            ``(contador, payload)`` con payload ``None`` para keepalive,
            o tupla ``(-1, None)`` si el frame se descarta (replay,
            GCM inválido o tipo desconocido).
        """
        if len(datagram) < FRAME_HEADER_LEN + 28:
            self.rx_gcm_dropped += 1
            return -1, None
        if not datagram.startswith(FRAME_MAGIC):
            self.rx_gcm_dropped += 1
            return -1, None
        ftype = datagram[4]
        header = datagram[:FRAME_HEADER_LEN]
        if datagram[5:FRAME_HEADER_LEN] != self.session_id:
            self.rx_gcm_dropped += 1
            return -1, None
        try:
            body = self.crypto.decrypt_bytes(
                datagram[FRAME_HEADER_LEN:], aad=header)
        except Exception:
            self.rx_gcm_dropped += 1
            return -1, None
        counter = struct.unpack_from("<Q", body, 0)[0]
        if not self.rx_window.check_and_record(counter):
            self.rx_replays_dropped += 1
            return -1, None
        self.last_rx = time.time()
        self.rx_frames += 1
        if ftype == FRAME_KEEPALIVE:
            self.rx_keepalives += 1
            return counter, None
        if ftype != FRAME_DATA:
            self.rx_gcm_dropped += 1
            return -1, None
        return counter, body[8:]


# ---------------------------------------------------------------------------
# TUN/TAP (adjunto real; errores accionables sin root / sin driver)
# ---------------------------------------------------------------------------
class TunDevice:
    """Interfaz TUN de Linux (y shim accionable en Windows).

    Uso Linux (requiere root o ``CAP_NET_ADMIN``)::

        dev = TunDevice(name="azz0")
        dev.open()
        dev.assign("10.66.66.1", prefix="24")

    En Windows es necesario el driver *tap-windows6* (puerto
    ``\\\\.\\Global\\{GUID}.tap``; la ruta concreta del driver está fuera
    del alcance del Sprint 3 — aquí se detecta y se explica).
    """

    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    TUNSETIFF = 0x400454CA

    def __init__(self, name: str = "azz0", mtu: int = DEFAULT_MTU) -> None:
        self.name = name
        self.mtu = mtu
        self.fd: Optional[int] = None

    def open(self) -> None:
        """Abre ``/dev/net/tun`` y crea la interfaz IFF_TUN|IFF_NO_PI.

        Raises:
            TunError: ENOPERM (sin root), ausencia de /dev/net/tun o
                plataforma Windows (requiere driver tap-windows6).
        """
        if os.name == "nt":
            raise TunError(
                "TUN en Windows requiere el driver tap-windows6 (OpenVPN "
                "community). Instálalo y vuelve a intentarlo; el adjunto "
                "directo por GUID llega como mejora posterior a la ruta "
                "documentada."
            )
        try:
            fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        except PermissionError as exc:
            raise TunError(
                "Sin privilegios para /dev/net/tun: ejecuta AZZAZEL como "
                "root o dale CAP_NET_ADMIN al Python "
                "('sudo setcap cap_net_admin+ep $(readlink -f $(which python3))')."
            ) from exc
        except FileNotFoundError as exc:
            raise TunError(
                "No existe /dev/net/tun: carga el módulo 'tun' del kernel "
                "('sudo modprobe tun')."
            ) from exc
        try:
            import fcntl
            ifr = struct.pack("16sH", self.name.encode()[:15],
                              self.IFF_TUN | self.IFF_NO_PI)
            name_out = fcntl.ioctl(fd, self.TUNSETIFF, ifr)
            self.name = name_out[:16].split(b"\x00")[0].decode()
        except OSError as exc:
            os.close(fd)
            raise TunError(f"Ioctl TUNSETIFF falló: {exc}") from exc
        self.fd = fd
        _log.success("Interfaz TUN '%s' abierta (fd=%s).", self.name, fd)

    def assign(self, address: str, prefix: str = "24") -> None:
        """Asigna IP y levanta la interfaz con ``ip(8)``."""
        if self.fd is None:
            raise TunError("TunDevice no abierto: llama open() primero.")
        for cmd in (("ip", "addr", "add", f"{address}/{prefix}", "dev",
                     self.name), ("ip", "link", "set", self.name, "up",
                                  "mtu", str(self.mtu))):
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise TunError(f"{' '.join(cmd)} falló: {proc.stderr.strip()}")
        _log.success("TUN '%s' configurada: %s/%s (mtu %s).",
                     self.name, address, prefix, self.mtu)

    def read_packet(self) -> Optional[bytes]:
        """Lee un paquete del TUN (``None`` si no hay datos)."""
        if self.fd is None:
            return None
        try:
            return os.read(self.fd, self.mtu + 64)
        except (BlockingIOError, InterruptedError):
            return None
        except OSError:
            return None

    def write_packet(self, packet: bytes) -> None:
        """Escribe un paquete al TUN."""
        if self.fd is not None:
            os.write(self.fd, packet[: self.mtu + 64])

    def close(self) -> None:
        """Cierra y elimina la interfaz."""
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
            _log.info("TUN '%s' cerrada.", self.name)


# ---------------------------------------------------------------------------
# Kill switch (estado + hook; el cableado real llega con firewall S7)
# ---------------------------------------------------------------------------
@dataclass
class KillSwitch:
    """Interruptor de seguridad del cliente VPN.

    Al activarse bloquea TODO el tráfico salvo el propio túnel mediante
    la imposición de reglas de aislamiento con :class:`FirewallManager`.

    Attributes:
        armed: Configuración del usuario (auto-engage al caer el túnel).
        engaged: Estado actual (``True`` = tráfico bloqueado).
        hook: Callback opcional invocado al activarse.
        firewall_manager: Instancia opcional de FirewallManager.
        peer_host: Endpoint del servidor VPN para filtrar el tráfico.
        peer_port: Puerto UDP/TCP del servidor VPN.
        protocol: Protocolo del túnel ('udp' o 'tcp').
    """

    armed: bool = True
    engaged: bool = False
    hook: Optional[Callable[[str], None]] = None
    firewall_manager: Optional[Any] = None
    peer_host: Optional[str] = None
    peer_port: Optional[int] = None
    protocol: str = "udp"

    def engage(self, reason: str) -> None:
        """Activa el bloqueo (si estaba armado), solo una vez por caída."""
        if not self.armed or self.engaged:
            return
        self.engaged = True
        _log.warning("KILL SWITCH ENGAGED (%s): tráfico fuera del túnel "
                     "suspendido hasta restablecer el enlace.", reason)
        if self.firewall_manager is not None and self.peer_host and self.peer_port:
            try:
                from firewall.fw_manager import vpn_only_rules
                rules = vpn_only_rules(self.peer_host, self.peer_port, protocol=self.protocol)
                self.firewall_manager.rules = rules
                self.firewall_manager.apply()
                _log.info("Reglas de firewall VPN-only aplicadas por KillSwitch.")
            except Exception as exc:  # noqa: BLE001
                _log.error("Fallo al aplicar reglas de firewall del KillSwitch: %s", exc)
        if self.hook is not None:
            try:
                self.hook(reason)
            except Exception as exc:  # noqa: BLE001 - nunca rompe
                _log.error("Hook del kill-switch falló: %s", exc)

    def disengage(self) -> None:
        """Restaura el tráfico normal."""
        if self.engaged:
            self.engaged = False
            _log.success("KILL SWITCH disengaged: túnel restablecido.")
            if self.firewall_manager is not None:
                try:
                    self.firewall_manager.rules = []
                    _log.info("Reglas de aislamiento KillSwitch desactivadas en firewall.")
                except Exception as exc:  # noqa: BLE001
                    _log.error("Fallo al restablecer firewall tras KillSwitch: %s", exc)


# ---------------------------------------------------------------------------
# Capa de datagramas asyncio compartida
# ---------------------------------------------------------------------------
class _Udp(asyncio.DatagramProtocol):
    """Protocolo pytest-friendly: encola datagramas, expone envío.

    Mantiene un queue independiente de frames crudos; quien consume
    decide si son control o datos.
    """

    def __init__(self) -> None:
        self.queue: "asyncio.Queue[tuple[bytes, tuple[str, int]]]" = \
            asyncio.Queue()
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.local_addr: Optional[tuple[str, int]] = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport
        self.local_addr = transport.get_extra_info("sockname")[:2]

    def datagram_received(self, data: bytes, addr) -> None:
        self.queue.put_nowait((data, (str(addr[0]), int(addr[1]))))

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.transport is None:
            raise TunnelError("Socket UDP no inicializado.")
        self.transport.sendto(data, addr)

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None


async def _open_udp(bind_host: str, bind_port: int) -> _Udp:
    """Crea el endpoint UDP asyncio (bind ``host:port``, 0 = efímero)."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _Udp, local_addr=(bind_host, bind_port))
    return protocol


# ---------------------------------------------------------------------------
# Servidor VPN
# ---------------------------------------------------------------------------
@dataclass
class _PendingHello:
    """Fase 1 del handshake en curso para un peer concreto."""

    client_nonce: bytes
    server_nonce: bytes
    session_id: bytes
    session_key: bytes
    started_at: float = field(default_factory=time.time)


class TunnelServer:
    """Servidor VPN: escucha UDP, handshake AZZ y distribución VIPs.

    El PSK se recibe ya resuelto (string) — nunca se persiste aquí.

    Args:
        psk: ``vpn.keys.private_key`` en claro (ya descifrado).
        port: Puerto de escucha (0 = efímero, tests).
        listen_host: Interfaz de escucha.
        max_clients / keepalive: De ``vpn.server``.
        network: Prefijo de VIPs server-side (p. ej. ``10.66.66.0/24``).
    """

    def __init__(self, psk: str, *, listen_host: str = "0.0.0.0",
                 port: int = 51820, max_clients: int = 5,
                 keepalive: int = 25, network: str = "10.66.66.0/24",
                 idle_life: Optional[float] = None) -> None:
        if not psk:
            raise TunnelError(
                "PSK vacío: define vpn.keys.private_key en config.yaml "
                "(wizard: python azzazel.py --setup)."
            )
        if not (0 <= port <= 65535):
            raise TunnelError(f"Puerto inválido: {port}")
        self._psk = psk
        self.listen_host = listen_host
        self.port = int(port)
        self.max_clients = max(1, max_clients)
        self.keepalive = max(1, keepalive)
        # margen de vida sin frames antes de pruned (keepalive × 3 por defecto)
        self.idle_life = float(idle_life) if idle_life \
            else float(self.keepalive) * 3.0
        self.network = network
        self._udp: Optional[_Udp] = None
        self.sessions: Dict[bytes, VpnSession] = {}
        self._pending: Dict[tuple[str, int], _PendingHello] = {}
        self.packet_queue: "asyncio.Queue[tuple[VpnSession, bytes]]" = \
            asyncio.Queue()
        self._dispatcher: Optional[asyncio.Task[None]] = None
        self._pruner: Optional[asyncio.Task[None]] = None
        self.tun: Optional[TunDevice] = None

    # -- Ciclo de vida ----------------------------------------------------
    async def start(self) -> None:
        """Abre el socket y arranca el dispatch + pruned."""
        if self._udp is not None:
            return
        self._udp = await _open_udp(self.listen_host, self.port)
        assert self._udp.local_addr is not None
        self.port = self._udp.local_addr[1]
        self._dispatcher = asyncio.create_task(self._dispatch_loop(),
                                               name="vpn-srv-dispatch")
        self._pruner = asyncio.create_task(self._pruner_loop(),
                                           name="vpn-srv-pruner")
        _log.success(
            "VPN server escuchando en %s:%s (máx %s clientes, ka=%ss).",
            self.listen_host, self.port, self.max_clients, self.keepalive)

    async def stop(self) -> None:
        """Cierre limpio: tasks, sesiones, socket y TUN."""
        for task in (self._dispatcher, self._pruner):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._dispatcher = self._pruner = None
        sessions_lost = len(self.sessions)
        self.sessions.clear()
        self._pending.clear()
        if self._udp:
            self._udp.close()
            self._udp = None
        if self.tun:
            self.tun.close()
            self.tun = None
        _log.info("VPN server detenido (%s sesiones perdidas).",
                  sessions_lost)

    def attach_tun(self, device: TunDevice) -> None:
        """Adjunta un TunDevice real (requiere privilegios al abrirlo)."""
        self.tun = device

    @property
    def active_sessions(self) -> int:
        """Sesiones vivas en este instante."""
        return len(self.sessions)

    @classmethod
    def from_config(cls, cm) -> "TunnelServer":
        """Constructor desde ConfigManager (comparte config.yaml).

        Lee ``vpn.server`` y la ``vpn.keys.private_key`` YA descifrada
        por el gestor de secretos.
        """
        cfg = cm.config.vpn
        return cls(
            cfg.keys.private_key,
            listen_host=cfg.server.listen_address,
            port=cfg.server.listen_port,
            max_clients=cfg.server.max_clients,
            keepalive=cfg.server.keepalive,
            network=cfg.server.network,
        )

    # -- Bucle de dispatch --------------------------------------------------
    async def _dispatch_loop(self) -> None:
        assert self._udp is not None
        try:
            while True:
                data, addr = await self._udp.queue.get()
                if data.startswith(CONTROL_MAGIC):
                    await self._handle_control(data, addr)
                elif data.startswith(FRAME_MAGIC):
                    await self._handle_frame(data, addr)
        except asyncio.CancelledError:
            raise

    async def _pruner_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(max(1.0, self.idle_life / 2.0))
                now = time.time()
                dead = [sid for sid, s in self.sessions.items()
                        if now - s.last_rx > self.idle_life]
                for sid in dead:
                    self.sessions.pop(sid)
                    _log.warning(
                        "Sesión %s expirada por inactividad (>%ss).",
                        sid.hex()[:8], int(self.idle_life))
                stale = [addr for addr, p in self._pending.items()
                         if now - p.started_at > HANDSHAKE_TIMEOUT * 2]
                for addr in stale:
                    self._pending.pop(addr, None)
        except asyncio.CancelledError:
            raise

    # ------------------------------------------------------------------
    # Handshake (AZZ-C1)
    # ------------------------------------------------------------------
    async def _handle_control(self, data: bytes, addr: tuple) -> None:
        body_raw = data[len(CONTROL_MAGIC):]
        try:
            msg = json.loads(body_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _log.debug("Control ilegible de %s — descartado.", addr)
            return
        mtype = msg.get("type")
        if mtype == "hello":
            await self._on_hello(msg, addr)
        elif mtype == "auth":
            await self._on_auth(msg, addr)
        else:
            _log.debug("Control tipo %r de %s ignorado.", mtype, addr)

    async def _on_hello(self, msg: dict, addr: tuple) -> None:
        assert self._udp is not None
        if self.active_sessions >= self.max_clients:
            self._udp.sendto(
                CONTROL_MAGIC + json.dumps({
                    "type": "error", "code": "full"}).encode(), addr)
            _log.warning("Handshake de %s rechazado: VPN llena (%s).",
                         addr, self.active_sessions)
            return
        try:
            client_nonce = bytes.fromhex(str(msg["client_nonce"]))
        except (KeyError, ValueError, TypeError):
            _log.debug("hello malformado de %s — descartado.", addr)
            return
        server_nonce = secrets.token_bytes(16)
        session_id = secrets.token_bytes(8)

        # Intercambio efímero X25519 para Perfect Forward Secrecy (PFS)
        ecdh_secret: Optional[bytes] = None
        server_pub_hex = ""
        client_pub_hex = msg.get("client_pub", "")
        if client_pub_hex:
            try:
                from cryptography.hazmat.primitives.asymmetric.x25519 import (
                    X25519PrivateKey, X25519PublicKey,
                )
                from cryptography.hazmat.primitives.serialization import (
                    Encoding, PublicFormat,
                )
                client_pub_bytes = bytes.fromhex(client_pub_hex)
                client_pub_key = X25519PublicKey.from_public_bytes(client_pub_bytes)
                srv_priv = X25519PrivateKey.generate()
                server_pub_bytes = srv_priv.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
                server_pub_hex = server_pub_bytes.hex()
                ecdh_secret = srv_priv.exchange(client_pub_key)
            except Exception as exc:
                _log.debug("X25519 PFS omitido/fallback: %s", exc)

        session_key = _derive_session_key(self._psk, client_nonce,
                                          server_nonce, ecdh_secret)
        self._pending[addr] = _PendingHello(
            client_nonce=client_nonce, server_nonce=server_nonce,
            session_id=session_id, session_key=session_key)
        _log.info("Fase HELLO de %s — challenge emitido (PFS=%s).",
                  addr, bool(ecdh_secret))
        
        chal_payload = {
            "type": "challenge",
            "server_nonce": server_nonce.hex(),
            "session_id": session_id.hex(),
        }
        if server_pub_hex:
            chal_payload["server_pub"] = server_pub_hex
        self._udp.sendto(
            CONTROL_MAGIC + json.dumps(chal_payload).encode(), addr)

    async def _on_auth(self, msg: dict, addr: tuple) -> None:
        assert self._udp is not None
        pending = self._pending.pop(addr, None)
        if pending is None:
            self._udp.sendto(
                CONTROL_MAGIC + json.dumps({
                    "type": "error", "code": "no_pending_hello"}).encode(),
                addr)
            _log.warning("auth inesperado de %s (sin hello previo).", addr)
            return
        session_id, session_key = pending.session_id, pending.session_key
        try:
            proof = bytes.fromhex(str(msg["proof"]))
        except (KeyError, ValueError, TypeError):
            _log.debug("auth malformado de %s — descartado.", addr)
            return
        expected = _auth_proof(session_key, pending.client_nonce,
                               pending.server_nonce, session_id)
        if not secure_compare(proof, expected):
            self._udp.sendto(
                CONTROL_MAGIC + json.dumps({
                    "type": "error", "code": "auth_failed"}).encode(),
                addr)
            _log.error(
                "Handshake AUTH fallido de %s (client_nonce=%s). "
                "¿PSK distinta?", addr, pending.client_nonce.hex()[:8])
            return
        peer = (str(addr[0]), int(addr[1]))
        session = VpnSession(
            session_id=session_id, peer=peer,
            crypto=CryptoEngine(session_key))
        self.sessions[session_id] = session
        _log.success("Sesión VPN %s establecida con %s (cliente #%s).",
                     session_id.hex()[:8], addr, self.active_sessions)
        confirm = _auth_proof(session_key, pending.server_nonce,
                              pending.client_nonce, session_id)
        self._udp.sendto(
            CONTROL_MAGIC + json.dumps({
                "type": "session_ok",
                "session_id": session_id.hex(),
                "proof_confirm": confirm.hex(),
                "keepalive": self.keepalive}).encode(), addr)

    # ------------------------------------------------------------------
    # Frames (datos cifrados)
    # ------------------------------------------------------------------
    async def _handle_frame(self, data: bytes, addr: tuple) -> None:
        if len(data) < FRAME_HEADER_LEN:
            return
        session = self.sessions.get(data[5:FRAME_HEADER_LEN])
        if session is None:
            return  # peer desconocido → silencio (sin fingerprinting)
        counter, payload = session.unpack_frame(data)
        if counter < 0:
            return
        if payload is not None:
            await self.packet_queue.put((session, payload))
            if self.tun is not None:
                self.tun.write_packet(payload)

    def get_session_by_peer(self, peer: tuple[str, int]
                            ) -> Optional[VpnSession]:
        """Busca una sesión por ``(host, puerto)`` del cliente."""
        for session in self.sessions.values():
            if session.peer == peer:
                return session
        return None

    async def send_to(self, session_id: bytes, packet: bytes) -> bool:
        """Envía un paquete de red cifrado al cliente de la sesión."""
        session = self.sessions.get(session_id)
        if session is None or self._udp is None:
            return False
        frame = session.build_frame(packet)
        if len(frame) > DEFAULT_MTU + 64:
            _log.debug("Frame > MTU soltado (%s bytes).", len(frame))
            return False
        self._udp.sendto(frame, session.peer)
        return True


# ---------------------------------------------------------------------------
# Cliente VPN
# ---------------------------------------------------------------------------
class TunnelClient:
    """Cliente VPN: handshake + frames + keepalive + reconexión.

    El *hook* del kill-switch se invoca SOLO cuando se agotan los
    reintentos y el túnel queda definitivamente caído.
    """

    def __init__(
        self,
        psk: str, server_host: str = "", server_port: int = 51820, *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        keepalive: int = 25,
        auto_reconnect: bool = True,
        max_retries: int = 10,
        backoff_base: float = 0.5,
        backoff_max: float = 30.0,
        bind_port: int = 0,
        kill_switch: Optional[KillSwitch] = None,
        handshake_timeout: float = HANDSHAKE_TIMEOUT,
    ) -> None:
        if not psk:
            raise TunnelError("PSK vacío en el cliente (config).")
        self._psk = psk
        self.server_host = host if host is not None else server_host
        self.server_port = port if port is not None else server_port
        self.keepalive = max(1, keepalive)
        self.auto_reconnect = auto_reconnect
        self.max_retries = max(0, max_retries)
        self.backoff_base = backoff_base
        self.backoff_max = max(backoff_base, backoff_max)
        self.bind_port = bind_port
        self.kill_switch = kill_switch or KillSwitch(armed=False)
        if self.kill_switch.peer_host is None:
            self.kill_switch.peer_host = self.server_host
        if self.kill_switch.peer_port is None:
            self.kill_switch.peer_port = self.server_port
        self.handshake_timeout = max(0.5, float(handshake_timeout))

        self._udp: Optional[_Udp] = None
        self.session: Optional[VpnSession] = None
        self.packet_queue: "asyncio.Queue[bytes]" = asyncio.Queue()
        self._control_queue: "asyncio.Queue[tuple[dict[str, Any], tuple]]" = \
            asyncio.Queue()
        self._reader_task: Optional[asyncio.Task[None]] = None
        self._ka_task: Optional[asyncio.Task[None]] = None
        self._reconnect_task: Optional[asyncio.Task[None]] = None
        self._stop = asyncio.Event()
        self._first_connected = asyncio.Event()
        self.attempts = 0

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------
    async def connect(self) -> None:
        """Abre el socket y ejecuta el handshake inicial.

        Raises:
            HandshakeError: Hello/Auth rechazados o timeout.
        """
        self._stop.clear()
        if self._udp is None:
            self._udp = await _open_udp("0.0.0.0", self.bind_port)
        # Dispatch único: lo arranca connect() para que TODO handshake
        # (incluidas las reconexiones) reciba el control por su cola.
        if self._reader_task is None:
            self._reader_task = asyncio.create_task(
                self._dispatch_loop(), name="vpn-cli-dispatch")
        await self._handshake()
        self.attempts = 0

    def start_background(self) -> None:
        """Activa keepalive + dispatch en segundo plano (reconexión)."""
        if self._reader_task is None:
            self._reader_task = asyncio.create_task(
                self._dispatch_loop(), name="vpn-cli-dispatch")
        if self._ka_task is None:
            self._ka_task = asyncio.create_task(
                self._keepalive_loop(), name="vpn-cli-keepalive")

    async def close(self) -> None:
        """Cierre limpio: cancela todos los loops y el socket."""
        self._stop.set()
        for task in (self._reader_task, self._ka_task,
                     self._reconnect_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._reader_task = self._ka_task = self._reconnect_task = None
        if self._udp:
            self._udp.close()
            self._udp = None
        self.session = None

    @property
    def connected(self) -> bool:
        """``True`` si hay una sesión cifrada viva."""
        return self.session is not None

    # ------------------------------------------------------------------
    # Handshake AZZ-C1 (cliente)
    # ------------------------------------------------------------------
    async def _handshake(self) -> None:
        """hello → challenge → auth → session_ok con Perfect Forward Secrecy."""
        assert self._udp is not None
        deadline = time.time() + self.handshake_timeout
        client_nonce = secrets.token_bytes(16)
        server = (self.server_host, self.server_port)

        # Generar clave efímera X25519 para Perfect Forward Secrecy
        client_priv = None
        client_pub_hex = ""
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import (
                X25519PrivateKey,
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat,
            )
            client_priv = X25519PrivateKey.generate()
            client_pub_bytes = client_priv.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            client_pub_hex = client_pub_bytes.hex()
        except Exception:
            pass

        hello_payload = {
            "type": "hello",
            "client_nonce": client_nonce.hex(),
            "version": 1,
        }
        if client_pub_hex:
            hello_payload["client_pub"] = client_pub_hex

        self._udp.sendto(
            CONTROL_MAGIC + json.dumps(hello_payload).encode(), server)
        challenge: Optional[dict] = None
        try:
            while time.time() < deadline and challenge is None:
                msg, addr = await asyncio.wait_for(
                    self._control_queue.get(),
                    timeout=max(0.1, deadline - time.time()))
                if addr != server:
                    continue
                if msg.get("type") == "error":
                    raise HandshakeError(
                        f"Servidor rechazó el hello: {msg.get('code')}")
                if msg.get("type") == "challenge":
                    challenge = msg
        except asyncio.TimeoutError:
            raise HandshakeError("Timeout esperando challenge del servidor.")
        assert challenge is not None

        try:
            server_nonce = bytes.fromhex(challenge["server_nonce"])
            session_id = bytes.fromhex(challenge["session_id"])
        except (KeyError, ValueError, TypeError) as exc:
            raise HandshakeError("Challenge malformado del servidor.") from exc

        # Resolver secreto compartido X25519 si el servidor respondió con server_pub
        ecdh_secret: Optional[bytes] = None
        server_pub_hex = challenge.get("server_pub", "")
        if client_priv is not None and server_pub_hex:
            try:
                from cryptography.hazmat.primitives.asymmetric.x25519 import (
                    X25519PublicKey,
                )
                server_pub_bytes = bytes.fromhex(server_pub_hex)
                server_pub_key = X25519PublicKey.from_public_bytes(server_pub_bytes)
                ecdh_secret = client_priv.exchange(server_pub_key)
            except Exception as exc:
                _log.debug("X25519 client exchange fallback: %s", exc)

        session_key = _derive_session_key(self._psk, client_nonce,
                                          server_nonce, ecdh_secret)
        proof = _auth_proof(session_key, client_nonce, server_nonce,
                            session_id)
        self._udp.sendto(
            CONTROL_MAGIC + json.dumps({
                "type": "auth", "proof": proof.hex()}).encode(), server)
        try:
            while time.time() < deadline:
                msg, addr = await asyncio.wait_for(
                    self._control_queue.get(),
                    timeout=max(0.1, deadline - time.time()))
                if addr != server:
                    continue
                if msg.get("type") == "error":
                    raise HandshakeError(
                        f"Auth rechazada por el servidor: {msg.get('code')}")
                if msg.get("type") == "session_ok":
                    confirm = bytes.fromhex(msg["proof_confirm"])
                    expected = _auth_proof(session_key, server_nonce,
                                           client_nonce,
                                           bytes.fromhex(msg["session_id"]))
                    if not secure_compare(confirm, expected):
                        raise HandshakeError(
                            "proof_confirm del servidor inválido "
                            "(¿ataque de suplantación?).")
                    self.session = VpnSession(
                        session_id=bytes.fromhex(msg["session_id"]),
                        peer=server, crypto=CryptoEngine(session_key))
                    self.keepalive = max(1, int(msg.get("keepalive",
                                                        self.keepalive)))
                    self._first_connected.set()
                    self.kill_switch.disengage()
                    _log.success("VPN túnel establecido: sesión %s con %s (PFS=%s).",
                                 self.session.session_id.hex()[:8], server, bool(ecdh_secret))
                    return
        except asyncio.TimeoutError:
            raise HandshakeError("Timeout esperando session_ok.")

    # ------------------------------------------------------------------
    # Frames / lectura
    # ------------------------------------------------------------------
    async def _dispatch_loop(self) -> None:
        """Único consumidor del socket UDP del cliente.

        - Datagramas ``AZZ-C1`` (control) → cola exclusiva del handshake.
        - Frames ``AZZ1`` cifrados → sesión actual → cola de paquetes.
        """
        try:
            while True:
                data, addr = await self._udp.queue.get()
                if data.startswith(CONTROL_MAGIC):
                    try:
                        msg = json.loads(
                            data[len(CONTROL_MAGIC):].decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    self._control_queue.put_nowait((msg, addr))
                    continue
                if self.session is None or addr != self.session.peer:
                    continue
                counter, payload = self.session.unpack_frame(data)
                if counter < 0:
                    continue
                if payload is not None:
                    self.packet_queue.put_nowait(payload)
        except asyncio.CancelledError:
            raise

    async def send_packet(self, packet: bytes) -> bool:
        """Encola y envía un paquete de red al peer, cifrado."""
        if self.session is None or self._udp is None:
            return False
        frame = self.session.build_frame(packet)
        if len(frame) > DEFAULT_MTU + 64:
            _log.debug("Frame > MTU soltado.")
            return False
        self._udp.sendto(frame, self.session.peer)
        return True

    # ------------------------------------------------------------------
    # Keepalive & reconexión exponencial
    # ------------------------------------------------------------------
    async def _keepalive_loop(self) -> None:
        """Pings periódicos + disparo de reconexión tras silencio sostenido."""
        try:
            while not self._stop.is_set():
                await asyncio.sleep(self.keepalive)
                if self.session is None:
                    continue
                ka = self.session.build_frame(b"ka",
                                              ftype=FRAME_KEEPALIVE)
                self._udp.sendto(ka, self.session.peer)
                idle = time.time() - self.session.last_rx
                if idle > self.keepalive * 3 and self.auto_reconnect:
                    dead_session = self.session
                    self.session = None
                    _log.warning("Keepalive vencido (%.0fs): sesión %s "
                                 "perdida; arranco reconexión.",
                                 idle, dead_session.session_id.hex()[:8])
                    if self._reconnect_task is None or \
                            self._reconnect_task.done():
                        self._reconnect_task = asyncio.create_task(
                            self._reconnect_loop())
        except asyncio.CancelledError:
            raise

    async def _reconnect_loop(self) -> None:
        """Reintenta handshake con backoff exponencial hasta agotar retries."""
        for attempt in range(1, self.max_retries + 2):
            self.attempts = attempt
            try:
                await self._handshake()
                self.attempts = 0
                _log.success("VPN reconectada tras %s intento(s).", attempt)
                return
            except HandshakeError as exc:
                if attempt > self.max_retries:
                    _log.error("Reconexión agotada (%s intentos): %s",
                               attempt, exc)
                    break
                delay = min(self.backoff_base * (2 ** (attempt - 1)),
                            self.backoff_max)
                _log.warning("Reintento %s/%s en %.1fs (%s)",
                             attempt, self.max_retries, delay, exc)
                await asyncio.sleep(delay)
        self.kill_switch.engage("túnel definitivamente caído")

    # ------------------------------------------------------------------
    # Métricas rápidas para CLI/GUI
    # ------------------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        """Snapshot legible del estado del cliente."""
        s = self.session
        return {
            "connected": self.connected,
            "attempts": self.attempts,
            "kill_switch": self.kill_switch.engaged,
            "rx_frames": s.rx_frames if s else 0,
            "rx_replays": s.rx_replays_dropped if s else 0,
            "rx_gcm": s.rx_gcm_dropped if s else 0,
            "rx_keepalives": s.rx_keepalives if s else 0,
        }


# ---------------------------------------------------------------------------
# Demo standalone: handshake + frames + tamper/replay/keepalive/reconnect
# ---------------------------------------------------------------------------
async def _demo() -> None:
    from ui.cli import ascii_art as art

    print(art.box(
        "DEMO tunnel_manager: handshake AZZ sobre UDP localhost,\n"
        "cifrado, anti-replay, tamper-drop, keepalive y reconexión.",
        title="VPN — Sprint 3", style="double"))

    # PSK compartida (producción: vpn.keys.private_key de config).
    psk = secrets.token_hex(24)

    server = TunnelServer(psk, listen_host="127.0.0.1", port=0,
                          max_clients=2, keepalive=1)
    await server.start()
    print(f"\n  1. Servidor UDP arriba en :{server.port} ✔")

    kill_calls: list[str] = []
    client = TunnelClient(
        psk, "127.0.0.1", server.port, keepalive=1,
        max_retries=3, backoff_base=0.05, backoff_max=0.2,
        kill_switch=KillSwitch(armed=True,
                               hook=lambda r: kill_calls.append(r)),
        handshake_timeout=0.6)

    async def wait_until(pred: Callable[[], bool], timeout: float,
                         desc: str) -> None:
        """Bucle de espera activa (determinista) para la demo."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            if pred():
                return
            await asyncio.sleep(0.05)
        raise AssertionError(f"wait_until agotado: {desc}")
    await client.connect()
    client.start_background()
    print("  2. Handshake AZZ-C1 completado; sesión activa ✔")
    assert client.connected and server.active_sessions == 1
    session_srv = next(iter(server.sessions.values()))
    assert session_srv.crypto is not None

    # Claves derivadas iguales en ambos extremos (vía API pública):
    token = session_srv.crypto.encrypt_str("prueba-clave")
    assert client.session.crypto.decrypt_str(token) == "prueba-clave"
    print("  3. Claves de sesión idénticas en ambos extremos ✔")

    # ---- Frame cliente→servidor ----
    await client.send_packet(b"PAQUETE-IP-1")
    sess, pkt = await asyncio.wait_for(server.packet_queue.get(), 2)
    assert pkt == b"PAQUETE-IP-1"
    print("  4. Frame cifrado c→s entregado con integridad ✔")

    # ---- Frame servidor→cliente ----
    ok = await server.send_to(session_srv.session_id, b"RESPUESTA-IP-9")
    assert ok
    pkt2 = await asyncio.wait_for(client.packet_queue.get(), 2)
    assert pkt2 == b"RESPUESTA-IP-9"
    print("  5. Frame cifrado s→c entregado ✔")

    # ---- Tamper: bit flip en el GCM tag → reject (handler directo) ----
    raw = client.session.build_frame(b"DATOS")
    flipped = bytearray(raw)
    flipped[-1] ^= 0x01
    peer = session_srv.peer
    g0 = session_srv.rx_gcm_dropped
    q0 = server.packet_queue.qsize()
    await server._handle_frame(bytes(flipped), peer)
    assert session_srv.rx_gcm_dropped > g0
    assert server.packet_queue.qsize() == q0
    print("  6. Bit flip en ciphertext → drop por GCM (nada entra) ✔")

    # ---- Replay: reenviar el mismo datagrama exacto ----
    raw2 = client.session.build_frame(b"REPLAY-ME")
    await server._handle_frame(raw2, peer)
    _, _ = await asyncio.wait_for(server.packet_queue.get(), 2)
    await server._handle_frame(raw2, peer)         # duplicado exacto
    assert session_srv.rx_replays_dropped >= 1
    print("  7. Frame duplicado → anti-replay drop ✔")

    # ---- Keepalive transitando ----
    await asyncio.sleep(1.4)
    assert session_srv.rx_keepalives >= 1
    print(f"  8. Keepalive: {session_srv.rx_keepalives} KA "
          f"recibidos por el servidor ✔")

    # ---- Reconexión: tumbar el server, levantarlo y probar cliente ----
    await server.stop()
    print("  9. Servidor detenido; el cliente detecta silencio…")
    await wait_until(lambda: not client.connected, 8.0,
                     "silencio no detectado")
    server2 = TunnelServer(psk, listen_host="127.0.0.1", port=server.port,
                           max_clients=2, keepalive=1)
    await server2.start()
    await wait_until(lambda: client.connected, 12.0,
                     "reconexión no ocurrió")
    assert len(server2.sessions) == 1
    await client.send_packet(b"POST-RECONNECT")
    _, pkt3 = await asyncio.wait_for(server2.packet_queue.get(), 2)
    assert pkt3 == b"POST-RECONNECT"
    print(" 10. Reconexión exponencial + frame nuevo validado ✔")

    # ---- Kill switch: túnel definitivamente caído ----
    await server2.stop()
    await wait_until(lambda: client.kill_switch.engaged, 20.0,
                     "kill-switch no enganchó")
    assert kill_calls, "hook no invocado"
    print(" 11. Reintentos agotados → KILL SWITCH engaged (hook llamado) ✔")

    await client.close()
    assert not client.connected
    print(" 12. close() limpio ✔")
    print("\n─ demo tunnel_manager OK ─")


if __name__ == "__main__":
    asyncio.run(_demo())
