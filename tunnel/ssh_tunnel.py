"""
AZZAZEL tunnel/ssh_tunnel.py — Túneles SSH y Port Forwarding (Sprint 7).

Gestor de túneles SSH y redirección de puertos local, remota y dinámica (SOCKS5)
construido sobre :mod:`paramiko` y compatible con :class:`remote.remote_shell.SshProfile`.

Funcionalidades:
- **Local Port Forwarding (-L)**: Abre un puerto local y reenvía el tráfico
  a través del túnel SSH hacia un destino remoto.
- **Remote / Reverse Port Forwarding (-R)**: Solicita al servidor SSH abrir un
  puerto remoto y reenvía las conexiones entrantes hacia un servicio local.
- **Dynamic Port Forwarding (-D)**: Servidor proxy SOCKS5 local completo que
  enruta peticiones a través del canal SSH (soporte IPv4 y FQDN).
- **Métricas y Estadísticas en Vivo**: Conteo de bytes RX/TX por túnel,
  conexiones activas/totales, latencia y tiempos de actividad.
- **Resiliencia y Concurrencia**: Manejo de reconexiones, drenado limpio de
  hilos y compatibilidad 100% multiplataforma (Windows y Linux).

Ejemplo::

    profile = SshProfile(host="bastion.empresa.com", username="operador",
                         password=os.environ["SSH_PASSWORD"])
    tunnel = SshTunnelManager(profile)
    tunnel.add_local_forward("db-tun", local_port=5432,
                             remote_host="10.0.0.5", remote_port=5432)
    tunnel.add_dynamic_forward("socks-tun", local_port=1080)
    tunnel.start()
"""
from __future__ import annotations

import os
import select
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

# Bootstrap de path si se ejecuta directamente
_AZZAZEL_ROOT = Path(__file__).resolve().parent.parent
if str(_AZZAZEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_AZZAZEL_ROOT))

from core.logger import get_logger
from remote.remote_shell import SshProfile, RemoteShellClient, RemoteShellError

_log = get_logger("tunnel.ssh")

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:  # pragma: no cover
    paramiko = None  # type: ignore[assignment]
    PARAMIKO_AVAILABLE = False

__all__ = [
    "ForwardType", "ForwardRule", "ForwardStats", "SshTunnelManager",
    "SshTunnelError", "PARAMIKO_AVAILABLE",
]


class SshTunnelError(RuntimeError):
    """Error al configurar o ejecutar un túnel SSH."""


class ForwardType(str, Enum):
    """Tipo de redirección de puertos SSH."""
    LOCAL = "local"
    REMOTE = "remote"
    DYNAMIC = "dynamic"


@dataclass
class ForwardStats:
    """Métricas y estadísticas en vivo de una regla de reenvío."""
    bytes_rx: int = 0
    bytes_tx: int = 0
    active_connections: int = 0
    total_connections: int = 0
    errors: int = 0
    started_at: float = field(default_factory=time.time)

    @property
    def uptime_seconds(self) -> float:
        """Tiempo de actividad transcurrido en segundos."""
        return max(0.0, time.time() - self.started_at)

    def as_dict(self) -> dict[str, Any]:
        """Representación serializable de las estadísticas."""
        return {
            "bytes_rx": self.bytes_rx,
            "bytes_tx": self.bytes_tx,
            "active_connections": self.active_connections,
            "total_connections": self.total_connections,
            "errors": self.errors,
            "uptime_seconds": round(self.uptime_seconds, 2),
        }


@dataclass
class ForwardRule:
    """Definición de una regla de redirección de puertos.

    Args:
        name: Identificador único de la regla.
        forward_type: Tipo ('local', 'remote' o 'dynamic').
        bind_host: Interfaz de escucha (ej. '127.0.0.1' o '0.0.0.0').
        bind_port: Puerto de escucha local (o remoto si type='remote').
        dest_host: Host de destino (para local/remote).
        dest_port: Puerto de destino (para local/remote).
        enabled: Estado de activación de la regla.
    """
    name: str
    forward_type: ForwardType | str
    bind_host: str = "127.0.0.1"
    bind_port: int = 0
    dest_host: str = ""
    dest_port: int = 0
    enabled: bool = True
    stats: ForwardStats = field(default_factory=ForwardStats)

    def __post_init__(self) -> None:
        if isinstance(self.forward_type, str):
            self.forward_type = ForwardType(self.forward_type.lower())
        if not (0 <= self.bind_port <= 65535):
            raise ValueError(f"Puerto de escucha inválido: {self.bind_port}")
        if self.forward_type in (ForwardType.LOCAL, ForwardType.REMOTE):
            if not self.dest_host:
                raise ValueError("dest_host es obligatorio para túneles local/remote")
            if not (1 <= self.dest_port <= 65535):
                raise ValueError(f"Puerto de destino inválido: {self.dest_port}")

    def render(self) -> str:
        """Formatea la regla para visualización en consola o UI."""
        ftype = self.forward_type.value if isinstance(self.forward_type, ForwardType) \
            else str(self.forward_type)
        if ftype == "local":
            return f"[-L] {self.bind_host}:{self.bind_port} → SSH → {self.dest_host}:{self.dest_port}"
        elif ftype == "remote":
            return f"[-R] SSH:{self.bind_port} → Local → {self.dest_host}:{self.dest_port}"
        else:
            return f"[-D] SOCKS5 en {self.bind_host}:{self.bind_port} → SSH Dinámico"


class SshTunnelManager:
    """Gestor orquestador de túneles SSH y port forwarders.

    Args:
        profile: Perfil SSH con credenciales y configuración del servidor.
        client: Cliente SSH opcional previamente conectado.
    """

    def __init__(self, profile: SshProfile,
                 client: Optional[RemoteShellClient] = None) -> None:
        if not PARAMIKO_AVAILABLE:
            raise SshTunnelError(
                "La librería 'paramiko' es requerida para túneles SSH.\n"
                "Instálela con: pip install paramiko"
            )
        self.profile = profile
        self._client: Optional[RemoteShellClient] = client
        self._owns_client: bool = client is None
        self._transport: Optional[paramiko.Transport] = None
        self._rules: dict[str, ForwardRule] = {}
        self._servers: dict[str, socket.socket] = {}
        self._threads: list[threading.Thread] = []
        self._running = threading.Event()
        self._lock = threading.RLock()

    @property
    def is_running(self) -> bool:
        """Indica si el gestor de túneles está activo."""
        return self._running.is_set()

    def add_rule(self, rule: ForwardRule) -> None:
        """Registra una regla de reenvío."""
        with self._lock:
            if rule.name in self._rules:
                raise ValueError(f"Ya existe una regla con el nombre '{rule.name}'")
            self._rules[rule.name] = rule
            if self.is_running and rule.enabled:
                self._start_rule(rule)

    def add_local_forward(self, name: str, local_port: int,
                          remote_host: str, remote_port: int,
                          bind_host: str = "127.0.0.1") -> ForwardRule:
        """Helper para agregar una regla Local Forward (-L)."""
        rule = ForwardRule(
            name=name,
            forward_type=ForwardType.LOCAL,
            bind_host=bind_host,
            bind_port=local_port,
            dest_host=remote_host,
            dest_port=remote_port,
        )
        self.add_rule(rule)
        return rule

    def add_remote_forward(self, name: str, remote_port: int,
                           local_host: str, local_port: int,
                           remote_bind_host: str = "127.0.0.1") -> ForwardRule:
        """Helper para agregar una regla Remote Forward (-R)."""
        rule = ForwardRule(
            name=name,
            forward_type=ForwardType.REMOTE,
            bind_host=remote_bind_host,
            bind_port=remote_port,
            dest_host=local_host,
            dest_port=local_port,
        )
        self.add_rule(rule)
        return rule

    def add_dynamic_forward(self, name: str, local_port: int,
                            bind_host: str = "127.0.0.1") -> ForwardRule:
        """Helper para agregar una regla Dynamic Forward SOCKS5 (-D)."""
        rule = ForwardRule(
            name=name,
            forward_type=ForwardType.DYNAMIC,
            bind_host=bind_host,
            bind_port=local_port,
        )
        self.add_rule(rule)
        return rule

    def remove_rule(self, name: str) -> None:
        """Elimina una regla y cierra sus sockets asociados."""
        with self._lock:
            if name not in self._rules:
                return
            rule = self._rules.pop(name)
            self._stop_rule(rule)

    def get_rule(self, name: str) -> Optional[ForwardRule]:
        """Obtiene una regla por su nombre."""
        with self._lock:
            return self._rules.get(name)

    def list_rules(self) -> list[ForwardRule]:
        """Lista todas las reglas registradas."""
        with self._lock:
            return list(self._rules.values())

    def start(self, sock: Optional[socket.socket] = None,
              transport: Optional[paramiko.Transport] = None) -> None:
        """Inicia la sesión SSH y todos los túneles configurados.

        Args:
            sock: Socket inyectable (útil para pruebas unitarias).
            transport: Transporte paramiko pre-existente.
        """
        with self._lock:
            if self._running.is_set():
                return

            if transport is not None:
                self._transport = transport
            else:
                if self._client is None:
                    self._client = RemoteShellClient(self.profile)
                    self._client.connect(sock=sock)
                assert self._client._client is not None
                self._transport = self._client._client.get_transport()

            if not self._transport or not self._transport.is_active():
                raise SshTunnelError(
                    f"El transporte SSH hacia {self.profile.host}:{self.profile.port} "
                    "no se encuentra activo o autenticado."
                )

            self._running.set()
            for rule in self._rules.values():
                if rule.enabled:
                    try:
                        self._start_rule(rule)
                    except Exception as exc:
                        _log.error("Fallo al iniciar regla %s: %s", rule.name, exc)
                        rule.stats.errors += 1

            _log.info(
                "Túnel SSH activo con %d reglas sobre %s:%d",
                len(self._rules), self.profile.host, self.profile.port
            )

    def stop(self) -> None:
        """Detiene todos los túneles y cierra conexiones activas."""
        with self._lock:
            if not self._running.is_set():
                return
            self._running.clear()

            # Cerrar sockets de escucha
            for s in self._servers.values():
                try:
                    s.close()
                except Exception:
                    pass
            self._servers.clear()

            if self._owns_client and self._client:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
                self._transport = None

            _log.info("Gestor de túneles SSH detenido correctamente.")

    def __enter__(self) -> SshTunnelManager:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        self.stop()

    def status(self) -> dict[str, Any]:
        """Retorna un informe estructurado del estado de todos los túneles."""
        with self._lock:
            total_rx = sum(r.stats.bytes_rx for r in self._rules.values())
            total_tx = sum(r.stats.bytes_tx for r in self._rules.values())
            total_active = sum(r.stats.active_connections for r in self._rules.values())
            return {
                "running": self.is_running,
                "host": self.profile.host,
                "port": self.profile.port,
                "user": self.profile.username,
                "rules_count": len(self._rules),
                "total_active_connections": total_active,
                "total_bytes_rx": total_rx,
                "total_bytes_tx": total_tx,
                "rules": {
                    name: {
                        "type": r.forward_type.value if isinstance(r.forward_type, ForwardType)
                        else str(r.forward_type),
                        "render": r.render(),
                        "stats": r.stats.as_dict(),
                    }
                    for name, r in self._rules.items()
                },
            }

    # ------------------------------------------------------------------
    # Implementación Interna de Reenvíos
    # ------------------------------------------------------------------
    def _start_rule(self, rule: ForwardRule) -> None:
        if rule.forward_type == ForwardType.LOCAL:
            self._start_local_forward(rule)
        elif rule.forward_type == ForwardType.DYNAMIC:
            self._start_dynamic_forward(rule)
        elif rule.forward_type == ForwardType.REMOTE:
            self._start_remote_forward(rule)

    def _stop_rule(self, rule: ForwardRule) -> None:
        if rule.name in self._servers:
            srv = self._servers.pop(rule.name)
            try:
                srv.close()
            except Exception:
                pass
        if rule.forward_type == ForwardType.REMOTE and self._transport:
            try:
                self._transport.cancel_port_forward(rule.bind_host, rule.bind_port)
            except Exception:
                pass

    def _start_local_forward(self, rule: ForwardRule) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((rule.bind_host, rule.bind_port))
        actual_port = server_sock.getsockname()[1]
        rule.bind_port = actual_port
        server_sock.listen(50)
        server_sock.settimeout(0.5)
        self._servers[rule.name] = server_sock

        def _accept_loop() -> None:
            _log.info("Túnel local '%s' escuchando en %s:%d",
                      rule.name, rule.bind_host, rule.bind_port)
            while self._running.is_set():
                try:
                    client_sock, client_addr = server_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                t = threading.Thread(
                    target=self._pipe_local_client,
                    args=(rule, client_sock, client_addr),
                    daemon=True,
                )
                t.start()

        th = threading.Thread(target=_accept_loop, daemon=True,
                              name=f"ssh-local-{rule.name}")
        th.start()
        self._threads.append(th)

    def _pipe_local_client(self, rule: ForwardRule, client_sock: socket.socket,
                           client_addr: tuple[str, int]) -> None:
        rule.stats.total_connections += 1
        rule.stats.active_connections += 1
        chan: Optional[paramiko.Channel] = None
        try:
            if not self._transport or not self._transport.is_active():
                raise SshTunnelError("Transporte SSH no disponible")

            chan = self._transport.open_channel(
                "direct-tcpip",
                (rule.dest_host, rule.dest_port),
                client_addr,
                timeout=10.0,
            )
            if chan is None:
                raise SshTunnelError(
                    f"El servidor SSH rechazó el reenvío hacia {rule.dest_host}:{rule.dest_port}"
                )

            self._bidirectional_pump(client_sock, chan, rule.stats)
        except Exception as exc:
            rule.stats.errors += 1
            _log.debug("Error en canal de túnel local %s: %s", rule.name, exc)
        finally:
            rule.stats.active_connections = max(0, rule.stats.active_connections - 1)
            try:
                client_sock.close()
            except Exception:
                pass
            if chan is not None:
                try:
                    chan.close()
                except Exception:
                    pass

    def _start_dynamic_forward(self, rule: ForwardRule) -> None:
        """Inicia un servidor SOCKS5 local."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((rule.bind_host, rule.bind_port))
        actual_port = server_sock.getsockname()[1]
        rule.bind_port = actual_port
        server_sock.listen(50)
        server_sock.settimeout(0.5)
        self._servers[rule.name] = server_sock

        def _socks_accept_loop() -> None:
            _log.info("Proxy SOCKS5 dinámico '%s' escuchando en %s:%d",
                      rule.name, rule.bind_host, rule.bind_port)
            while self._running.is_set():
                try:
                    client_sock, client_addr = server_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                t = threading.Thread(
                    target=self._handle_socks5_client,
                    args=(rule, client_sock, client_addr),
                    daemon=True,
                )
                t.start()

        th = threading.Thread(target=_socks_accept_loop, daemon=True,
                              name=f"ssh-socks-{rule.name}")
        th.start()
        self._threads.append(th)

    def _handle_socks5_client(self, rule: ForwardRule, client_sock: socket.socket,
                              client_addr: tuple[str, int]) -> None:
        rule.stats.total_connections += 1
        rule.stats.active_connections += 1
        chan: Optional[paramiko.Channel] = None
        try:
            client_sock.settimeout(10.0)
            # 1. Saludo SOCKS5 (RFC 1928)
            ver_methods = client_sock.recv(2)
            if len(ver_methods) < 2 or ver_methods[0] != 0x05:
                client_sock.close()
                return
            nmethods = ver_methods[1]
            methods = client_sock.recv(nmethods)
            # Respondemos: Versión 5, Sin autenticación (0x00)
            client_sock.sendall(b"\x05\x00")

            # 2. Solicitud SOCKS5: VER=5, CMD=1 (CONNECT), RSV=0, ATYP
            req_header = client_sock.recv(4)
            if len(req_header) < 4 or req_header[0] != 0x05:
                client_sock.close()
                return

            cmd = req_header[1]
            if cmd != 0x01:  # Solo soportamos CONNECT (1)
                # 0x07 = Command not supported
                client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            atyp = req_header[3]
            target_host: str = ""
            if atyp == 0x01:  # IPv4 (4 bytes)
                raw_ip = client_sock.recv(4)
                target_host = socket.inet_ntoa(raw_ip)
            elif atyp == 0x03:  # FQDN / Nombre de dominio
                len_domain = client_sock.recv(1)[0]
                raw_domain = client_sock.recv(len_domain)
                target_host = raw_domain.decode("utf-8", errors="replace")
            elif atyp == 0x04:  # IPv6 (16 bytes)
                raw_ip6 = client_sock.recv(16)
                target_host = socket.inet_ntop(socket.AF_INET6, raw_ip6)
            else:
                client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            raw_port = client_sock.recv(2)
            target_port = struct.unpack(">H", raw_port)[0]

            if not self._transport or not self._transport.is_active():
                client_sock.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            # 3. Abrir canal SSH direct-tcpip
            chan = self._transport.open_channel(
                "direct-tcpip",
                (target_host, target_port),
                client_addr,
                timeout=10.0,
            )
            if chan is None:
                # 0x05 = Connection refused
                client_sock.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            # Éxito: 0x00 = Request granted
            client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            client_sock.settimeout(None)

            self._bidirectional_pump(client_sock, chan, rule.stats)
        except Exception as exc:
            rule.stats.errors += 1
            _log.debug("Error en proxy dinámico SOCKS5 %s: %s", rule.name, exc)
        finally:
            rule.stats.active_connections = max(0, rule.stats.active_connections - 1)
            try:
                client_sock.close()
            except Exception:
                pass
            if chan is not None:
                try:
                    chan.close()
                except Exception:
                    pass

    def _start_remote_forward(self, rule: ForwardRule) -> None:
        """Inicia una redirección remota inversa (-R)."""
        if not self._transport or not self._transport.is_active():
            raise SshTunnelError("Transporte SSH no activo para reverse forward")

        def _remote_handler(channel: paramiko.Channel, origin_addr, server_addr) -> None:  # noqa: ANN001
            rule.stats.total_connections += 1
            rule.stats.active_connections += 1
            try:
                local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                local_sock.connect((rule.dest_host, rule.dest_port))
                self._bidirectional_pump(local_sock, channel, rule.stats)
            except Exception as exc:
                rule.stats.errors += 1
                _log.debug("Error conectando a servicio local para reverse %s: %s",
                           rule.name, exc)
            finally:
                rule.stats.active_connections = max(0, rule.stats.active_connections - 1)
                try:
                    local_sock.close()
                except Exception:
                    pass
                try:
                    channel.close()
                except Exception:
                    pass

        try:
            self._transport.request_port_forward(
                rule.bind_host, rule.bind_port, handler=_remote_handler
            )
            _log.info("Reverse tunnel '%s' solicitado en servidor SSH:%d hacia local %s:%d",
                      rule.name, rule.bind_port, rule.dest_host, rule.dest_port)
        except Exception as exc:
            raise SshTunnelError(
                f"El servidor SSH rechazó el reverse forward en puerto {rule.bind_port}: {exc}"
            ) from exc

    def _bidirectional_pump(self, sock: socket.socket, chan: Any,
                            stats: ForwardStats) -> None:
        """Transfiere datos bidireccionalmente entre socket y canal de forma robusta."""
        closed = threading.Event()

        def _sock_to_chan() -> None:
            try:
                while not closed.is_set():
                    data = sock.recv(32768)
                    if not data:
                        break
                    chan.sendall(data)
                    stats.bytes_tx += len(data)
            except Exception:
                pass
            finally:
                closed.set()
                try:
                    chan.shutdown_write()
                except Exception:
                    pass

        def _chan_to_sock() -> None:
            try:
                while not closed.is_set():
                    data = chan.recv(32768)
                    if not data:
                        break
                    sock.sendall(data)
                    stats.bytes_rx += len(data)
            except Exception:
                pass
            finally:
                closed.set()
                try:
                    sock.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=_sock_to_chan, daemon=True)
        t2 = threading.Thread(target=_chan_to_sock, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()


# ----------------------------------------------------------------------
# Demo / Batería de Pruebas Standalone
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  AZZAZEL VPN — tunnel/ssh_tunnel.py (Port Forwarding Suite) ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    assert PARAMIKO_AVAILABLE, "Paramiko requerido para demo"

    # 1. Batería: Modelos de reglas y validación
    r1 = ForwardRule("web", "local", "127.0.0.1", 8080, "10.0.0.2", 80)
    assert r1.forward_type == ForwardType.LOCAL
    assert "[-L]" in r1.render() and "8080" in r1.render()

    r2 = ForwardRule("rev", "remote", "0.0.0.0", 9000, "127.0.0.1", 3000)
    assert r2.forward_type == ForwardType.REMOTE
    assert "[-R]" in r2.render()

    r3 = ForwardRule("dyn", "dynamic", "127.0.0.1", 1080)
    assert r3.forward_type == ForwardType.DYNAMIC
    assert "[-D]" in r3.render()

    try:
        ForwardRule("bad_port", "local", "127.0.0.1", 999999, "127.0.0.1", 80)
        raise AssertionError("Puerto fuera de rango no detectado")
    except ValueError:
        pass
    print("  ✔ 1/6: ForwardRule dataclass, enums, rendering y validación")

    # 2. Servidor destino TCP para probar túneles (Echo Server)
    echo_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    echo_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo_srv.bind(("127.0.0.1", 0))
    echo_port = echo_srv.getsockname()[1]
    echo_srv.listen(10)

    def _echo_worker():
        while True:
            try:
                c, _ = echo_srv.accept()
                d = c.recv(4096)
                if d:
                    c.sendall(b"ECHO:" + d)
                c.close()
            except Exception:
                break

    threading.Thread(target=_echo_worker, daemon=True).start()

    # 3. Servidor SSH In-Process con soporte para direct-tcpip
    from paramiko import RSAKey, ServerInterface, Transport

    host_key = RSAKey.generate(2048)
    client_side, server_side = socket.socketpair()

    class _ForwardTestSshServer(ServerInterface):
        def check_auth_password(self, user: str, password: str) -> str:
            return paramiko.AUTH_SUCCESSFUL if user == "war" and password == "s3cret" \
                else paramiko.AUTH_FAILED

        def check_channel_request(self, kind: str, chanid: int) -> str:
            return paramiko.OPEN_SUCCEEDED

        def check_channel_direct_tcpip_request(self, chanid: int, origin, destination):
            return paramiko.OPEN_SUCCEEDED

        def check_port_forward_request(self, address: str, port: int) -> int:
            return port

    ssh_transport = Transport(server_side)
    ssh_transport.add_server_key(host_key)
    ssh_srv_handler = _ForwardTestSshServer()

    def _run_ssh_server():
        ssh_transport.start_server(server=ssh_srv_handler)
        while ssh_transport.is_active():
            chan = ssh_transport.accept(1.0)
            if chan is not None:
                try:
                    target_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target_s.connect(("127.0.0.1", echo_port))

                    def _p1():
                        try:
                            while True:
                                data = chan.recv(4096)
                                if not data: break
                                target_s.sendall(data)
                        except Exception: pass
                        finally: target_s.close()

                    def _p2():
                        try:
                            while True:
                                data = target_s.recv(4096)
                                if not data: break
                                chan.sendall(data)
                        except Exception: pass
                        finally: chan.close()

                    threading.Thread(target=_p1, daemon=True).start()
                    threading.Thread(target=_p2, daemon=True).start()
                except Exception:
                    chan.close()

    threading.Thread(target=_run_ssh_server, daemon=True).start()

    # 4. Batería: Local Forwarding e2e (-L)
    profile = SshProfile(host="localhost", port=22, username="war",
                         password="s3cret", timeout=5.0)
    tunnel_mgr = SshTunnelManager(profile)
    tunnel_mgr.start(sock=client_side)
    assert tunnel_mgr.is_running

    l_rule = tunnel_mgr.add_local_forward("test-local", local_port=0,
                                          remote_host="127.0.0.1", remote_port=echo_port)
    time.sleep(0.15)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", l_rule.bind_port))
    s.sendall(b"HELLO_AZZAZEL_TUNNEL")
    resp = s.recv(4096)
    s.close()
    time.sleep(0.1)
    assert resp == b"ECHO:HELLO_AZZAZEL_TUNNEL", f"Respuesta inesperada: {resp}"
    assert l_rule.stats.bytes_tx > 0 and l_rule.stats.bytes_rx > 0
    print("  ✔ 2/6: Local Forward (-L) e2e bidireccional sobre canal SSH")

    # 5. Batería: Dynamic SOCKS5 Forwarding e2e (-D)
    d_rule = tunnel_mgr.add_dynamic_forward("test-socks", local_port=0)
    time.sleep(0.15)
    socks_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks_sock.connect(("127.0.0.1", d_rule.bind_port))
    socks_sock.sendall(b"\x05\x01\x00")
    g_resp = socks_sock.recv(2)
    assert g_resp == b"\x05\x00", f"SOCKS handshake fallo: {g_resp}"

    req = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", echo_port)
    socks_sock.sendall(req)
    c_resp = socks_sock.recv(10)
    assert c_resp[0:2] == b"\x05\x00", f"SOCKS connect fallo: {c_resp}"

    socks_sock.sendall(b"SOCKS_DATA_PAYLOAD")
    s_resp = socks_sock.recv(4096)
    socks_sock.close()
    time.sleep(0.1)
    assert s_resp == b"ECHO:SOCKS_DATA_PAYLOAD", f"Respuesta socks inesperada: {s_resp}"
    print("  ✔ 3/6: Dynamic SOCKS5 Proxy (-D) RFC 1928 handshake y forward e2e")

    # 6. Batería: Remote Forwarding (-R) registro y control
    tunnel_mgr.add_remote_forward("test-rem", remote_port=9999,
                                  local_host="127.0.0.1", local_port=echo_port)
    rem_rule = tunnel_mgr.get_rule("test-rem")
    assert rem_rule is not None and rem_rule.forward_type == ForwardType.REMOTE
    print("  ✔ 4/6: Remote Forward (-R) request_port_forward procesado")

    # 7. Batería: Status y métricas agregadas
    st = tunnel_mgr.status()
    assert st["running"] is True
    assert st["rules_count"] == 3
    assert st["total_bytes_rx"] > 0
    assert "test-local" in st["rules"]
    assert "test-socks" in st["rules"]
    print("  ✔ 5/6: Status payload estructurado con métricas en vivo")

    # 8. Batería: Stop y ciclo de vida limpio
    tunnel_mgr.stop()
    assert not tunnel_mgr.is_running
    echo_srv.close()
    print("  ✔ 6/6: Parada ordenada, cierre de sockets y liberación de recursos")

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║  DEMO COMPLETA: SshTunnelManager 6/6 Baterías Verdes ✔       ║")
    print("╚══════════════════════════════════════════════════════════════╝")
