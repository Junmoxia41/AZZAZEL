"""
AZZAZEL remote/remote_shell.py — acceso remoto vía SSH (Sprint 7).

Cliente SSH de ejecución sobre :mod:`paramiko` (puro, oficial y
multiplataforma):

- :class:`SshProfile` — credenciales validadas (password **xor**
  key_path, timeout acotado, host obligatorio).
- :class:`RemoteShellClient` — ``connect()/exec()/close()`` con:
    - host-key policy explícita ``accept_new`` | ``reject_unknown`` (con
      guía cuando el host no está en known_hosts);
    - ``exec()`` con deadline: si el host no responde antes del
      ``timeout``, el canal se cierra y el resultado viene marcado
      ``timed_out`` (y con nada de ambigüedad sobre el rc);
    - errores mapeados a mensajes accionables (auth, host alcanzable,
      host key desconocida, SFTP/transporte caído).
- :class:`ExecResult` — rc/stdout/stderr/duration/timed_out, con
  ``render()`` de líneas para la consola AZZAZEL.

Ejemplo::

    profile = SshProfile(host="192.168.1.10", username="war",
                         password="s3cret", timeout=8.0)
    with RemoteShellClient(profile) as sh:
        result = sh.exec("uname -a")
        print(result.render())
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Optional

_AZZAZEL_ROOT = Path(__file__).resolve().parent.parent
if str(_AZZAZEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_AZZAZEL_ROOT))

from core.logger import get_logger

_log = get_logger("remote.shell")

try:  # paramiko es opcional: sin él, error accionable al conectar
    import paramiko
    PARAMIKO_AVAILABLE = True
    PARAMIKO_ERROR = None
except ImportError as exc:  # pragma: no cover - depende de entorno
    paramiko = None  # type: ignore[assignment]
    PARAMIKO_AVAILABLE = False
    PARAMIKO_ERROR = exc

__all__ = [
    "SshProfile", "ExecResult", "RemoteShellClient", "RemoteShellError",
    "PARAMIKO_AVAILABLE", "HOST_KEY_POLICIES",
]

HOST_KEY_POLICIES: tuple[str, ...] = ("accept_new", "reject_unknown")


class RemoteShellError(RuntimeError):
    """Fallo de conexión/operación remota con guía integrada."""


@dataclass(frozen=True)
class SshProfile:
    """Perfil de conexión SSH validado.

    Attributes:
        host: Nombre/IP del servidor SSH.
        port: Puerto SSH (1-65535, típicamente 22).
        username: Usuario para authenticated sessions.
        password: Contraseña (o vacía si solo clave).
        key_path: Ruta de la clave privada (o vacía si no hay clave).
        passphrase: Frase de la clave cifrada.
        timeout: Segundos máximos por exec (y por connect cuando aplica).
    """

    host: str
    port: int = 22
    username: str = ""
    password: str = ""
    key_path: str = ""
    passphrase: str = ""
    timeout: float = 10.0

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("host vacío: indica el nombre o la IP del "
                             "servidor SSH.")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"puerto inválido: {self.port} (1-65535).")
        if not self.username.strip():
            raise ValueError("username vacío: las conexiones anónimas "
                             "no existen en SSH.")
        if not self.password and not self.key_path:
            raise ValueError("sin credencial: define 'password' o "
                             "'key_path' (ambos es válido; paramiko los "
                             "prueba en orden).")
        if not (0.5 <= self.timeout <= 300.0):
            raise ValueError(f"timeout inválido: {self.timeout} (0.5-300 s).")


@dataclass
class ExecResult:
    """Resultado de un ``exec()`` distante."""

    command: str
    rc: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """True si terminó a tiempo y el remoto devolvió rc 0."""
        return not self.timed_out and self.rc == 0

    def render(self) -> str:
        """Representación legible para consola."""
        head = (f"$ {self.command} → rc={self.rc} "
                f"({self.duration_ms:.0f} ms"
                f"{', TIMEOUT' if self.timed_out else ''})")
        body = self.stdout.rstrip() or "(vacío)"
        if self.stderr.strip():
            body += f"\nstderr: {self.stderr.rstrip()[:160]}"
        return f"{head}\n{body}"


class RemoteShellClient:
    """Cliente SSH paramiko con timeout honesto y errores accionables."""

    def __init__(self, profile: SshProfile,
                 host_key_policy: str = "accept_new") -> None:
        if host_key_policy not in HOST_KEY_POLICIES:
            raise ValueError(f"host_key_policy inválida: {host_key_policy!r} "
                             f"(válidas: {', '.join(HOST_KEY_POLICIES)}).")
        self.profile = profile
        self.host_key_policy = host_key_policy
        self._client: Optional["paramiko.SSHClient"] = None  # noqa: F821

    # ------------------------------------------------------------------
    # conexión
    # ------------------------------------------------------------------
    def connect(self, sock: Optional[socket.socket] = None) -> None:
        """Establece la sesión SSH; lanza :class:`RemoteShellError`.

        Args:
            sock: Socket YA conectado para el transporte (p. ej. un túnel
                propio o test in-process). Si se omite, se abre TCP hacia
                ``profile.host:profile.port``.
        """
        if self._client is not None:
            _log.debug("connect() reutiliza sesión existente.")
            return
        if not PARAMIKO_AVAILABLE:
            raise RemoteShellError(
                f"paramiko no instalado ({PARAMIKO_ERROR}). Ejecuta: "
                "pip install paramiko; o desactiva el acceso remoto.")
        prof = self.profile
        client = paramiko.SSHClient()
        if self.host_key_policy == "accept_new":
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.load_system_host_keys()  # conocidas del sistema
        kwargs: dict[str, object] = {
            "hostname": prof.host, "port": prof.port,
            "username": prof.username, "timeout": prof.timeout,
            "banner_timeout": prof.timeout,
            "auth_timeout": prof.timeout,
            "look_for_keys": False, "allow_agent": False,
        }
        if sock is not None:
            kwargs["sock"] = sock
            _log.info("Transporte SSH sobre socket inyectado "
                      "(sin I/O de red propia).")
        if prof.password:
            kwargs["password"] = prof.password
        if prof.key_path:
            kwargs["key_filename"] = prof.key_path
            if prof.passphrase:
                kwargs["passphrase"] = prof.passphrase
        start = time.monotonic()
        try:
            client.connect(**kwargs)  # type: ignore[arg-type]
        except paramiko.AuthenticationException as exc:
            raise RemoteShellError(
                f"autenticación rechazada por {prof.host}:{prof.port} — "
                "comprueba usuario/contraseña/clave del SshProfile.") \
                from exc
        except paramiko.BadHostKeyException as exc:
            raise RemoteShellError(
                f"host key inesperada de {prof.host}: ¿MITM? — "
                "depura manualmente (paramiko.BadHostKeyException).") \
                from exc
        except paramiko.SSHException as exc:
            msg = str(exc)
            if "not found in known_hosts" in msg or "known_hosts" in msg:
                raise RemoteShellError(
                    f"host key de {prof.host} DESCONOCIDA: revísala o "
                    "usa policy='accept_new' (primer contacto, como ssh).")\
                    from exc
            raise RemoteShellError(f"fallo SSH contra {prof.host}: {exc}")\
                from exc
        except socket.timeout as exc:
            raise RemoteShellError(
                f"timeout conectando a {prof.host}:{prof.port} — "
                "¿servidor apagado, puerto filtrado o firewall?") from exc
        except (socket.gaierror, ConnectionRefusedError, OSError) as exc:
            raise RemoteShellError(
                f"host inalcanzable {prof.host}:{prof.port} ({exc}). "
                "Verifica DNS, ruta de red y que sshd esté escuchando.") \
                from exc
        self._client = client
        _log.success("SSH conectado: %s@%s:%d (policy=%s, %.0f ms).",
                     prof.username, prof.host, prof.port,
                     self.host_key_policy, (time.monotonic() - start) * 1000.0)

    # ------------------------------------------------------------------
    # ejecución
    # ------------------------------------------------------------------
    def exec(self, command: str, timeout: Optional[float] = None
             ) -> ExecResult:
        """Ejecuta ``command`` en el host remoto con deadline estricto.

        Returns:
            :class:`ExecResult` — si vence el plazo, ``timed_out=True``
            y ``rc=-1`` (el rc real ya no se conoce: matamos el canal).

        Raises:
            RemoteShellError: sin sesión previa (llama a connect antes).
        """
        if self._client is None:
            raise RemoteShellError("exec() sin conexión: llama a "
                                   "connect() primero (o el bloque with).")
        budget = timeout if timeout is not None else self.profile.timeout
        start = time.monotonic()
        chan = self._client.get_transport().open_session(
            timeout=self.profile.timeout)
        chan.settimeout(budget)
        out_parts: list[bytes] = []
        err_parts: list[bytes] = []
        timed_out = False
        rc = -1
        try:
            chan.exec_command(command)
            while True:
                if chan.recv_ready():
                    out_parts.append(chan.recv(65536))
                if chan.recv_stderr_ready():
                    err_parts.append(chan.recv_stderr(65536))
                if chan.exit_status_ready():
                    while chan.recv_ready():
                        out_parts.append(chan.recv(65536))
                    while chan.recv_stderr_ready():
                        err_parts.append(chan.recv_stderr(65536))
                    rc = chan.recv_exit_status()
                    break
                if time.monotonic() - start > budget:
                    timed_out = True
                    chan.close()
                    break
                time.sleep(0.01)
        except socket.timeout:
            timed_out = True
            chan.close()
        finally:
            try:
                chan.close()
            except Exception:  # noqa: BLE001 - cierre best-effort
                pass
        duration = (time.monotonic() - start) * 1000.0
        res = ExecResult(
            command=command, rc=rc,
            stdout=b"".join(out_parts).decode("utf-8", errors="replace"),
            stderr=b"".join(err_parts).decode("utf-8", errors="replace"),
            duration_ms=duration, timed_out=timed_out)
        _log.info("exec %s → rc=%s timed_out=%s (%.0f ms).",
                  command.split()[0] if command else "?", res.rc,
                  timed_out, duration)
        return res

    # ------------------------------------------------------------------
    def close(self) -> None:
        """Cierre idempotente de la sesión."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None
            _log.info("Sesión SSH cerrada (%s:%d).", self.profile.host,
                      self.profile.port)

    def __enter__(self) -> "RemoteShellClient":
        self.connect()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        """True si hay una sesión activa."""
        return self._client is not None


# =====================================================================
# Pruebas autónomas: python -m remote.remote_shell
# =====================================================================
if __name__ == "__main__":
    import threading

    print("╔══ remote/remote_shell.py — demo: SSH e2e sobre socket in-process ══╗\n")

    # A) validación de perfil
    SshProfile(host="h", username="u", password="p")
    for kwargs, piece in (
        ({"host": " ", "username": "u", "password": "p"}, "host"),
        ({"host": "h", "port": 0, "username": "u", "password": "p"}, "puerto"),
        ({"host": "h", "username": "u"}, "credencial"),
        ({"host": "h", "username": " ", "password": "p"}, "username"),
        ({"host": "h", "username": "u", "password": "p", "timeout": 0.1},
         "timeout"),
    ):
        try:
            SshProfile(**kwargs)
            raise AssertionError(f"aceptó perfil ilegal: {kwargs}")
        except ValueError as exc:
            assert piece in str(exc), (piece, str(exc))
    print("  ✔ SshProfile: 5 configuraciones ilegales rechazadas con guía")

    # B) servidor SSH real de prueba (paramiko en modo servidor)
    assert PARAMIKO_AVAILABLE, "paramiko obligatorio para el e2e"

    def _run_test_server(behaviors: "dict[str, tuple[str, str, int, float]]",
                         expected_user: str, expected_password: str,
                         stop_after: int = 7) -> "tuple[threading.Thread, paramiko.Transport]":
        """SSH server in-process: behaviors cmd → (out, err, rc, delay)."""
        from paramiko import RSAKey, ServerInterface, Transport

        host_key = RSAKey.generate(2048)
        client_side, server_side = socket.socketpair()

        class _Srv(ServerInterface):
            def __init__(self) -> None:
                self.cmd = ""
                self.cmd_event = threading.Event()

            def check_auth_password(self, user: str, password: str) -> str:
                if user == expected_user and password == expected_password:
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED

            def check_channel_request(self, kind: str, chanid: int) -> str:
                return paramiko.OPEN_SUCCEEDED if kind == "session" \
                    else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command) -> bool:
                self.cmd = command.decode()
                self.cmd_event.set()
                return True

        srv = _Srv()
        transport = Transport(server_side)
        transport.add_server_key(host_key)
        finished = threading.Event()

        def _run() -> None:
            transport.start_server(server=srv)
            for _ in range(stop_after):
                channel = transport.accept(10.0)
                if channel is None:
                    break
                if not srv.cmd_event.wait(5.0):
                    channel.close(); continue
                stdout, stderr, rc, delay = behaviors.get(
                    srv.cmd, (f"echo: {srv.cmd}", "", 0, 0.0))
                srv.cmd_event.clear()
                time.sleep(delay)
                if channel.closed:
                    continue  # el cliente mató el canal (timeout)
                channel.send(stdout)
                if stderr:
                    channel.send_stderr(stderr)
                channel.send_exit_status(rc)
                channel.close()
            finished.set()

        th = threading.Thread(target=_run, daemon=True)
        th.start()
        return th, transport, client_side

    _th, _srv, sock1 = _run_test_server(
        {"uname -a": ("Linux AZZ-v01 6.1 #1 SMP\n", "", 0, 0.0),
         "whoami": ("war\n", "", 0, 0.0),
         "fallo": ("", "boom\n", 7, 0.0),
         "lento": ("tardío\n", "", 0, 2.0)},
        "war", "s3cret")

    # C) full e2e: connect sobre socket inyectado + execs (rc y timeout)
    profile = SshProfile(host="localhost", port=22, username="war",
                         password="s3cret", timeout=6.0)
    client = RemoteShellClient(profile)
    client.connect(sock=sock1)
    n = client.exec("uname -a")
    assert n.ok and "Linux AZZ-v01" in n.stdout and n.duration_ms >= 0
    n2 = client.exec("whoami")
    assert n2.ok and n2.stdout.strip() == "war"
    n3 = client.exec("fallo")
    assert not n3.ok and n3.rc == 7 and "boom" in n3.stderr
    n4 = client.exec("lento", timeout=0.5)
    assert n4.timed_out and n4.rc == -1, n4
    assert n4.duration_ms >= 500
    client.close()
    print("  ✔ e2e: 4 execs (rc=0/rc=7/stderr/timeout=chan-matado-rc=-1)")

    # D) auth rechazada → error accionable (mismo servidor, PSK errada)
    _th2, _srv2, sock2 = _run_test_server({}, "war", "s3cret",
                                          stop_after=1)
    bad = SshProfile(host="localhost", username="war",
                     password="mala", timeout=4.0)
    try:
        RemoteShellClient(bad).connect(sock=sock2)
        raise AssertionError("auth mala aceptada")
    except RemoteShellError as exc:
        assert "autenticación" in str(exc), exc
    print("  ✔ auth fallida → RemoteShellError con guía")

    # E) host inalcanzable → NSError amable (sin sshd en 1791)
    ghost = SshProfile(host="127.0.0.1", port=1791, username="war",
                       password="x", timeout=1.5)
    try:
        RemoteShellClient(ghost).connect()
        raise AssertionError("conectó a un puerto cerrado")
    except RemoteShellError as exc:
        assert "host inalcanzable" in str(exc) or "timeout" in str(exc), exc
    print("  ✔ host inalcanzable/puerto fantasma → guía de diagnóstico")

    # F) exec sin connect → guardia + policy ilegal
    try:
        RemoteShellClient(profile,
                          host_key_policy="acepta_todo_sin_verificar")
        raise AssertionError
    except ValueError:
        pass
    orphan = RemoteShellClient(profile)
    try:
        orphan.exec("echo hola")
        raise AssertionError
    except RemoteShellError as exc:
        assert "llama a connect" in str(exc)
    print("  ✔ guardas: policy ilegal + exec sin connect rechazados")
    print("\n╔══ DEMO COMPLETA: Remote Shell 6/6 baterías ✔ ══╗")
