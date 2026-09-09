"""
AZZAZEL network/scanner.py — Network Tools (Sprint 5).

Escáner de red asíncrono y multiplataforma construido sobre sockets
TCP + ``asyncio`` (sin dependencias externas, sin raw sockets):

- :func:`parse_ports` — parser de especificaciones ``"22,80,8000-8010"``
  con validación estricta y errores accionables.
- :class:`PortScanner` — barrido TCP-connect concurrente (semáforo),
  medición de latencia, resolución de servicio común y *banner grabbing*
  pasivo opcional.
- :class:`NetworkEnumerator` — descubrimiento de hosts vivos. Las
  herramientas clásicas usan ICMP, pero un ping crudo exige sockets
  RAW y privilegios (root / SeLoadDriverPrivilege); para que el módulo
  funcione igual en Windows y Linux sin privilegios, la heurística es
  **TCP-ping**: host vivo = alguno de los puertos ``alive_ports`` da SYN/ACK.
- :func:`get_local_ipv4` — IP local honesta vía truco UDP de ruta.

Ejemplo::

    from network.scanner import PortScanner, parse_ports

    scanner = PortScanner(timeout=1.0, concurrency=400, banner_grab=True)
    report = scanner.scan("192.168.1.1", parse_ports("22,80,443,3000-3010"))
    print(report.render())
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
import sys
from typing import Callable, Iterable, Optional, Sequence

_AZZAZEL_ROOT = Path(__file__).resolve().parent.parent
if str(_AZZAZEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_AZZAZEL_ROOT))

from core.logger import get_logger

_log = get_logger("network.scanner")

__all__ = [
    "COMMON_SERVICES", "PortProbe", "HostReport", "PortScanner",
    "NetworkEnumerator", "parse_ports", "get_local_ipv4",
]

MAX_PORTS_PER_SCAN = 10000
MAX_CONCURRENCY = 2**14

# Tabla propia de servicios habituales (complementa getservbyport, que
# depende de /etc/services y está vacío en instalaciones mínimas).
COMMON_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 80: "http", 110: "pop3", 135: "msrpc", 139: "netbios",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1883: "mqtt", 3000: "dev-http",
    3306: "mysql", 3389: "rdp", 47671: "azz-bridge", 51820: "azz-vpn",
    5900: "vnc", 5432: "postgres", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9000: "pharos", 27017: "mongodb",
}


def parse_ports(spec: str) -> list[int]:
    """Convierte ``"22,80,8000-8010"`` en una lista ordenada y deduplicada.

    Args:
        spec: Lista separada por comas de puertos y/o rangos ``a-b``.

    Returns:
        Lista de enteros (1-65535) en orden ascendente, sin duplicados.

    Raises:
        ValueError: Especificación vacía, token ilegal o fuera de rango,
            con un mensaje que indica el token exacto que falló.
    """
    spec = (spec or "").strip()
    if not spec:
        raise ValueError("Especificación de puertos vacía "
                         "(ejemplo válido: \"22,80,443,8000-8010\").")
    out: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            raise ValueError("Token vacío entre comas en "
                             f"{spec!r}: revisa la sintaxis.")
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
        if match is None:
            raise ValueError(f"Token de puerto ilegal: {token!r} "
                             "(acepta 443 o 8000-8010).")
        a = int(match.group(1))
        b = int(match.group(2)) if match.group(2) is not None else a
        if a > b:
            raise ValueError(f"Rango invertido: {token!r} (inicio > fin).")
        if not (1 <= a <= 65535 and b <= 65535):
            raise ValueError(f"Puerto fuera de rango 1-65535 en {token!r}.")
        if b - a > MAX_PORTS_PER_SCAN:
            raise ValueError(f"Rango {token!r} demasiado grande "
                             f"(límite {MAX_PORTS_PER_SCAN}).")
        out.update(range(a, b + 1))
    if len(out) > MAX_PORTS_PER_SCAN:
        raise ValueError(f"Demasiados puertos en un solo escaneo "
                         f"({len(out)} > {MAX_PORTS_PER_SCAN}).")
    return sorted(out)


@dataclass(frozen=True)
class PortProbe:
    """Resultado de sondear un único puerto TCP."""

    port: int
    open: bool
    latency_ms: float = -1.0
    service: str = ""
    banner: str = ""

    @property
    def label(self) -> str:
        """Etiqueta legible: ``22/ssh OPEN 0.4ms`` o ``23/tcp closed``."""
        svc = self.service or "tcp"
        if not self.open:
            return f"{self.port}/{svc} closed"
        note = f" ‹{self.banner[:32]}›" if self.banner else ""
        return f"{self.port}/{svc} OPEN {self.latency_ms:.1f}ms{note}"


def _service_name(port: int) -> str:
    """Nombre del servicio de un puerto: tabla propia → getservbyport."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, OverflowError):
        return ""


@dataclass
class HostReport:
    """Informe completo del escaneo de UN host."""

    host: str
    ip: str
    probes: list[PortProbe] = field(default_factory=list)
    duration_ms: float = 0.0
    tcp_ping_ok: bool = False

    @property
    def open_ports(self) -> list[PortProbe]:
        """Solo los puertos abiertos detectados."""
        return [p for p in self.probes if p.open]

    def render(self, color: bool = True) -> str:
        """Renderiza el informe; ``color=False`` garantiza 0 caracteres ANSI."""
        open_ps = self.open_ports
        lines = [
            f"Host: {self.host} ({self.ip})",
            f"Duración: {self.duration_ms:.0f} ms · "
            f"probes: {len(self.probes)} · abiertos: {len(open_ps)}",
        ]
        if open_ps:
            lines.append("")
            for probe in open_ps:
                ts = ""
                if color:
                    ts = f"\x1b[38;2;0;255;65m●\x1b[0m "
                lines.append(f"  {ts}{probe.label}")
        else:
            lines.append("  (ningún puerto abierto en la franja probada)")
        body = "\n".join(lines)
        if not color:
            body = _strip_ansi(body)
        return body


def _strip_ansi(text: str) -> str:
    """Elimina cualquier secuencia ANSI residual (para renders externos)."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


class PortScanner:
    """Escáner TCP-connect concurrente con banner grabbing opcional.

    El barrido connect() sin privilegios es una decisión deliberada: el
    barrido SYN clásico requiere raw sockets con root. Con ``concurrency``
    alto y timeouts sub-segundo, TCP-connect mantiene el módulo rápido
    y 100% portable.
    """

    def __init__(self, timeout: float = 1.0, concurrency: int = 400,
                 banner_grab: bool = False) -> None:
        """Inicializa el escáner validando límites anti-accidente.

        Args:
            timeout: Segundos de espera máxima por conexión (0.05-30).
            concurrency: Conexiones simultáneas (1-16384).
        banner_grab: Si ``True``, tras abrir cada puerto se escucha
            pasivamente un instante (0.3 s, máx 128 B) para capturar el
            banner de los servicios que hablan primero. Nunca emite
            tráfico adicional (sin sondas invasivas).

        Raises:
            ValueError: Parámetros fuera de rango operativo.
        """
        if not (0.05 <= timeout <= 30.0):
            raise ValueError("timeout debe estar entre 0.05s y 30s "
                             f"(recibido: {timeout}).")
        if not (1 <= concurrency <= MAX_CONCURRENCY):
            raise ValueError("concurrency debe estar entre 1 y "
                             f"{MAX_CONCURRENCY} (recibido: {concurrency}).")
        self.timeout = timeout
        self.concurrency = concurrency
        self.banner_grab = banner_grab
        self._log_scans = 0

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------
    def scan(self, host: str, ports: Sequence[int],
             on_progress: Optional[Callable[[int, int], None]] = None
             ) -> HostReport:
        """Versión síncrona conveniente (bloquea hasta terminar).

        Args:
            host: Nombre DNS o IP literal (v4/v6).
            ports: Puertos a sondear (lista de :func:`parse_ports`
                habitualmente).
            on_progress: Callable ``(completados, totales)`` por cada
                puerto resuelto.

        Returns:
            :class:`HostReport` con todos los probes.

        Raises:
            RuntimeError: si se llama desde un loop asyncio activo
                (usa :meth:`ascan` en su lugar — no anidar asyncio.run).
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "Hay un loop asyncio corriendo: dentro de código asíncrono "
                "usa 'await scanner.ascan(...)' — asyncio.run anidado no "
                "está permitido por la stdlib.")
        return asyncio.run(self.ascan(host, ports, on_progress))

    async def ascan(self, host: str, ports: Sequence[int],
                    on_progress: Optional[Callable[[int, int], None]] = None
                    ) -> HostReport:
        """Escanea asíncronamente ``host`` en los ``ports`` indicados."""
        ports = list(ports)
        if not host or not host.strip():
            raise ValueError("host vacío: indicaDNS o IP literal.")
        if not ports:
            raise ValueError("lista de puertos vacía: nada que escanear.")
        ip = await self._resolve(host.strip())
        started = time.monotonic()
        probes = await self._probe_all(ip, ports, on_progress)
        report = HostReport(host=host.strip(), ip=ip, probes=probes,
                            duration_ms=(time.monotonic() - started) * 1000.0)
        self._log_scans += 1
        _log.info("Escaneo #%d de %s: %d/%d abiertos en %.0f ms.",
                  self._log_scans, ip, len(report.open_ports),
                  len(probes), report.duration_ms)
        return report

    # ------------------------------------------------------------------
    # Internos
    # ------------------------------------------------------------------
    @staticmethod
    async def _resolve(host: str) -> str:
        """Resuelve DNS sin bloquear el loop; error accionable si no hay DNS."""
        try:
            info = await asyncio.get_running_loop().getaddrinfo(
                host, port=0, family=socket.AF_INET, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"No se pudo resolver '{host}': {exc}. "
                             "Comprueba DNS / nombre del host.") from exc
        return info[0][4][0]

    async def _probe_all(self, ip: str, ports: list[int],
                         on_progress: Optional[Callable[[int, int], None]]
                         ) -> list[PortProbe]:
        sem = asyncio.Semaphore(self.concurrency)
        total = len(ports)
        done = [0]

        async def _one(port: int) -> PortProbe:
            async with sem:
                probe = await self._probe(ip, port)
                done[0] += 1
                if on_progress is not None:
                    on_progress(done[0], total)
                return probe

        return list(await asyncio.gather(*(_one(p) for p in ports)))

    async def _probe(self, ip: str, port: int) -> PortProbe:
        """Un connect() con timeout; captura banner si el puerto habla."""
        started = time.monotonic()
        try:
            read, write = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout)
        except (asyncio.TimeoutError, OSError):
            # TimeoutError = timeout; cualquier OSError = refused/unreachable
            return PortProbe(port=port, open=False,
                             service=_service_name(port))
        latency = (time.monotonic() - started) * 1000.0
        banner = ""
        if self.banner_grab:
            banner = await self._grab_banner(read)
        try:
            write.close()
            await asyncio.wait_for(write.wait_closed(), timeout=1.0)
        except (OSError, asyncio.TimeoutError):
            pass
        return PortProbe(port=port, open=True, latency_ms=latency,
                         service=_service_name(port), banner=banner)

    async def _grab_banner(self, read: asyncio.StreamReader) -> str:
        """Lee pasivamente hasta 128 bytes en 0.3s; jamás emite tráfico."""
        try:
            data = await asyncio.wait_for(read.read(128), timeout=0.3)
        except (asyncio.TimeoutError, OSError, ValueError):
            return ""
        text = data.decode("utf-8", errors="replace")
        return " ".join(text.split())  # una línea limpia


class NetworkEnumerator:
    """Descubrimiento de hosts vivos mediante TCP-ping (sin ICMP crudo).

    Justificación honesta: un ping ICMP necesita socket RAW + privilegios
    de root/elevación y difiere entre Windows y Linux. En su lugar, la
    lógica declara "vivo" a un host si alguno de los ``alive_ports``
    acepta conexión dentro del timeout — resultado reproducible en los
    dos SOs.
    """

    def __init__(self, timeout: float = 0.4, concurrency: int = 256,
                 alive_ports: Sequence[int] = (80, 443, 22, 445, 139)) -> None:
        if not (1 <= len(alive_ports) <= 16):
            raise ValueError("alive_ports debe tener entre 1 y 16 puertos "
                             "de sondeo (los más habituales vienen de serie).")
        self.timeout = timeout
        self.concurrency = concurrency
        self.alive_ports = tuple(alive_ports)
        self._scanner = PortScanner(timeout=timeout,
                                    concurrency=concurrency)

    async def sweep(self, network: str,
                    on_host_up: Optional[Callable[[str], None]] = None
                    ) -> list[str]:
        """Recorre los host bits de ``network`` y devuelve los IPs vivos.

        Args:
            network: Notación CIDR (p. ej. ``"192.168.1.0/24"``). Se
                rechazan prefijos más grandes que /16 para evitar
                barridos accidentales de 65k direcciones.
            on_host_up: callback por cada IP viva en cuanto se descubre.

        Returns:
            Lista de IPs vivas (tiempo de comprobación para x puertos).

        Raises:
            ValueError: CIDR mal formado o prefixlen > /16.
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            raise ValueError(f"CIDR inválido: {network!r} ({exc}).") from exc
        if net.version != 4:
            raise ValueError("Solo IPv4 de momento (el sweep v6 exige "
                             "estrategia de muestreo, no enumeración).")
        if net.prefixlen < 16:
            raise ValueError("Sweep /16+ como máximo: recibiste "
                             f"/{net.prefixlen}. Los barridos masivos son "
                             "y deben seguir siendo una decisión explícita.")
        hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
        _log.info("Sweep TCP-ping de %s (%s hosts × %s puertos).",
                  str(net), len(hosts), len(self.alive_ports))
        sem = asyncio.Semaphore(self.concurrency)
        up: list[str] = []

        async def _host(ip: str) -> None:
            async with sem:
                alive = await self._is_up(ip)
                if alive:
                    up.append(ip)
                    if on_host_up is not None:
                        on_host_up(ip)

        await asyncio.gather(*(_host(ip) for ip in hosts))
        up_sorted = sorted(up, key=lambda ip: tuple(map(int, ip.split("."))))
        _log.info("Sweep %s: %d vivos de %d.", str(net), len(up_sorted),
                  len(hosts))
        return up_sorted

    def sweep_sync(self, network: str) -> list[str]:
        """Versión síncrona de :meth:`sweep`."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Loop asyncio activo: usa 'await "
                               "enumerator.sweep(...)'.")
        return asyncio.run(self.sweep(network))

    async def _is_up(self, ip: str) -> bool:
        for port in self.alive_ports:
            try:
                _, write = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout)
            except (asyncio.TimeoutError, OSError):
                continue
            try:
                write.close()
                await asyncio.wait_for(write.wait_closed(), timeout=0.5)
            except (OSError, asyncio.TimeoutError):
                pass
            return True
        return False


def get_local_ipv4() -> str:
    """IP local honesta de la máquina.

    Usa el truco UDP sin paquetes: conecta un datagrama a una ruta pública
    (sin enviar nada — el SO solo selecciona una interfaz de salida) y lee
    los datos locales del socket. Sin ruta disponible, devuelve
    ``127.0.0.1`` y registra el aviso.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local = sock.getsockname()[0]
    except OSError as exc:
        _log.warning("Sin ruta hacia 8.8.8.8 — IP local por defecto "
                     "127.0.0.1 (%s).", exc)
        return "127.0.0.1"
    _log.info("IP local detectada: %s", local)
    return local


# =====================================================================
# Pruebas autónomas: python -m network.scanner
# =====================================================================
if __name__ == "__main__":
    print("╔══ network/scanner.py — demo Sprint 5: Network Tools ══╗\n")

    # A) parse_ports
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("8000-8003,80") == [80, 8000, 8001, 8002, 8003]
    assert parse_ports("443,80,443-445") == [80, 443, 444, 445]  # dedup
    for bad in ("", "0", "65536", "abc", "80-", "5,", "8-2", "1-"):
        try:
            parse_ports(bad)
            raise AssertionError(f"parse_ports aceptó {bad!r}")
        except ValueError:
            pass
    print("  ✔ parse_ports: 3 válidas + 8 ilegales (todas con guía)")

    async def _demo_live() -> None:
        # B) escaneo real contra un servidor que monta el propio demo
        banner_backlog = {"value": ""}

        async def _echo(read: asyncio.StreamReader,
                        write: asyncio.StreamWriter) -> None:
            write.write(b"SSH-2.0-AZZ_DEMO_SERVER\r\n")
            await write.drain()
            write.close()
            banner_backlog["value"] = "sent"

        server = await asyncio.start_server(_echo, "127.0.0.1", 0)
        alive_port = server.sockets[0].getsockname()[1]

        # Puertos GARANTIZADAMENTE cerrados (bind+close → ECONNREFUSED);
        # no usamos 22/80/etc: el entorno puede tener servicios reales.
        def _free_closed_port() -> int:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        closed_a, closed_b = _free_closed_port(), _free_closed_port()

        scanner = PortScanner(timeout=0.6, concurrency=64, banner_grab=True)
        ports = sorted({alive_port, closed_a, closed_b})
        progress: list[tuple[int, int]] = []
        rep = await scanner.ascan(
            "localhost", ports,
            on_progress=lambda done, total: progress.append((done, total)))
        alive = rep.open_ports
        assert len(progress) == len(ports), "callback de progreso roto"
        assert any(p.port == alive_port for p in alive), rep
        hit = next(p for p in alive if p.port == alive_port)
        assert hit.banner.startswith("SSH-2.0"), hit.banner
        assert hit.latency_ms >= 0.0
        # Los dos puertos cerrados deben aparecer CLOSED
        closed_hits = [p for p in rep.probes
                       if p.port in (closed_a, closed_b)]
        assert len(closed_hits) == 2 and not any(
            p.open for p in closed_hits), closed_hits
        print(f"  ✔ ascan: {len(ports)} puertos, alive={alive_port}/ssh "
              f"banner={hit.banner!r}, latency={hit.latency_ms:.2f} ms")

        # C) sweep de la propia 127.0.0.0/30 detectando nuestro puerto vivo
        enum = NetworkEnumerator(timeout=0.25, concurrency=8,
                                 alive_ports=(alive_port,))
        up = await enum.sweep("127.0.0.0/30")
        assert up == ["127.0.0.1"], up
        print(f"  ✔ sweep 127.0.0.0/30 con alive_port={alive_port} → {up}")

        # D) sweep bien validado: CIDR absurdos = error accionable
        for bad_cidr in ("300.1.1.1/24", "10.0.0.0/8", "10.0.0.1/64",
                         "::1/64"):
            try:
                await enum.sweep(bad_cidr)
                raise AssertionError(f"sweep aceptó {bad_cidr!r}")
            except ValueError as exc:
                assert "CIDR" in str(exc) or "Sweep" in str(exc) or "IPv4" \
                    in str(exc), str(exc)
        print("  ✔ sweep: CIDRs ilegítimos rechazados con guía (casos ×4)")

        # E) render con y sin ANSI
        clean = rep.render(color=False)
        colored = rep.render(color=True)
        assert "\x1b[" not in clean, "render(color=False) con ANSI residual"
        assert str(len(rep.probes)) in clean
        assert f"abiertos: {len(rep.open_ports)}" in clean
        assert str(len(rep.probes)) in colored
        print("  ✔ HostReport.render(): ANSI limpio bidireccional")

        # Sync-scan funciona fuera del loop y se niega dentro
        try:
            scanner.scan("localhost", [alive_port])
            raise AssertionError("scan() debió negarse dentro de loop")
        except RuntimeError:
            pass
        print("  ✔ scan() síncrono: guarda contra asyncio.run anidado")
        server.close()
        await server.wait_closed()

    asyncio.run(_demo_live())

    # F) sync scan desde contexto NO-async + local ip honesta
    s2 = PortScanner(timeout=0.4, concurrency=16)
    r2 = s2.scan("127.0.0.1", parse_ports("1-24"))
    assert r2.ip == "127.0.0.1" and len(r2.probes) == 24
    assert len(r2.open_ports) <= len(r2.probes)
    local_ip = get_local_ipv4()
    local_ip_parts = local_ip.split(".")
    assert len(local_ip_parts) == 4 and all(
        p.isdigit() and 0 <= int(p) <= 255 for p in local_ip_parts
    ), local_ip
    print(f"  ✔ scan() síncrono: 1-24 probados vs 127.0.0.1")
    print(f"  ✔ get_local_ipv4() → {local_ip} (ruta UDP sin paquetes)")
    print("\n" + r2.render(color=False).split("\n")[1])
    print("\n╔══ DEMO COMPLETA: Network Tools 6/6 baterías ✔ ══╗")
