#!/usr/bin/env python3
"""
AZZAZEL VPN — proxy/proxy_chain.py
==================================

Encadenamiento de proxies (`proxy chain`): composición, prueba de
latencia nodo a nodo, health-check en background y apertura de túneles
multi-hop a través de la cadena.

Modelo::

    [Cliente] → NODO 1 → NODO 2 → … → NODO N → [Destino]
                 (http)    (socks)      (direct)

- Cada hop HTTP se negocia con ``CONNECT`` (reutilizando
  :class:`proxy.upstream_proxy.UpstreamProxyClient`, con su auth).
- Los hops ``socks5`` y ``direct`` se modelan ya en la topología; el
  handshake CONNECT de varios hops funciona hoy; el handshake SOCKS5
  nativo llega con ``proxy/socks5_proxy.py`` (Sprint 2, siguiente
  archivo) — hasta entonces un hop socks5 en medio lanza
  :class:`ChainError` con mensaje claro.
- **Failover documentado**: la cadena se prueba entera; si un nodo
  intermedio falla, ``test_chain`` reporta exactamente cuál y la
  cadena se marca NO-OK (no hay bypass silencioso de un proxy — eso
  rompería las políticas corporativas que el usuario configuró).

Uso básico::

    from proxy.proxy_chain import ProxyChain, ProxyNode

    chain = ProxyChain.from_config_manager(cm)   # local → upstream → destino
    report = await chain.test_chain("example.com", 443)
    print(report.render())                        # caja con latencias
    reader, writer = await chain.open_tunnel("example.com", 443)

Demo autocontenida (dos proxies falsos encadenados + echo server)::

    python proxy/proxy_chain.py
"""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.logger import get_logger
from proxy.upstream_proxy import (
    AuthNotSupportedError,
    ProxyAuthError,
    UpstreamError,
    UpstreamProxyClient,
)
from ui.cli import ascii_art as art

__all__ = [
    "ChainError",
    "ProxyNode",
    "NodeProbe",
    "ChainReport",
    "ProxyChain",
]

_log = get_logger("proxy.chain")

VALID_NODE_KINDS = ("http", "socks5", "direct")


class ChainError(Exception):
    """Fallo de composición o de túnel en la cadena de proxies."""


# ---------------------------------------------------------------------------
# Nodos
# ---------------------------------------------------------------------------
@dataclass
class ProxyNode:
    """Un salto de la cadena.

    Attributes:
        name: Etiqueta legible ("corp-proxy", "local", ...).
        host: Host del nodo (vacío = salida DIRECTA a internet).
        port: Puerto del nodo.
        kind: "http" (CONNECT), "socks5" o "direct".
        auth: Cliente autenticado si el hop exige credenciales (solo
            hops ``http`` por ahora).
        timeout: Timeout por intento de conexión/probe (s).
    """

    name: str
    host: str = ""
    port: int = 0
    kind: str = "direct"
    auth: Optional[UpstreamProxyClient] = None
    timeout: float = 8.0

    def __post_init__(self) -> None:
        self.kind = self.kind.strip().lower()
        if self.kind not in VALID_NODE_KINDS:
            raise ChainError(
                f"Tipo de nodo inválido: {self.kind!r} "
                f"(válidos: {', '.join(VALID_NODE_KINDS)})"
            )
        if self.kind != "direct":
            if not self.host:
                raise ChainError(f"El nodo {self.name!r} necesita host.")
            if not (1 <= self.port <= 65535):
                raise ChainError(
                    f"Puerto inválido en nodo {self.name!r}: {self.port}"
                )

    @property
    def address(self) -> str:
        """``host:port`` legible (o ``DIRECT``)."""
        return f"{self.host}:{self.port}" if self.kind != "direct" else "DIRECT"


@dataclass(frozen=True)
class NodeProbe:
    """Resultado del chequeo de un nodo individual."""

    node_name: str
    ok: bool
    latency_ms: float
    detail: str


# ---------------------------------------------------------------------------
# Informe
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ChainReport:
    """Informe completo de :meth:`ProxyChain.test_chain`."""

    probes: list[NodeProbe]
    total_latency_ms: float
    target: str

    @property
    def ok(self) -> bool:
        """La cadena está operativa solo si TODOS los nodos responden."""
        return all(p.ok for p in self.probes)

    def render(self, color: bool = True) -> str:
        """Caja ASCII con el estado de cada nodo y la latencia total."""
        theme = art.get_theme()
        lines: list[str] = []
        for i, probe in enumerate(self.probes):
            estado = "[✓]" if probe.ok else "[✗]"
            color_fn = (theme.primary if probe.ok else theme.alert) \
                if color else ""
            line = (f"{estado} [{i}] {probe.node_name:<18} "
                    f"{probe.latency_ms:>7.0f} ms   {probe.detail}")
            lines.append(f"{color_fn}{line}"
                         f"{art.AnsiPalette.RESET if color else ''}")
        verdict = "CHAINED — cadena operativa" if self.ok else \
            "CADENA ROTA — revisa el nodo marcado"
        verdict_color = (theme.primary if self.ok else theme.alert) \
            if color else ""
        lines.append("")
        lines.append(f"{verdict_color}{verdict} · total "
                     f"{self.total_latency_ms:.0f} ms → {self.target}"
                     f"{art.AnsiPalette.RESET if color else ''}")
        return art.box(
            lines, title="PROXY CHAIN TEST", style="double",
            border_color=theme.secondary if color else "none",
        )


# ---------------------------------------------------------------------------
# Cadena principal
# ---------------------------------------------------------------------------
class ProxyChain:
    """Secuencia ordenada de proxies con pruebas y túneles multi-hop."""

    def __init__(self, nodes: Sequence[ProxyNode]) -> None:
        if not nodes:
            raise ChainError("Una cadena necesita al menos un nodo.")
        self.nodes: list[ProxyNode] = list(nodes)
        self.healthy: dict[str, bool] = {
            n.name: True for n in self.nodes
        }

    # -- Construcción desde config.yaml ------------------------------------

    @classmethod
    def from_config_manager(cls, cm, **overrides) -> "ProxyChain":
        """Compone la cadena según ``proxy.upstream`` de la config:

        - upstream activado → ``[corp-proxy (http+auth), DIRECT]``
        - upstream desactivado → ``[DIRECT]`` (salida directa)
        """
        up = cm.config.proxy.upstream
        if not up.enabled:
            _log.info("Upstream desactivado: cadena = salida directa.")
            return cls([ProxyNode(name="direct-out", kind="direct")])
        client = UpstreamProxyClient.from_config_manager(cm, **overrides)
        nodes = [
            ProxyNode(name="corp-proxy", host=client.host,
                      port=client.port, kind="http", auth=client),
            ProxyNode(name="direct-out", kind="direct"),
        ]
        _log.info("Cadena compuesta: corp-proxy(%s:%d) → direct.",
                  client.host, client.port)
        return cls(nodes)

    # -- Sondeo ---------------------------------------------------------------

    async def probe_node(self, node: ProxyNode) -> NodeProbe:
        """TCP-connect al nodo midiendo latencia (sin auth ni CONNECT)."""
        if node.kind == "direct":
            return NodeProbe(node.name, True, 0.0, "salida directa")
        started = time.monotonic()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node.host, node.port),
                timeout=node.timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            latency = (time.monotonic() - started) * 1000
            return NodeProbe(node.name, True, latency, "TCP OK")
        except (OSError, asyncio.TimeoutError) as exc:
            latency = (time.monotonic() - started) * 1000
            return NodeProbe(node.name, False, latency,
                             f"{type(exc).__name__}: {exc or 'timeout'}")

    async def test_chain(
        self, target_host: str = "example.com", target_port: int = 443
    ) -> ChainReport:
        """Prueba la cadena: sondea cada nodo y luego el túnel COMPLETO.

        El último probe es el túnel end-to-end real (open_tunnel al
        target), de modo que el informe refleja latencia de suma de hops
        + negociación CONNECT autenticada.
        """
        started = time.monotonic()
        probes: list[NodeProbe] = []
        for node in self.nodes:
            probe = await self.probe_node(node)
            probes.append(probe)
            self.healthy[node.name] = probe.ok
            if not probe.ok:
                _log.warning("Nodo caído en la cadena: %s (%s).",
                             node.name, probe.detail)

        # Túnel completo si todos los nodos responden a TCP.
        if all(p.ok for p in probes):
            try:
                t0 = time.monotonic()
                reader, writer = await self.open_tunnel(
                    target_host, target_port
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                full_ms = (time.monotonic() - t0) * 1000
                probes.append(NodeProbe(
                    "end-to-end", True, full_ms,
                    f"CONNECT {target_host}:{target_port} OK",
                ))
            except (ChainError, UpstreamError) as exc:
                full_ms = (time.monotonic() - t0) * 1000
                probes.append(NodeProbe("end-to-end", False, full_ms,
                                        str(exc)))
        total = (time.monotonic() - started) * 1000
        report = ChainReport(probes=probes, total_latency_ms=total,
                             target=f"{target_host}:{target_port}")
        if report.ok:
            _log.success("Cadena verificada (%.0f ms) → %s.",
                         total, report.target)
        else:
            _log.error("Cadena NO operativa → %s.", report.target)
        return report

    # -- Túnel multi-hop -----------------------------------------------------------

    async def open_tunnel(
        self, target_host: str, target_port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Abre un túnel al destino atravesando TODOS los nodos HTTP.

        Algoritmo: conecta al primer nodo y negocia ``CONNECT`` al
        siguiente; repite hop a hop sobre el MISMO stream (los CONNECT
        intermedios tunelizan dentro del túnel anterior); el último
        CONNECT apunta al destino real. Un nodo ``direct`` en la
        posición i significa "salir a internet desde el nodo i-1" — la
        cadena termina ahí (es el caso normal: corp-proxy → direct).

        Raises:
            ChainError: Topología inservible (direct no terminal, socks5
                pendiente, nodo caído...).
            UpstreamError: Fallo de red/CONNECT en algún hop.
            ProxyAuthError: Auth rechazada en algún hop.
        """
        http_hops = [n for n in self.nodes if n.kind != "direct"]
        # honestidad de topología: direct es siempre el último nodo
        for i, node in enumerate(self.nodes):
            if node.kind == "direct" and i != len(self.nodes) - 1:
                raise ChainError(
                    "El nodo 'direct' solo puede ser el último de la cadena."
                )
        if any(n.kind == "socks5" for n in http_hops):
            raise ChainError(
                "Hops socks5 todavía no soportados en el túnel multi-hop "
                "(llegan con proxy/socks5_proxy.py)."
            )
        if not http_hops:
            # Cadena = salida directa
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=self.nodes[-1].timeout,
                )
            except (OSError, asyncio.TimeoutError) as exc:
                raise ChainError(
                    f"Salida directa a {target_host}:{target_port} falló: "
                    f"{exc or 'timeout'}"
                ) from exc

        first = http_hops[0]
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(first.host, first.port),
                timeout=first.timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise UpstreamError(
                f"No se alcanza el primer nodo {first.address}: "
                f"{exc or 'timeout'}"
            ) from exc

        # Hops intermedios: CONNECT al siguiente nodo de la cadena.
        try:
            for hop_index, hop in enumerate(http_hops):
                client = hop.auth or UpstreamProxyClient(
                    host=hop.host, port=hop.port, timeout=hop.timeout,
                    retries=1,
                )
                is_last_hop = hop_index == len(http_hops) - 1
                if is_last_hop:
                    dst_host, dst_port = target_host, target_port
                else:
                    nxt = http_hops[hop_index + 1]
                    dst_host, dst_port = nxt.host, nxt.port
                await asyncio.wait_for(
                    client.negotiate_connect(reader, writer,
                                             dst_host, dst_port),
                    timeout=hop.timeout,
                )
                _log.debug("Hop %d (%s) CONNECT → %s:%d OK.",
                           hop_index, hop.name, dst_host, dst_port)
        except (ProxyAuthError, AuthNotSupportedError, UpstreamError,
                asyncio.TimeoutError) as exc:
            writer.close()
            if isinstance(exc, asyncio.TimeoutError):
                raise UpstreamError("Timeout negociando un hop CONNECT.") \
                    from exc
            raise

        _log.info("Túnel multi-hop (%d hops) abierto → %s:%d.",
                  len(http_hops), target_host, target_port)
        return reader, writer

    # -- Health-check en background -------------------------------------------

    async def health_monitor(
        self,
        interval: float = 30.0,
        stop: Optional[asyncio.Event] = None,
    ) -> None:
        """Sondea la cadena periódicamente y loguea cambios de estado.

        Pensado para engancharse al loop del modo ``--daemon``. Termina
        limpiamente cuando ``stop`` (o CanelledError) lo indica.
        """
        _log.info("Health monitor de cadena activo (cada %.0f s).", interval)
        while True:
            if stop is not None and stop.is_set():
                break
            for node in self.nodes:
                probe = await self.probe_node(node)
                previous = self.healthy.get(node.name, True)
                if probe.ok != previous:
                    self.healthy[node.name] = probe.ok
                    if probe.ok:
                        _log.success("Nodo recuperado: %s.", node.name)
                    else:
                        _log.warning("Nodo CAÍDO: %s (%s).",
                                     node.name, probe.detail)
            try:
                await asyncio.wait_for(asyncio.sleep(interval), timeout=interval)
            except asyncio.CancelledError:
                break
        _log.info("Health monitor detenido.")


# ---------------------------------------------------------------------------
# Demo standalone: cadena de 2 proxies falsos → echo server
# ---------------------------------------------------------------------------
async def _fake_proxy_with_relay(port: int, creds: Optional[str],
                                 name: str) -> asyncio.AbstractServer:
    """CONNECT proxy falso que reenvía a cualquier destino (como un corp)."""

    async def handle(reader, writer):
        try:
            data = await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError:
            # Conexión TCP que se cerró sin enviar nada (probe TCP del
            # health-check); no es un error del proxy, cierre silencioso.
            writer.close()
            return
        if creds and f"Basic {creds}".encode() not in data:
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                         b"Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        first = data.split(b"\r\n", 1)[0].decode()
        _, target, _ = first.split(" ", 2)
        host, _, port_s = target.partition(":")
        try:
            r2, w2 = await asyncio.open_connection(host, int(port_s))
        except OSError:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        _log.debug("[%s] relay establecido → %s", name, target)

        async def pipe(r, w):
            try:
                while True:
                    chunk = await r.read(8192)
                    if not chunk:
                        break
                    w.write(chunk)
                    await w.drain()
            except OSError:
                pass
            finally:
                w.close()

        await asyncio.gather(pipe(reader, w2), pipe(r2, writer))

    return await asyncio.start_server(handle, "127.0.0.1", port)


async def _echo(port: int) -> asyncio.AbstractServer:
    async def handle(reader, writer):
        while (data := await reader.read(1024)):
            writer.write(b"ECHO:" + data)
            await writer.drain()
        writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", port)


async def _demo_async() -> None:
    import base64

    echo = await _echo(0)
    echo_port = echo.sockets[0].getsockname()[1]

    creds = base64.b64encode(b"juan:S3cr3to!").decode()
    proxy_b = await _fake_proxy_with_relay(0, creds, "B")   # corp proxy
    proxy_a = await _fake_proxy_with_relay(0, None, "A")    # proxy local
    port_a = proxy_a.sockets[0].getsockname()[1]
    port_b = proxy_b.sockets[0].getsockname()[1]

    async with echo, proxy_a, proxy_b:
        print(f"─ local A :{port_a} → corp B :{port_b} (auth) → echo :{echo_port} ─")

        auth_b = UpstreamProxyClient(
            host="127.0.0.1", port=port_b, username="juan",
            password=os.environ.get("AZZAZEL_DEMO_PASS", "demo_test_pswd"), auth_type="basic",
        )
        chain = ProxyChain([
            ProxyNode(name="local-A", host="127.0.0.1", port=port_a,
                      kind="http"),
            ProxyNode(name="corp-B", host="127.0.0.1", port=port_b,
                      kind="http", auth=auth_b),
            ProxyNode(name="direct-out", kind="direct"),
        ])

        print("─ 1. test_chain completo ─")
        report = await chain.test_chain("127.0.0.1", echo_port)
        assert report.ok, report.render(color=False)
        print(report.render(color=False))

        print("─ 2. datos a través del túnel de 2 hops ─")
        reader, writer = await chain.open_tunnel("127.0.0.1", echo_port)
        writer.write(b"mensaje desde el movil")
        resp = await asyncio.wait_for(reader.read(64), timeout=5)
        assert resp == b"ECHO:mensaje desde el movil", resp
        writer.close()
        print(f"    eco multi-hop: {resp!r} ✔")

        print("─ 3. failover honesto: nodo caído detectado ─")
        proxy_b.close()
        await proxy_b.wait_closed()
        report2 = await chain.test_chain("127.0.0.1", echo_port)
        assert not report2.ok
        print("    cadena marcada NO-OK con el nodo exacto ✔")

    print("─ demo chain OK ─")


def _demo() -> None:
    asyncio.run(_demo_async())


if __name__ == "__main__":
    _demo()
