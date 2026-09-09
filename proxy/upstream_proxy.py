#!/usr/bin/env python3
"""
AZZAZEL VPN — proxy/upstream_proxy.py
=====================================

Cliente asíncrono del **proxy corporativo (upstream)** con autenticación.

Es la pieza que conecta la PC de casa con el exterior cuando toda la
salida a internet pasa por un proxy de empresa. Implementa el túnel
``CONNECT`` del RFC 7231 sobre sockets asyncio puros (sin dependencias
pesadas), con soporte de autenticación:

- **Basic**  — header ``Proxy-Authorization`` (base64), funciona ya.
- **Digest** — handshake 407 → cálculo RFC 2617 (MD5, qop=auth), ya.
- **NTLM / Kerberos** — lanzan :class:`AuthNotSupportedError` con guía;
  el handshake NTLMv2 se implementará en una iteración dedicada porque
  exige MD4/pure-python (ausente en OpenSSL 3) y merece su propio QA.

Se alimenta directamente de la sección ``proxy.upstream`` de
``config.yaml`` (``bypass_list``, ``ssl_verify``, credenciales...).

Uso básico::

    from proxy.upstream_proxy import UpstreamProxyClient

    client = UpstreamProxyClient.from_config_manager(cm)
    if not client.should_bypass("intranet.empresa.com"):
        reader, writer = await client.open_connect_tunnel("example.com", 443)
        # ... escribir TLS/HTTP directamente sobre el túnel

Demo autocontenida con un proxy CONNECT falso local::

    python proxy/upstream_proxy.py
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import re
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Permite ejecutar este archivo directamente como script (demo standalone).
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.logger import get_logger

__all__ = [
    "UpstreamError",
    "ProxyAuthError",
    "AuthNotSupportedError",
    "UpstreamTestResult",
    "UpstreamProxyClient",
]

_log = get_logger("proxy.upstream")

_CRLF = "\r\n"
_HEADER_END = b"\r\n\r\n"
_MAX_HEADER_BYTES = 16 * 1024  # protección contra servidores maliciosos


# ---------------------------------------------------------------------------
# Excepciones
# ---------------------------------------------------------------------------
class UpstreamError(Exception):
    """Fallo genérico del proxy upstream (red, respuesta inválida...)."""


class ProxyAuthError(UpstreamError):
    """El proxy rechazó las credenciales (407) tras todos los intentos."""


class AuthNotSupportedError(UpstreamError):
    """El esquema de autenticación configurado aún no está implementado."""


# ---------------------------------------------------------------------------
# Resultados
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class UpstreamTestResult:
    """Resultado de una prueba de conectividad contra el upstream.

    Attributes:
        ok: Si el túnel CONNECT se estableció.
        latency_ms: Tiempo total de la negociación (0 si falló).
        detail: Descripción legible del resultado o del fallo.
        target: ``host:port`` objetivo de la prueba.
    """

    ok: bool
    latency_ms: float
    detail: str
    target: str


@dataclass(frozen=True)
class _HttpResponseHead:
    """Cabecera HTTP(s) parseada de la respuesta del proxy."""

    status: int
    reason: str
    headers: dict[str, str]


# ---------------------------------------------------------------------------
# Helpers HTTP/Digest (privados)
# ---------------------------------------------------------------------------
def _parse_auth_params(value: str) -> dict[str, str]:
    """Parsea ``realm="x", nonce="y", qop="auth"`` de un header 407."""
    params: dict[str, str] = {}
    for match in re.finditer(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', value):
        params[match.group(1).lower()] = match.group(2) or match.group(3) or ""
    return params


def _md5_hex(data: str) -> str:
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def _digest_response(
    *,
    username: str,
    password: str,
    method: str,
    uri: str,
    realm: str,
    nonce: str,
    qop: Optional[str],
) -> str:
    """Calcula el ``response`` Digest RFC 2617 (perfil MD5)."""
    ha1 = _md5_hex(f"{username}:{realm}:{password}")
    ha2 = _md5_hex(f"{method}:{uri}")
    if qop:
        nc = "00000001"
        cnonce = secrets.token_hex(8)
        return _md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    return _md5_hex(f"{ha1}:{nonce}:{ha2}")


async def _read_head(reader: asyncio.StreamReader) -> _HttpResponseHead:
    """Lee y parsea la cabecera de respuesta HTTP del proxy.

    Raises:
        UpstreamError: Cabecera excesiva, conexión cerrada o malformada.
    """
    try:
        raw = await reader.readuntil(_HEADER_END)
    except asyncio.LimitOverrunError as exc:
        raise UpstreamError("Cabecera del proxy excede el límite.") from exc
    except asyncio.IncompleteReadError as exc:
        raise UpstreamError("El proxy cerró la conexión sin responder.") from exc
    if len(raw) > _MAX_HEADER_BYTES:
        raise UpstreamError("Cabecera del proxy sospechosamente grande.")
    try:
        text = raw.decode("iso-8859-1")
    except UnicodeDecodeError as exc:  # prácticamente imposible con latin-1
        raise UpstreamError("Cabecera no decodificable.") from exc
    lines = text.split("\r\n")
    status_line = lines[0]
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)", status_line)
    if not match:
        raise UpstreamError(f"Respuesta no-HTTP del proxy: {status_line!r}")
    status = int(match.group(1))
    reason = match.group(2).strip()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    # Si la respuesta trae cuerpo de error (Content-Length), consumirlo para no ensuciar lecturas siguientes
    if status != 200:
        cl_str = headers.get("content-length")
        if cl_str and cl_str.isdigit():
            cl_len = int(cl_str)
            if cl_len > 0:
                try:
                    await reader.readexactly(cl_len)
                except Exception:
                    pass

    return _HttpResponseHead(
        status=status, reason=reason,
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Cliente principal
# ---------------------------------------------------------------------------
class UpstreamProxyClient:
    """Cliente async del proxy corporativo configurado en AZZAZEL.

    Protocolo soportado: HTTP ``CONNECT`` (el estándar para tunelizar
    cualquier TCP, incluido TLS, a través de un proxy de empresa).

    Attributes:
        host: Host del proxy corporativo.
        port: Puerto del proxy.
        username / password / domain: Credenciales (password llega ya
            descifrada de :class:`core.config_manager.ConfigManager`).
        auth_type: "basic" | "digest" | "ntlm" | "kerberos".
        bypass: Lista de exclusiones (CIDR, sufijos o nombres exactos).
        timeout: Timeout por intento (segundos).
        retries: Reintentos ante fallo de RED (no de autenticación).
    """

    def __init__(
        self,
        host: str,
        port: int = 8080,
        username: str = "",
        password: str = "",
        domain: str = "",
        auth_type: str = "basic",
        bypass: Optional[list[str]] = None,
        timeout: float = 10.0,
        retries: int = 3,
        keep_alive: bool = True,
    ) -> None:
        if not host:
            raise UpstreamError("UpstreamProxyClient requiere un host.")
        if not (1 <= port <= 65535):
            raise UpstreamError(f"Puerto upstream fuera de rango: {port}")
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.auth_type = auth_type.strip().lower()
        self.bypass = list(bypass or [])
        self.timeout = timeout
        self.retries = max(1, retries)
        self.keep_alive = keep_alive

    # -- Construcción desde la configuración global -------------------------

    @classmethod
    def from_config_manager(cls, cm, **overrides) -> "UpstreamProxyClient":
        """Construye el cliente desde la sección ``proxy.upstream``.

        Args:
            cm: :class:`~core.config_manager.ConfigManager` cargado.
            overrides: Parámetros que pisan a los del YAML (timeout...).

        Raises:
            UpstreamError: El upstream está deshabilitado o sin host.
        """
        up = cm.config.proxy.upstream
        if not up.enabled:
            raise UpstreamError(
                "proxy.upstream.enabled=false en config.yaml; "
                "activa el upstream o usa salida DIRECT."
            )
        if not up.host:
            raise UpstreamError("proxy.upstream.host está vacío.")
        params = dict(
            host=up.host, port=up.port, username=up.username,
            password=up.password, domain=up.domain, auth_type=up.auth_type,
            bypass=list(up.bypass),
        )
        params.update(overrides)
        return cls(**params)

    # -- Bypass --------------------------------------------------------------

    def should_bypass(self, host: str) -> bool:
        """Decide si un destino debe EVITAR el proxy corporativo.

        Reglas de la ``bypass_list`` de config.yaml:

        - CIDR (``10.0.0.0/8``) → coincide si ``host`` es IP dentro.
        - Punto inicial (``.local``, ``.empresa.com``) → coincide con
          el dominio y sus subdominios.
        - Coincidencia exacta con el nombre (``localhost``...).
        """
        host = host.strip().lower().rstrip(".")
        try:
            host_ip: Optional[ipaddress.IPv4Address | ipaddress.IPv6Address] = (
                ipaddress.ip_address(host)
            )
        except ValueError:
            host_ip = None

        for raw_rule in self.bypass:
            rule = raw_rule.strip().lower()
            if not rule:
                continue
            if "/" in rule and host_ip is not None:
                try:
                    if host_ip in ipaddress.ip_network(rule, strict=False):
                        return True
                except ValueError:
                    continue
            elif rule.startswith("."):
                if host == rule[1:] or host.endswith(rule):
                    return True
            elif host == rule:
                return True
        return False

    # -- Autenticación -------------------------------------------------------

    def _auth_user(self) -> str:
        """Usuario efectivo (con dominio NT si aplica)."""
        if self.domain and "\\" not in self.username:
            return f"{self.domain}\\{self.username}"
        return self.username

    def basic_auth_header(self) -> str:
        """Header ``Proxy-Authorization: Basic ...`` listo para usar."""
        creds = f"{self._auth_user()}:{self.password}"
        token = base64.b64encode(creds.encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    def _ensure_supported_auth(self) -> None:
        if self.auth_type == "kerberos":
            raise AuthNotSupportedError(
                "Autenticación 'kerberos' aún no implementada (requiere "
                "tickets GSSAPI del dominio). Alternativas inmediatas: "
                "auth_type=ntlm (nativo ya) o auth_type=basic si el "
                "proxy lo permite."
            )
        if self.auth_type not in ("basic", "digest", "ntlm", "none", ""):
            raise AuthNotSupportedError(
                f"auth_type desconocido: {self.auth_type!r}."
            )

    # -- CONNECT --------------------------------------------------------------

    def _connect_request(self, target_host: str, target_port: int,
                         proxy_auth: Optional[str]) -> bytes:
        """Construye la petición CONNECT con headers ordenados sin duplicar prefijos."""
        lines = [
            f"CONNECT {target_host}:{target_port} HTTP/1.1",
            f"Host: {target_host}:{target_port}",
        ]
        if proxy_auth:
            pauth = proxy_auth.strip()
            if pauth.lower().startswith("proxy-authorization:"):
                lines.append(pauth)
            else:
                lines.append(f"Proxy-Authorization: {pauth}")
        lines.append("Proxy-Connection: keep-alive" if self.keep_alive
                     else "Proxy-Connection: close")
        lines.append("User-Agent: AZZAZEL/1.0")
        return (_CRLF.join(lines) + _CRLF + _CRLF).encode("ascii")

    async def negotiate_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
    ) -> None:
        """Negocia un CONNECT sobre un stream YA abierto hacia el proxy."""
        self._ensure_supported_auth()
        uri = f"{target_host}:{target_port}"

        if self.auth_type == "ntlm":
            try:
                await self._negotiate_ntlm(reader, writer,
                                           target_host, target_port)
                return
            except Exception as exc:
                _log.debug("Negociación NTLM falló (%s), intentando Basic fallback...", exc)

        auth_header: Optional[str] = None
        if self.username:
            auth_header = self.basic_auth_header()

        for attempt in (1, 2):
            writer.write(self._connect_request(target_host, target_port,
                                               auth_header))
            await writer.drain()
            head = await _read_head(reader)

            if 200 <= head.status < 300:
                _log.debug("CONNECT %s establecido (%d %s) vía %s:%d.",
                           uri, head.status, head.reason,
                           self.host, self.port)
                return

            if head.status == 407 and attempt == 1:
                challenge = head.headers.get("proxy-authenticate", "")
                if challenge.lower().startswith("digest"):
                    params = _parse_auth_params(challenge)
                    response = _digest_response(
                        username=self._auth_user(), password=self.password,
                        method="CONNECT", uri=uri,
                        realm=params.get("realm", ""),
                        nonce=params.get("nonce", ""),
                        qop=params.get("qop", "auth").split(",")[0].strip()
                        or "auth",
                    )
                    auth_header = (
                        f'Digest username="{self._auth_user()}", realm="{params.get("realm", "")}", '
                        f'nonce="{params.get("nonce", "")}", uri="{uri}", '
                        f'response="{response}", qop=auth, nc=00000001, '
                        f'cnonce="{secrets.token_hex(8)}"'
                    )
                    continue  # segundo intento con Digest
                elif self.username:
                    auth_header = self.basic_auth_header()
                    continue

                if not self.username:
                    raise ProxyAuthError(
                        "El proxy exige autenticación (407) pero no hay "
                        "credenciales configuradas en proxy.upstream."
                    )
            if head.status == 407:
                raise ProxyAuthError(
                    f"Credenciales rechazadas por {self.host}:{self.port} "
                    f"(407). Revisa usuario/contraseña/dominio."
                )
            raise UpstreamError(
                f"CONNECT {uri} rechazado: {head.status} {head.reason}"
            )

    async def _negotiate_ntlm(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
    ) -> None:
        """Handshake NTLMv2 completo sobre el stream hacia el proxy.

        Secuencia: CONNECT sin auth → Type1 → (Type2 del proxy) →
        Type3 con respuesta NTLMv2/LMv2 → 200 OK.

        Raises:
            ProxyAuthError: Credenciales/dominio rechazados (407 final).
            UpstreamError: El proxy no habla NTLM o respuestas inválidas.
        """
        from security.ntlm import (
            NtlmError,
            b64_decode,
            b64_encode,
            build_type1,
            build_type3,
            parse_type2,
            split_credentials,
        )

        domain, user = split_credentials(self.username, self.domain)
        uri = f"{target_host}:{target_port}"

        # Paso 1: CONNECT sin autenticación → esperamos 407 + NTLM.
        writer.write(self._connect_request(target_host, target_port, None))
        await writer.drain()
        head = await _read_head(reader)
        if 200 <= head.status < 300:
            return  # proxy sin auth (raro, pero válido)
        if head.status != 407:
            raise UpstreamError(
                f"CONNECT {uri} rechazado pre-auth: "
                f"{head.status} {head.reason}"
            )

        # Paso 2: CONNECT + Type1 (NEGOTIATE)
        token1 = b64_encode(build_type1(domain=domain))
        writer.write(self._connect_request(
            target_host, target_port, f"NTLM {token1}"))
        await writer.drain()
        head2 = await _read_head(reader)
        if 200 <= head2.status < 300:
            return
        if head2.status != 407:
            raise UpstreamError(
                f"Respuesta inesperada a NTLM Type1: {head2.status}"
            )
        challenge_hdr = head2.headers.get("proxy-authenticate", "").strip()
        if not challenge_hdr.upper().startswith("NTLM"):
            raise UpstreamError(
                f"El proxy ofrece {challenge_hdr or 'nada'} tras Type1; "
                f"se esperaba NTLM Type2."
            )
        token2 = challenge_hdr[4:].strip()
        if not token2:
            raise UpstreamError("El proxy no devolvió Type 2 (challenge).")

        # Paso 3: Type2 → Type3 (AUTHENTICATE con NTLMv2)
        try:
            challenge = parse_type2(b64_decode(token2))
            token3 = b64_encode(build_type3(user, self.password, domain,
                                            challenge))
        except NtlmError as exc:
            raise UpstreamError(f"Type 2 inválido del proxy: {exc}") from exc

        writer.write(self._connect_request(
            target_host, target_port, f"NTLM {token3}"))
        await writer.drain()
        head3 = await _read_head(reader)
        if 200 <= head3.status < 300:
            _log.info("NTLM auth OK como %s\\%s (%s) → CONNECT %s.",
                      domain or "(sin dominio)", user,
                      self.host, uri)
            return
        if head3.status == 407:
            raise ProxyAuthError(
                f"NTLM rechazado por {self.host}:{self.port} (407 tras "
                f"Type3). Revisa usuario/contraseña/dominio o política "
                f"del proxy (¿exige Kerberos?)."
            )
        raise UpstreamError(
            f"Respuesta inesperada a NTLM Type3: {head3.status} "
            f"{head3.reason}"
        )

    async def open_connect_tunnel(
        self, target_host: str, target_port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Abre un túnel TCP al destino A TRAVÉS del proxy corporativo.

        Aplica ``timeout`` y ``retries`` ante fallos de red; los fallos
        de autenticación NO se reintentan (sería ruido y riesgo de
        bloqueo de cuenta corporativa).

        Returns:
            ``(reader, writer)`` del stream ya tunelizado: todo lo que
            se escriba llega al destino final.

        Raises:
            UpstreamError: Tras agotar los reintentos.
        """
        last_error: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            started = time.monotonic()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port),
                    timeout=self.timeout,
                )
                await asyncio.wait_for(
                    self.negotiate_connect(reader, writer,
                                           target_host, target_port),
                    timeout=self.timeout,
                )
                elapsed = (time.monotonic() - started) * 1000
                _log.info(
                    "Túnel upstream %s:%d → %s:%d listo en %.0f ms.",
                    self.host, self.port, target_host, target_port, elapsed,
                )
                return reader, writer
            except (ProxyAuthError, AuthNotSupportedError):
                raise
            except (OSError, asyncio.TimeoutError, UpstreamError) as exc:
                last_error = exc
                _log.warning(
                    "Intento %d/%d de CONNECT falló (%s: %s)",
                    attempt, self.retries, type(exc).__name__, exc,
                )
                if attempt < self.retries:
                    await asyncio.sleep(min(2 ** attempt, 8) * 0.25)
        raise UpstreamError(
            f"No se pudo abrir túnel vía {self.host}:{self.port} "
            f"tras {self.retries} intentos: {last_error}"
        )

    # Alias conveniente de open_connect_tunnel
    open_tunnel = open_connect_tunnel

    async def test_connectivity(
        self, target_host: str = "example.com", target_port: int = 443
    ) -> UpstreamTestResult:
        """Prueba real: abre y cierra un CONNECT midiendo la latencia."""
        started = time.monotonic()
        target = f"{target_host}:{target_port}"
        try:
            reader, writer = await self.open_connect_tunnel(
                target_host, target_port
            )
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            latency = (time.monotonic() - started) * 1000
            _log.success("Upstream verificado (%s) en %.0f ms.",
                         target, latency)
            return UpstreamTestResult(
                ok=True, latency_ms=latency,
                detail="CONNECT 200 OK", target=target,
            )
        except UpstreamError as exc:
            latency = (time.monotonic() - started) * 1000
            _log.error("Prueba de upstream fallida (%s): %s", target, exc)
            return UpstreamTestResult(
                ok=False, latency_ms=latency, detail=str(exc), target=target,
            )


# ---------------------------------------------------------------------------
# Demo standalone: proxy CONNECT falso + túnel real hacia echo server
# ---------------------------------------------------------------------------
async def _fake_connect_proxy(port: int, good_creds: str) -> asyncio.AbstractServer:
    """Mini-proxy CONNECT de prueba (autentica Basic y reenvía)."""

    async def handle(reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(_HEADER_END)
        first = data.split(b"\r\n", 1)[0].decode()
        _, target, _ = first.split(" ", 2)
        auth_ok = f"Basic {good_creds}".encode() in data
        if not auth_ok:
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                         b"Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n")
            await writer.drain()
            writer.close()
            return
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

        async def pipe(r, w):
            try:
                while True:
                    chunk = await r.read(4096)
                    if not chunk:
                        break
                    w.write(chunk)
                    await w.drain()
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                w.close()

        await asyncio.gather(pipe(reader, w2), pipe(r2, writer))

    return await asyncio.start_server(handle, "127.0.0.1", port)


async def _echo_server(port: int) -> asyncio.AbstractServer:
    async def handle(reader, writer):
        while True:
            data = await reader.read(1024)
            if not data:
                break
            writer.write(b"ECHO:" + data)
            await writer.drain()
        writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", port)


async def _demo_async() -> None:
    """Demo: túnel REAL a través del proxy falso hasta un echo server."""
    echo = await _echo_server(0)
    echo_port = echo.sockets[0].getsockname()[1]

    demo_pw = os.environ.get("AZZAZEL_DEMO_PASS", "demo_test_pswd")
    creds = base64.b64encode(f"EMPRESA\\juan:{demo_pw}".encode()).decode()
    proxy = await _fake_connect_proxy(0, creds)
    proxy_port = proxy.sockets[0].getsockname()[1]

    async with echo, proxy:
        print(f"─ echo :{echo_port} · fake-proxy :{proxy_port} ─")

        client = UpstreamProxyClient(
            host="127.0.0.1", port=proxy_port, username="juan",
            password=demo_pw, domain="EMPRESA", auth_type="basic",
            bypass=[".local", "192.168.0.0/16", "localhost"],
        )

        print("─ 1. Bypass ─")
        cases = {"intranet.local": True, "192.168.1.10": True,
                 "localhost": True, "google.com": False,
                 "10.5.5.5": False, "mi.empresa.com": False}
        for host, esperado in cases.items():
            got = client.should_bypass(host)
            assert got == esperado, (host, got, esperado)
            print(f"    {host:<18} bypass={got} ✔")

        print("─ 2. CONNECT autenticado + datos por el túnel ─")
        result = await client.test_connectivity("127.0.0.1", echo_port)
        assert result.ok, result.detail
        print(f"    CONNECT OK en {result.latency_ms:.0f} ms ✔")

        reader, writer = await client.open_connect_tunnel("127.0.0.1",
                                                          echo_port)
        writer.write(b"hola desde el movil")
        resp = await asyncio.wait_for(reader.read(64), timeout=5)
        assert resp == b"ECHO:hola desde el movil", resp
        writer.close()
        print(f"    eco a través del túnel: {resp!r} ✔")

        print("─ 3. Credenciales malas → ProxyAuthError limpio ─")
        bad = UpstreamProxyClient(host="127.0.0.1", port=proxy_port,
                                  username="juan", password="MAL",
                                  auth_type="basic", retries=1)
        try:
            await bad.open_connect_tunnel("127.0.0.1", echo_port)
        except ProxyAuthError:
            print("    407 → ProxyAuthError ✔")
        else:
            raise AssertionError("credenciales malas no deben pasar")

    print("─ demo upstream OK ─")


def _demo() -> None:
    asyncio.run(_demo_async())


if __name__ == "__main__":
    _demo()
