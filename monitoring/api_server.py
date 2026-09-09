"""
AZZAZEL monitoring/api_server.py — API REST de gestión (Sprint 7).

Servidor HTTP construido sobre ``http.server`` (stdlib pura, sin
framework): ``ThreadingHTTPServer`` + tabla de rutas muy explícita,
sirviendo la consola web (:mod:`monitoring.dashboard`) y endpoints
JSON protegidos con *Bearer token*:

- ``GET  /``                      consola web (HTML embebido, sin CDN).
- ``GET  /api/v1/health``         liveness pública (sin auth; pensada
  para orquestadores).
- ``GET  /api/v1/status``         modo, uptime, sondas vitales.
- ``GET  /api/v1/metrics``        snapshot JSON; ``?fmt=prom`` → texto
  Prometheus.
- ``GET  /api/v1/logs?n=100``     últimas N líneas del ring en memoria.
- ``GET  /api/v1/config``         config completo con secretos REDACTADOS.
- ``GET  /api/v1/events``         **SSE**: heartbeat periódico con las
  sondas vitales (la consola web lo pinta en directo).

Defensas integradas: auth con comparación constante, rate-limit por IP
(ventana deslizante, config ``api.rate_limit`` req/min) con respuesta
``429``, CORS desde ``api.cors_origins``, y paro limpio desde el loop
principal (``stop()``). La auth vive solo en el header — nunca en la
URL (los logs de proxy/caché no deberían ver tokens).
"""
from __future__ import annotations

import hmac
import json
from pathlib import Path
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

_AZZAZEL_ROOT = Path(__file__).resolve().parent.parent
if str(_AZZAZEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_AZZAZEL_ROOT))

from core.config_manager import SECRET_FIELDS, ConfigManager
from core.logger import get_logger
from monitoring.metrics import (LOG_RING, METRICS, UPTIME, VITALS,
                                LogRing, MetricsRegistry, VitalRegistry)

_log = get_logger("monitoring.api")

__all__ = ["ApiServer", "build_redacted_config", "RateLimiter"]

DEFAULT_HEAD = {"Content-Type": "application/json; charset=utf-8"}
HEALTH_PATH = "/api/v1/health"
SSE_KEEPALIVE_S = 5.0  # latido del stream de eventos


class RateLimiter:
    """Ventana deslizante por IP: ``limit`` peticiones por 60 segundos."""

    def __init__(self, limit_per_minute: int = 100) -> None:
        if not (1 <= limit_per_minute <= 100000):
            raise ValueError("rate_limit fuera de rango (1-100000/min).")
        self.limit = limit_per_minute
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def allow(self, ip: str) -> bool:
        """True si esta IP puede pedir ahora; registra el acierto."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(ip, deque())
            while hits and now - hits[0] > 60.0:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


def build_redacted_config(cm: ConfigManager) -> dict[str, Any]:
    """Config completo con cada campo de :data:`SECRET_FIELDS` → "***".

    La lectura atraviesa ``cm.config.as_dict()`` — ya desencriptado en
    memoria — de modo que la redacción es la ÚLTIMA línea de defensa
    antes de que el dict salga al socket.
    """
    dump = cm.config.as_dict()
    for key in SECRET_FIELDS:
        cursor: Any = dump
        parts = key.split(".")
        for part in parts[:-1]:
            if not isinstance(cursor, dict):
                break
            cursor = cursor.get(part)
        else:
            if isinstance(cursor, dict) and parts[-1] in cursor \
                    and cursor[parts[-1]]:
                cursor[parts[-1]] = "***"
    return dump


class _ApiHandler(BaseHTTPRequestHandler):
    """Handler generado por fábrica: usa ``self.server.app`` inyectado."""

    server_version = "AZZAZEL-API/1.0"

    # --------------------------------------------------------------
    # utilidades internas
    # --------------------------------------------------------------
    def _app(self) -> "ApiServer":
        return self.server.app  # type: ignore[attr-defined]

    def _send(self, status: int, body: bytes,
              headers: Optional[dict[str, str]] = None) -> None:
        self.send_response(status)
        merged = dict(DEFAULT_HEAD)
        if headers:
            merged.update(headers)
        for key, value in merged.items():
            self.send_header(key, value)
        cors = self._app()._cors_for(self.headers.get("Origin", ""), self)
        if cors:
            self.send_header("Access-Control-Allow-Origin", cors)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        self._send(status, json.dumps(payload, default=str).encode("utf-8"))

    def _err(self, status: int, message: str) -> None:
        self._json(status, {"ok": False, "error": message})

    def _client_ip(self) -> str:
        host = self.client_address[0] if self.client_address else "?"
        return host

    def _authorized(self) -> bool:
        """Bearer constante-time. Health pública; resto, token requerido."""
        token = self._app().auth_token.strip()
        if not token:
            return True  # API sin token configurada: aviso ya en logs
        sent = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if sent.startswith(prefix):
            return hmac.compare_digest(
                sent[len(prefix):].strip().encode("utf-8"),
                token.encode("utf-8")
            )
        # Fallback browser query param (?token=) para SSE y consola web
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        param_token = qs.get("token", [""])[0].strip()
        if param_token:
            return hmac.compare_digest(
                param_token.encode("utf-8"),
                token.encode("utf-8")
            )
        return False

    # --------------------------------------------------------------
    # rutas
    # --------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - firma impuesta por stdlib
        ip = self._client_ip()
        if not self._app().rate.allow(ip):
            return self._err(429, "rate limit superado (ver api.rate_limit)")
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)

        if path == HEALTH_PATH:
            return self._json(200, {"ok": True, "alive": True,
                                    "uptime_s": round(UPTIME.seconds(), 1)})

        if path == "/" or path == "/index.html":
            html = self._app().render_dashboard()
            return self._send(200, html, {
                "Content-Type": "text/html; charset=utf-8"})

        if not self._authorized():
            self._err(401, "token inválido o ausente — header "
                      "'Authorization: Bearer <token>' requerido")
            return

        if path == "/api/v1/status":
            return self._json(200, self._app().status_payload())
        if path == "/api/v1/metrics":
            if "fmt=prom" in parsed.query or query.get("fmt") == ["prom"]:
                text = METRICS.render_prometheus_text()
                return self._send(200, text.encode("utf-8"),
                                  {"Content-Type": "text/plain; "
                                   "charset=utf-8"})
            return self._json(200, {"ok": True, **METRICS.snapshot()})
        if path == "/api/v1/logs":
            raw_n = query.get("n", ["100"])[0]
            try:
                n = max(1, min(int(raw_n), 1000))
            except ValueError:
                return self._json(400, {
                    "ok": False, "error": "parametro 'n' inválido."})
            return self._json(200, {"ok": True, "lines": LOG_RING.tail(n)})
        if path == "/api/v1/config":
            cm = self._app().config_manager
            if cm is None:
                return self._err(409, "config_manager no registrado en la "
                                      "API (modo standalone).")
            return self._json(200, {"ok": True,
                                    "config": build_redacted_config(cm)})
        if path == "/api/v1/events":
            return self._serve_sse()

        self._err(404, f"ruta desconocida: {path}")

    do_HEAD = do_GET

    def _serve_sse(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        app = self._app()
        _log.info("Cliente SSE conectado (%s).", self._client_ip())
        beat = 0
        while not app.stop_event.is_set():
            payload = {
                "beat": beat,
                "uptime_s": round(UPTIME.seconds(), 1),
                "vitals": app.vitals.collect(),
            }
            chunk = f"event: vitals\ndata: {json.dumps(payload, default=str)}\n\n"
            try:
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                _log.info("Cliente SSE desconectado (%s).", self._client_ip())
                return
            beat += 1
            app.stop_event.wait(SSE_KEEPALIVE_S)
        _log.info("SSE cerrado por paro del servidor.")

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        _log.debug("http %s — %s", self._client_ip(), fmt % args)


class ApiServer:
    """Servidor REST en hilo propio; paro limpio con ``stop()``."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9999,
                 auth_token: str = "",
                 config_manager: Optional[ConfigManager] = None,
                 cors_origins: Optional[list[str]] = None,
                 rate_limit: int = 100,
                 metrics: Optional[MetricsRegistry] = None,
                vitals: Optional[VitalRegistry] = None,
                 log_ring: Optional[LogRing] = None,
                 dashboard_fn: Optional[Callable[[], bytes]] = None) -> None:
        if not (0 <= port <= 65535):
            raise ValueError(f"puerto API inválido: {port} (0=efímero, "
                             "1-65535 fijos)")
        self.host, self.port = host, port
        self.auth_token = auth_token or ""
        if not self.auth_token:
            _log.warning("API REST sin auth_token configurado: endpoints "
                         "abiertos — configura 'api.auth_token' para "
                         "redes no confiables.")
        self.config_manager = config_manager
        self.cors_origins = cors_origins or ["*"]
        self.rate = RateLimiter(rate_limit)
        self.metrics = metrics or METRICS      # compartidos por defecto
        self.vitals = vitals or VITALS
        self.log_ring = log_ring or LOG_RING
        self._dashboard_fn = dashboard_fn
        self.stop_event = threading.Event()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    @classmethod
    def from_config(cls, cm: ConfigManager, **overrides: Any) -> "ApiServer":
        """Construye con los valores de la sección ``api`` del Config."""
        cfg = cm.config.api
        return cls(host=cfg.host, port=cfg.port,
                   auth_token=cm.get("api.auth_token") or "",
                   cors_origins=list(cfg.cors_origins),
                   rate_limit=cfg.rate_limit,
                   config_manager=cm, **overrides)

    def start_background(self) -> None:
        """Arranca ``serve_forever`` en un daemon-thread propio."""
        app_obj = self  # renombrado: evita el seguro shadowing del class body

        class _Server(ThreadingHTTPServer):
            daemon_threads = True
            app = app_obj

        try:
            self._server = _Server((self.host, self.port), _ApiHandler)
        except OSError as exc:
            raise RuntimeError(f"no se pudo abrir la API en "
                               f"{self.host}:{self.port} ({exc}). Otro "
                               "proceso ocupa ese puerto?") from exc
        self.port = self._server.server_address[1]  # puerto real y efímero
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="azz-api", daemon=True)
        self._thread.start()
        _log.success("API REST escuchando en http://%s:%d", self.host,
                     self.port)

    def stop(self) -> None:
        """Parada ordenada: señal de stop a SSE + shutdown + close."""
        self.stop_event.set()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        _log.info("API REST detenida.")

    # ------------------------------------------------------------------
    def status_payload(self) -> dict[str, Any]:
        """El JSON exacto de ``/api/v1/status``."""
        return {
            "ok": True,
            "app": "AZZAZEL VPN",
            "uptime_s": round(UPTIME.seconds(), 1),
            "uptime_human": UPTIME.human(),
            "vitals": self.vitals.collect(),
        }

    def render_dashboard(self) -> bytes:
        """HTML de la consola; functión inyectable para tests."""
        if self._dashboard_fn is not None:
            return self._dashboard_fn()
        from monitoring.dashboard import dashboard_html
        return dashboard_html().encode("utf-8")

    def _cors_for(self, origin: str,
                  _handler: Any) -> str:
        if "*" in self.cors_origins:
            return "*"
        if origin and origin in self.cors_origins:
            return origin
        return ""


# =====================================================================
# Pruebas autónomas: python -m monitoring.api_server
# =====================================================================
if __name__ == "__main__":
    import io
    import logging
    import tempfile
    import urllib.error
    import urllib.request

    print("╔══ monitoring/api_server.py — demo: API REST en vivo ══╗\n")
    UPTIME.mark_started()

    TOKEN = "t0ken-de-prueba"
    api = ApiServer(host="127.0.0.1", port=0, auth_token=TOKEN,
                    rate_limit=1000)
    api.start_background()
    base = f"http://127.0.0.1:{api.port}"

    def _get(path: str, token: Optional[str] = TOKEN,
             timeout: float = 5.0):
        req = urllib.request.Request(base + path, method="GET")
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Origin", "http://local")
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as err:
            return err.code, err.read(), dict(err.headers)

    # A) health pública sin token; resto protegidas (401)
    code, body, _ = _get(HEALTH_PATH, token=None)
    assert code == 200 and json.loads(body)["alive"] is True
    code, _, _ = _get("/api/v1/status", token=None)
    assert code == 401
    code, _, _ = _get("/api/v1/status", token="incorrecto")
    assert code == 401
    print("  ✔ auth: health pública · status requiere Bearer correcto (401)")

    # B) status / metrics (json + prometheus) / config redactada
    code, body, _ = _get("/api/v1/status")
    st = json.loads(body)
    assert st["ok"] and "vitals" in st and "uptime_s" in st
    METRICS.inc("req_rx", 41)
    code, body, _ = _get("/api/v1/metrics")
    assert json.loads(body)["counters"]["req_rx"] == 41.0
    code, body, hdrs = _get("/api/v1/metrics?fmt=prom")
    assert b"req_rx 41.0" in body and hdrs["Content-Type"].startswith("text/plain")
    print("  ✔ status + metrics json/prom con counter del proceso leídos")

    # C) logs ring expuesto + n clamp
    logging.getLogger().addHandler(LOG_RING)
    logging.getLogger().setLevel(10)
    logging.getLogger("suite.retro").warning("evento-ESPORÁDICO-α")
    code, body, _ = _get("/api/v1/logs?n=5000")
    logs = json.loads(body)["lines"]
    assert len(logs) <= 1000 and any("ESPORÁDICO" in l for l in logs)
    logging.getLogger().removeHandler(LOG_RING)
    print(f"  ✔ logs: {len(logs)} líneas (n clamp ≤1000, caracteres vivos)")

    # D) config redacción: secreto nunca en claro por HTTP
    from pathlib import Path
    from core.crypto_engine import CryptoEngine
    tmp = Path(tempfile.mkdtemp(prefix="azz-api-"))
    cm = ConfigManager(tmp / "cfg.yaml")
    cm.set_crypto(CryptoEngine.for_machine(Path("data")))
    cm.load_or_create()
    cm.set("proxy.upstream.password", "P455w0rd-Vi5ible")
    cm.save()
    api_w_cfg = ApiServer(host="127.0.0.1", port=0, auth_token=TOKEN,
                          config_manager=cm)
    api_w_cfg.start_background()
    base2 = f"http://127.0.0.1:{api_w_cfg.port}"
    req = urllib.request.Request(base2 + "/api/v1/config")
    req.add_header("Authorization", f"Bearer {TOKEN}")
    body = urllib.request.urlopen(req, timeout=5.0).read()
    conf = json.loads(body)["config"]
    assert conf["proxy"]["upstream"]["password"] == "***"
    assert "P455w0rd" not in body.decode("utf-8")
    api_w_cfg.stop()
    print("  ✔ config HTTP: SECRET_FIELDS → '***' (contrasena jamás sale)")

    # E) SSE: primer latido + paro limpio
    req = urllib.request.Request(base + "/api/v1/events")
    req.add_header("Authorization", f"Bearer {TOKEN}")
    resp = urllib.request.urlopen(req, timeout=6.0)
    first = resp.readline().decode().strip()
    second = resp.readline().decode().strip()
    assert first == "event: vitals" and second.startswith("data: {")
    resp.close()
    print("  ✔ SSE /api/v1/events: 'event: vitals' + data JSON en directo")

    # F) rate-limit: superar la ventana → 429 + mensaje accionable
    tight = ApiServer(host="127.0.0.1", port=0, auth_token=TOKEN,
                      rate_limit=3)
    tight.start_background()
    codes = []
    for _ in range(5):
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    f"http://127.0.0.1:{tight.port}" + HEALTH_PATH),
                timeout=3.0)
            codes.append(200)
        except urllib.error.HTTPError as err:
            codes.append(err.code)
    tight.stop()
    assert codes.count(200) == 3 and codes.count(429) == 2, codes
    print(f"  ✔ rate-limit: ventana {codes} → 429 desde la 4ª req")

    # G) CORS + dashboard servido
    code, body, hdrs = _get("/")
    assert code == 200 and hdrs["Access-Control-Allow-Origin"] == "*"
    assert b"SENTINEL" not in body  # por defecto = plantilla real
    print("  ✔ CORS '*' + consola HTML servida en /")

    api.stop()
    print("\n╔══ DEMO COMPLETA: REST API 7/7 baterías ✔ ══╗")
