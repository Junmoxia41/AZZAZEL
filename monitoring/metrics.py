"""
AZZAZEL monitoring/metrics.py — núcleo de telemetría (Sprint 7).

Piezas pequeñas, thread-safe y sin dependencias que alimentan la API
REST y el dashboard:

- :class:`MetricsRegistry` — contadores y gauges nombrados con
  exportación JSON y formato *Prometheus text* (compatible con
  herramientas estándar).
- :class:`LogRing` — handler de ``logging`` que retiene los últimos N
  registros en memoria (para ``/api/v1/logs`` y la página de eventos).
- :class:`VitalRegistry` — punto único de "sondas vivas": cada módulo
  del daemon registra una callable que devuelve su estado actual
  (sesiones VPN, túnel, bridge, etc.).
- :class:`UptimeTracker` — antigüedad del proceso con render humano.

Ejemplo::

    from monitoring.metrics import METRICS, VITALS, UPTIME
    UPTIME.mark_started()
    METRICS.inc("vpn_frames_rx")
    VITALS.register("vpn-server", lambda: {"sessions": 2})
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from pathlib import Path
import sys
from typing import Any, Callable, Dict, Optional

_AZZAZEL_ROOT = Path(__file__).resolve().parent.parent
if str(_AZZAZEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_AZZAZEL_ROOT))

from core.logger import get_logger

_log = get_logger("monitoring.metrics")

__all__ = [
    "MetricsRegistry", "LogRing", "VitalRegistry", "UptimeTracker",
    "METRICS", "LOG_RING", "VITALS", "UPTIME",
]

VitalProbe = Callable[[], Dict[str, Any]]


class MetricsRegistry:
    """Registro thread-safe de contadores (monótonos) y gauges (puntuales)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}

    def inc(self, name: str, delta: float = 1.0) -> None:
        """Incrementa un contador. Nombre corto y estable (snake_case)."""
        if not name:
            raise ValueError("nombre de métrica vacío.")
        with self._lock:
            self._counters[name] = self._counters.get(name, 0.0) + delta

    def counter(self, name: str) -> float:
        """Valor actual del contador (0.0 si nunca se tocó)."""
        with self._lock:
            return self._counters.get(name, 0.0)

    def set_gauge(self, name: str, value: float) -> None:
        """Fija el valor instantáneo de un gauge (numérico)."""
        if not name:
            raise ValueError("nombre de gauge vacío.")
        with self._lock:
            self._gauges[name] = float(value)

    def snapshot(self) -> dict[str, dict[str, float]]:
        """Foto consistente: ``{"counters": {...}, "gauges": {...}}``."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
            }

    def render_prometheus_text(self) -> str:
        """Exportación en formato texto de Prometheus."""
        snap = self.snapshot()
        lines: list[str] = []
        for name, value in sorted(snap["counters"].items()):
            lines.append(f"{name} {value}")
        for name, value in sorted(snap["gauges"].items()):
            lines.append(f"{name} {value}")
        return "\n".join(lines)


class LogRing(logging.Handler):
    """Handler que guarda los últimos ``capacity`` registros formateados.

    Se añade a UN logger raíz; no interfiere con la salida estándar del
    sistema de logs (es un handler adicional, puramente en memoria).
    """

    def __init__(self, capacity: int = 500,
                 level: int = logging.INFO) -> None:
        if not (10 <= capacity <= 50000):
            raise ValueError("capacity fuera de rango (10-50000).")
        super().__init__(level=level)
        self.capacity = capacity
        self._lock = threading.Lock()
        self._records: deque[str] = deque(maxlen=capacity)
        self.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)-7s] [%(name)s] %(message)s",
            datefmt="%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:  # noqa: BLE001 - diagnóstico nunca rompe el log
            return
        with self._lock:
            self._records.append(msg)

    def tail(self, n: int = 100) -> list[str]:
        """Los últimos ``n`` registros (o menos si no hay tantos)."""
        with self._lock:
            snapshot = list(self._records)
        return snapshot[-n:] if n < len(snapshot) else snapshot


class VitalRegistry:
    """Registro de sondas de estado por nombre de servicio.

    Cada sonda es una callable sin argumentos que devuelve un dict con
    los valores "vivo" del servicio (o lanza: el error se captura y se
    expone como ``{"error": "..."}`` para no tumbar la telemetría).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._probes: dict[str, VitalProbe] = {}

    def register(self, name: str, probe: VitalProbe) -> None:
        if not name:
            raise ValueError("nombre de sonda vacío.")
        with self._lock:
            self._probes[name] = probe
        _log.info("Sonda vital registrada: %s", name)

    def unregister(self, name: str) -> None:
        with self._lock:
            self._probes.pop(name, None)

    def collect(self) -> dict[str, Any]:
        """Ejecuta todas las sondas y devuelve un dict servicio→estado."""
        with self._lock:
            probes = dict(self._probes)
        out: dict[str, Any] = {}
        for name, probe in probes.items():
            try:
                out[name] = probe()
            except Exception as exc:  # noqa: BLE001 - telemetría tolerante
                out[name] = {"error": f"{type(exc).__name__}: {exc}"}
        return out


class UptimeTracker:
    """Antigüedad del proceso; se marca al arrancar cualquier modo."""

    def __init__(self) -> None:
        self._started_at: Optional[float] = None

    def mark_started(self) -> None:
        if self._started_at is None:
            self._started_at = time.monotonic()

    def seconds(self) -> float:
        """Segundos desde mark_started (0.0 si nunca se marcó)."""
        if self._started_at is None:
            return 0.0
        return time.monotonic() - self._started_at

    def human(self) -> str:
        """Render legible: ``2h 14m`` / ``31m 05s`` / ``8s`` / ``0s``."""
        total = int(self.seconds())
        hours, rem = divmod(total, 3600)
        minutes, secs = divmod(rem, 60)
        if hours:
            return f"{hours}h {minutes:02d}m"
        if minutes:
            return f"{minutes}m {secs:02d}s"
        return f"{secs}s"


# Singletons de proceso: la API/los daemons comparten ESTAS instancias.
METRICS = MetricsRegistry()
LOG_RING = LogRing()
VITALS = VitalRegistry()
UPTIME = UptimeTracker()


# =====================================================================
# Pruebas autónomas: python -m monitoring.metrics
# =====================================================================
if __name__ == "__main__":
    print("╔══ monitoring/metrics.py — demo: núcleo de telemetría ══╗\n")

    # A) contadores/gauges + snapshot + render prometheus
    m = MetricsRegistry()
    m.inc("frames_rx"); m.inc("frames_rx"); m.inc("frames_rx", 8)
    m.set_gauge("queue_depth", 3)
    snap = m.snapshot()
    assert snap["counters"]["frames_rx"] == 10.0
    assert snap["gauges"]["queue_depth"] == 3.0
    prom = m.render_prometheus_text()
    assert "frames_rx 10.0" in prom and "queue_depth 3.0" in prom
    json.dumps(snap)  # serializable → la API depende de esto
    print("  ✔ MetricsRegistry: counters/gauges/{json,prometheus}")

    # B) LogRing: guarda records, tail estable, honra capacity
    ring = LogRing(capacity=20)
    logger = logging.getLogger("suite.tool")
    logger.addHandler(ring); logger.setLevel(logging.DEBUG)
    for i in range(25):
        logger.info("evt %d", i)
    logger.removeHandler(ring)
    tail = ring.tail(100)
    assert len(tail) == 20 and "evt 24" in tail[-1], tail[-1]
    assert "evt 0" not in "\n".join(tail), "desbordó capacity"
    assert "evt 20" in "\n".join(tail) and ring.tail(3)[-1] == tail[-1]
    print("  ✔ LogRing: capacity deuced + tail estable")

    # C) VitalRegistry: happy + sonda que rompe → error capturado
    v = VitalRegistry()
    v.register("vpn", lambda: {"sessions": 2, "ka_ok": True})
    def _roto() -> dict: raise RuntimeError("escombro")
    v.register("roto", _roto)
    out = v.collect()
    assert out["vpn"] == {"sessions": 2, "ka_ok": True}
    assert "error" in out["roto"] and "escombro" in out["roto"]["error"]
    v.unregister("roto")
    assert "roto" not in v.collect()
    print("  ✔ VitalRegistry: sonda rota → {error} sin tumbar el collect")

    # D) UptimeTracker
    u = UptimeTracker()
    assert u.seconds() == 0.0 and u.human() == "0s"
    u.mark_started(); u.mark_started()  # idempotente
    time.sleep(0.12)
    assert u.seconds() >= 0.1 and "s" in u.human()
    u2 = UptimeTracker()
    u2._started_at = time.monotonic() - 2 * 3600 - 14 * 60
    assert "2h 14m" == u2.human()
    print("  ✔ UptimeTracker: 0s/2h 14m renders exactos")
    print("\n╔══ DEMO COMPLETA: 4/4 baterías de telemetría ✔ ══╗")
