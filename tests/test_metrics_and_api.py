"""
AZZAZEL tests/test_metrics_and_api.py — Batería de pruebas de Metrics, LogRing, API REST y Dashboard.
"""
import json
import logging
import urllib.request
import urllib.error
import pytest
from monitoring.metrics import (
    MetricsRegistry,
    LogRing,
    VitalRegistry,
    UptimeTracker,
    METRICS,
)
from monitoring.api_server import (
    ApiServer,
    build_redacted_config,
    RateLimiter,
)
from monitoring.dashboard import dashboard_html
from core.config_manager import ConfigManager


def test_metrics_registry():
    mr = MetricsRegistry()
    mr.inc("http_requests_total", 5)
    mr.set_gauge("active_tunnels", 3)
    snap = mr.snapshot()
    assert snap["counters"]["http_requests_total"] == 5
    assert snap["gauges"]["active_tunnels"] == 3

    prom = mr.render_prometheus_text()
    assert "http_requests_total 5" in prom
    assert "active_tunnels 3" in prom


def test_log_ring_buffer():
    lr = LogRing(capacity=50)
    logger = logging.getLogger("test.ring")
    logger.addHandler(lr)
    logger.setLevel(logging.INFO)
    for i in range(10):
        logger.info(f"log line {i}")
    tail = lr.tail(3)
    assert len(tail) == 3
    assert "log line 9" in tail[-1]


def test_vital_registry():
    vr = VitalRegistry()
    vr.register("probe_1", lambda: {"status": "healthy", "cpu": 15})
    vitals = vr.collect()
    assert vitals["probe_1"]["status"] == "healthy"
    assert vitals["probe_1"]["cpu"] == 15


def test_rate_limiter():
    rl = RateLimiter(limit_per_minute=2)
    assert rl.allow("1.1.1.1") is True
    assert rl.allow("1.1.1.1") is True
    assert rl.allow("1.1.1.1") is False


def test_dashboard_html_render():
    html = dashboard_html(app_version="1.0.0", api_prefix="/api/v1")
    assert "<!DOCTYPE html>" in html
    assert "AZZAZEL" in html
    assert "#00ff41" in html  # Hacker theme color


def test_api_server_endpoints(temp_config_manager: ConfigManager):
    cm = temp_config_manager
    token = "test_bearer_token_xyz"
    cm.set("api.auth_token", token)

    api = ApiServer(host="127.0.0.1", port=0, auth_token=token, config_manager=cm)
    api.start_background()
    port = api.port
    assert port > 0

    # 1. Health público (sin auth)
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/health")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data["alive"] is True

    # 2. Status con token
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/status")
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "uptime_s" in data
        assert "vitals" in data

    # 3. Status sin token -> 401 Unauthorized
    req_no_auth = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/status")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req_no_auth)
    assert exc_info.value.code == 401

    api.stop()
