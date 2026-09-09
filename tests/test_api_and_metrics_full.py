"""
Pruebas integrales de API Server, Métricas, Vitals y Dashboard HTML.
"""
from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
import pytest

from monitoring.metrics import LogRing, MetricsRegistry, METRICS, VitalRegistry, VITALS
from monitoring.api_server import ApiServer
from monitoring.dashboard import dashboard_html


def test_dashboard_html_rendering_comprehensive():
    html = dashboard_html(
        app_version="1.0.0",
        api_prefix="/api/v1",
    )
    assert "<!DOCTYPE html>" in html
    assert "AZZAZEL" in html
    assert "1.0.0" in html


def test_metrics_registry_methods():
    reg = MetricsRegistry()
    reg.inc("rx_bytes", 1024)
    reg.inc("tx_bytes", 2048)
    reg.set_gauge("active_sessions", 3)

    snap = reg.snapshot()
    assert snap["counters"]["rx_bytes"] == 1024
    assert snap["counters"]["tx_bytes"] == 2048
    assert snap["gauges"]["active_sessions"] == 3

    prom_text = reg.render_prometheus_text()
    assert "rx_bytes 1024.0" in prom_text


def test_api_server_full_routes():
    ring = LogRing(capacity=50)
    record1 = logging.LogRecord("main", logging.INFO, "main.py", 1, "System starting up...", (), None)
    record2 = logging.LogRecord("vpn", logging.WARNING, "vpn.py", 1, "Keepalive warning test", (), None)
    ring.emit(record1)
    ring.emit(record2)

    metrics = MetricsRegistry()
    metrics.inc("vpn_rx_pkts", 42)

    api = ApiServer(
        host="127.0.0.1",
        port=0,
        auth_token="secure_test_token_123",
        rate_limit=200,
        metrics=metrics,
        log_ring=ring,
    )
    api.start_background()

    try:
        base_url = f"http://127.0.0.1:{api.port}"
        headers = {"Authorization": "Bearer secure_test_token_123"}

        # 1. Endpoint /api/v1/status
        req = urllib.request.Request(f"{base_url}/api/v1/status", headers=headers)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode())
            assert data.get("ok") is True or "product" in data

        # 2. Endpoint /api/v1/metrics
        req = urllib.request.Request(f"{base_url}/api/v1/metrics", headers=headers)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode())
            assert "counters" in data

        # 3. Endpoint /api/v1/logs
        req = urllib.request.Request(f"{base_url}/api/v1/logs", headers=headers)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode())
            assert "lines" in data

        # 4. Endpoint / (Dashboard HTML)
        req = urllib.request.Request(f"{base_url}/", headers=headers)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            html_content = resp.read().decode()
            assert "<!DOCTYPE html>" in html_content

        # 5. Unauthorized access
        req_unauth = urllib.request.Request(f"{base_url}/api/v1/status")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_unauth, timeout=2.0)
        assert exc_info.value.code == 401

        # 6. Route 404
        req_404 = urllib.request.Request(f"{base_url}/api/v1/nonexistent", headers=headers)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_404, timeout=2.0)
        assert exc_info.value.code == 404

    finally:
        api.stop()
