"""
AZZAZEL tests/test_proxy_chain.py — Batería de pruebas de ProxyChain.
"""
import pytest
from proxy.proxy_chain import (
    ProxyChain,
    ProxyNode,
    ChainReport,
    NodeProbe,
)
from core.config_manager import ConfigManager


def test_proxy_chain_from_config(temp_config_manager: ConfigManager):
    cm = temp_config_manager
    chain = ProxyChain.from_config_manager(cm)
    assert len(chain.nodes) >= 1
    assert chain.nodes[0].name in ("corp-proxy", "direct-out")


def test_chain_report_rendering():
    probes = [
        NodeProbe(
            node_name="nodo_1",
            latency_ms=12.5,
            ok=True,
            detail="CONNECT ok",
        ),
        NodeProbe(
            node_name="nodo_2",
            latency_ms=25.0,
            ok=True,
            detail="NTLMv2 ok",
        ),
    ]
    report = ChainReport(
        target="example.com:443",
        probes=probes,
        total_latency_ms=37.5,
    )
    rendered = report.render(color=False)
    assert "nodo_1" in rendered
    assert "nodo_2" in rendered
    assert "38 ms" in rendered or "37" in rendered
