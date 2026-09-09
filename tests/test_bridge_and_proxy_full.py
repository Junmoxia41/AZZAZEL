"""
Pruebas exhaustivas para bridge/mobile_bridge.py y proxy/proxy_chain.py.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
import pytest

from bridge.mobile_bridge import (
    DeviceRegistry,
    PairedDevice,
    MobileBridge,
    PAIR_TTL_SECONDS,
)
from proxy.proxy_chain import (
    ProxyChain,
    ProxyNode,
    ChainReport,
    ChainError,
)
from proxy.upstream_proxy import UpstreamProxyClient


def test_device_registry_persistence(tmp_path: Path):
    reg_file = tmp_path / "devices.json"
    reg = DeviceRegistry(reg_file)

    dev = reg.add(
        device_id="dev-01",
        name="Pixel 8 Pro",
        token="token_secret_123",
        max_devices=5,
    )
    assert dev is not None
    assert reg.verify("dev-01", "token_secret_123") is not None
    assert len(reg.list()) == 1

    # Recargar desde archivo
    reg2 = DeviceRegistry(reg_file)
    assert reg2.verify("dev-01", "token_secret_123") is not None
    assert reg2.list()[0].name == "Pixel 8 Pro"

    # Eliminar
    assert reg2.remove("dev-01") is True
    assert len(reg2.list()) == 0


def test_proxy_chain_construction_and_nodes():
    client1 = UpstreamProxyClient(host="10.0.0.1", port=8080, auth_type="basic")

    node1 = ProxyNode(name="Node-1", kind="http", host="10.0.0.1", port=8080, auth=client1)
    node2 = ProxyNode(name="Node-2", kind="direct")

    chain = ProxyChain(nodes=[node1, node2])
    assert len(chain.nodes) == 2
    assert chain.nodes[0].name == "Node-1"
    assert chain.nodes[1].name == "Node-2"
