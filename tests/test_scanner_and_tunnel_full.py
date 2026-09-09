"""
Pruebas integrales para network/scanner.py y tunnel/ssh_tunnel.py.
"""
from __future__ import annotations

import asyncio
import socket
from pathlib import Path
import pytest

from network.scanner import (
    PortScanner,
    PortProbe,
    HostReport,
    parse_ports,
    get_local_ipv4,
)
from tunnel.ssh_tunnel import (
    ForwardRule,
    ForwardType,
    SshProfile,
    SshTunnelManager,
    SshTunnelError,
)


def test_scanner_parse_ports_advanced():
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("8080-8083") == [8080, 8081, 8082, 8083]
    assert parse_ports("21, 25, 80-82") == [21, 25, 80, 81, 82]

    with pytest.raises(ValueError):
        parse_ports("70000")
    with pytest.raises(ValueError):
        parse_ports("-1")
    with pytest.raises(ValueError):
        parse_ports("abc")


@pytest.mark.anyio
async def test_port_scanner_local_loopback_async():
    # Iniciar un servidor TCP local temporal
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    scanner = PortScanner(timeout=0.5, concurrency=2)
    report = await scanner.ascan("127.0.0.1", [port])

    assert isinstance(report, HostReport)
    assert report.host == "127.0.0.1"
    assert port in [p.port for p in report.open_ports]
    assert len(report.open_ports) == 1

    server.close()
    await server.wait_closed()


def test_ssh_forward_rule_and_config():
    rule = ForwardRule(
        name="web-fwd",
        forward_type=ForwardType.LOCAL,
        bind_host="127.0.0.1",
        bind_port=8080,
        dest_host="example.com",
        dest_port=80,
    )
    assert rule.bind_port == 8080
    assert rule.dest_port == 80

    profile = SshProfile(
        host="10.0.0.1",
        port=22,
        username="admin",
        password="secretpassword",
    )
    assert profile.host == "10.0.0.1"

    mgr = SshTunnelManager(profile)
    mgr.add_rule(rule)
    assert len(mgr.list_rules()) == 1
    assert mgr.is_running is False
