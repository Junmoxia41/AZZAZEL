"""
AZZAZEL tests/test_scanner.py — Batería de pruebas de Network Tools y Port Scanner.
"""
import socket
import threading
import pytest
from network.scanner import (
    parse_ports,
    PortScanner,
    NetworkEnumerator,
    get_local_ipv4,
)


def test_parse_ports_valid():
    ports = parse_ports("22,80,443")
    assert ports == [22, 80, 443]

    range_ports = parse_ports("8080-8083")
    assert range_ports == [8080, 8081, 8082, 8083]

    combined = parse_ports("22, 80-82, 443")
    assert combined == [22, 80, 81, 82, 443]


def test_parse_ports_invalid():
    with pytest.raises(ValueError):
        parse_ports("invalid")

    with pytest.raises(ValueError):
        parse_ports("70000")

    with pytest.raises(ValueError):
        parse_ports("8080-8000")  # Rango invertido


def test_get_local_ipv4():
    ip = get_local_ipv4()
    assert isinstance(ip, str)
    assert len(ip.split(".")) == 4


def test_port_scanner_local_probe():
    # Iniciar un socket de prueba en puerto efímero
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(5)

    scanner = PortScanner(timeout=0.5, concurrency=10, banner_grab=False)
    report = scanner.scan("127.0.0.1", [port, port + 1])
    srv.close()

    assert report.host == "127.0.0.1"
    open_p = [p.port for p in report.open_ports]
    assert port in open_p
    assert (port + 1) not in open_p
