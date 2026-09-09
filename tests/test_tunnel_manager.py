"""
AZZAZEL tests/test_tunnel_manager.py — Batería de pruebas de VPN Tunnel, Replay Window y KillSwitch.
"""
import time
import pytest
from vpn.tunnel_manager import (
    ReplayWindow,
    KillSwitch,
    TunnelServer,
    TunnelClient,
    HandshakeError,
)


def test_replay_window_behavior():
    rw = ReplayWindow(size=64)
    # Secuencia en orden
    assert rw.check_and_record(0) is True
    assert rw.check_and_record(1) is True
    assert rw.check_and_record(2) is True

    # Duplicado debe ser rechazado
    assert rw.check_and_record(1) is False
    assert rw.check_and_record(2) is False

    # Desorden dentro de la ventana
    assert rw.check_and_record(10) is True
    assert rw.check_and_record(5) is True
    assert rw.check_and_record(5) is False

    # Paquete muy viejo fuera de la ventana
    assert rw.check_and_record(100) is True
    assert rw.check_and_record(0) is False


def test_kill_switch_trigger():
    triggered = []

    def _hook(reason):
        triggered.append(reason)

    ks = KillSwitch(armed=True, hook=_hook)
    assert ks.armed is True
    assert ks.engaged is False

    ks.engage("Túnel caído inesperadamente")
    assert ks.engaged is True
    assert len(triggered) == 1
    assert "Túnel caído" in triggered[0]

    # Disengage
    ks.disengage()
    assert ks.engaged is False


@pytest.mark.anyio
async def test_tunnel_handshake_e2e(dummy_psk: str):
    srv = TunnelServer(dummy_psk, listen_host="127.0.0.1", port=0)
    await srv.start()
    assert srv.port > 0

    client = TunnelClient(
        psk=dummy_psk,
        server_host="127.0.0.1",
        server_port=srv.port,
        handshake_timeout=2.0,
    )
    await client.connect()
    assert client.connected is True
    assert client.session is not None
    assert len(client.session.session_id) == 8

    await client.close()
    await srv.stop()


@pytest.mark.anyio
async def test_tunnel_bad_psk_rejection(dummy_psk: str):
    srv = TunnelServer(dummy_psk, listen_host="127.0.0.1", port=0)
    await srv.start()

    bad_client = TunnelClient(
        psk="wrong_key_that_does_not_match_server_psk",
        server_host="127.0.0.1",
        server_port=srv.port,
        handshake_timeout=1.0,
        max_retries=1,
    )
    with pytest.raises(HandshakeError):
        await bad_client.connect()

    await bad_client.close()
    await srv.stop()
