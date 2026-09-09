"""
AZZAZEL tests/test_ssh_tunnel.py — Batería de pruebas de SshTunnelManager y Port Forwarding.
"""
import socket
import struct
import threading
import time
import pytest
from tunnel.ssh_tunnel import (
    ForwardRule,
    ForwardType,
    SshTunnelManager,
    PARAMIKO_AVAILABLE,
)
from remote.remote_shell import SshProfile

if PARAMIKO_AVAILABLE:
    import paramiko
    from paramiko import RSAKey, ServerInterface, Transport


def test_forward_rule_dataclass():
    r = ForwardRule("test_rule", "local", "127.0.0.1", 8080, "10.0.0.1", 80)
    assert r.forward_type == ForwardType.LOCAL
    assert r.bind_port == 8080
    assert "[-L]" in r.render()

    with pytest.raises(ValueError):
        ForwardRule("invalid", "local", "127.0.0.1", -1, "10.0.0.1", 80)


@pytest.mark.skipif(not PARAMIKO_AVAILABLE, reason="Paramiko no instalado")
def test_ssh_tunnel_local_forward_e2e():
    # 1. Echo server
    echo_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    echo_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo_srv.bind(("127.0.0.1", 0))
    echo_port = echo_srv.getsockname()[1]
    echo_srv.listen(5)

    def _echo():
        while True:
            try:
                c, _ = echo_srv.accept()
                d = c.recv(4096)
                if d:
                    c.sendall(b"ECHO:" + d)
                c.close()
            except Exception:
                break

    threading.Thread(target=_echo, daemon=True).start()

    # 2. SSH Server in-process con direct-tcpip
    host_key = RSAKey.generate(2048)
    client_side, server_side = socket.socketpair()

    class _Srv(ServerInterface):
        def check_auth_password(self, user: str, password: str) -> str:
            return paramiko.AUTH_SUCCESSFUL if user == "war" and password == "s3cret" else paramiko.AUTH_FAILED

        def check_channel_request(self, kind: str, chanid: int) -> str:
            return paramiko.OPEN_SUCCEEDED

        def check_channel_direct_tcpip_request(self, chanid: int, origin, destination):
            return paramiko.OPEN_SUCCEEDED

        def check_port_forward_request(self, address: str, port: int) -> int:
            return port

    ssh_trans = Transport(server_side)
    ssh_trans.add_server_key(host_key)

    def _run_ssh():
        ssh_trans.start_server(server=_Srv())
        while ssh_trans.is_active():
            chan = ssh_trans.accept(1.0)
            if chan is not None:
                try:
                    target_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target_s.connect(("127.0.0.1", echo_port))

                    def _p1():
                        try:
                            while True:
                                data = chan.recv(4096)
                                if not data:
                                    break
                                target_s.sendall(data)
                        except Exception:
                            pass
                        finally:
                            target_s.close()

                    def _p2():
                        try:
                            while True:
                                data = target_s.recv(4096)
                                if not data:
                                    break
                                chan.sendall(data)
                        except Exception:
                            pass
                        finally:
                            chan.close()

                    threading.Thread(target=_p1, daemon=True).start()
                    threading.Thread(target=_p2, daemon=True).start()
                except Exception:
                    chan.close()

    threading.Thread(target=_run_ssh, daemon=True).start()

    profile = SshProfile(host="localhost", port=22, username="war", password="s3cret", timeout=5.0)
    tunnel_mgr = SshTunnelManager(profile)
    tunnel_mgr.start(sock=client_side)

    # Añadir Local Forward
    l_rule = tunnel_mgr.add_local_forward("test-l", 0, "127.0.0.1", echo_port)
    time.sleep(0.15)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", l_rule.bind_port))
    s.sendall(b"TEST_SSH_FORWARD")
    resp = s.recv(4096)
    s.close()
    time.sleep(0.1)

    assert resp == b"ECHO:TEST_SSH_FORWARD"
    assert l_rule.stats.bytes_tx > 0
    assert l_rule.stats.bytes_rx > 0

    st = tunnel_mgr.status()
    assert st["running"] is True
    assert st["rules_count"] == 1

    tunnel_mgr.stop()
    echo_srv.close()
