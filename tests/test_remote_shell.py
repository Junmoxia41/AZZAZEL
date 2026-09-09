"""
AZZAZEL tests/test_remote_shell.py — Batería de pruebas de RemoteShellClient y SSH Execution.
"""
import socket
import threading
import time
import pytest
from remote.remote_shell import (
    SshProfile,
    RemoteShellClient,
    RemoteShellError,
    PARAMIKO_AVAILABLE,
)

if PARAMIKO_AVAILABLE:
    import paramiko
    from paramiko import RSAKey, ServerInterface, Transport


def test_ssh_profile_validation():
    p = SshProfile(host="bastion.lan", username="admin", password="password123")
    assert p.host == "bastion.lan"
    assert p.port == 22

    with pytest.raises(ValueError):
        SshProfile(host="", username="admin", password="p")  # Host vacío

    with pytest.raises(ValueError):
        SshProfile(host="bastion", username="", password="p")  # Usuario vacío

    with pytest.raises(ValueError):
        # Sin password ni key_path
        SshProfile(host="bastion", username="admin")


@pytest.mark.skipif(not PARAMIKO_AVAILABLE, reason="Paramiko no instalado")
def test_remote_shell_in_process_exec():
    host_key = RSAKey.generate(2048)
    client_side, server_side = socket.socketpair()

    class _Srv(ServerInterface):
        def __init__(self) -> None:
            self.cmd = ""
            self.cmd_event = threading.Event()

        def check_auth_password(self, user: str, password: str) -> str:
            if user == "war" and password == "s3cret":
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        def check_channel_request(self, kind: str, chanid: int) -> str:
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command) -> bool:
            self.cmd = command.decode()
            self.cmd_event.set()
            return True

    srv = _Srv()
    transport = Transport(server_side)
    transport.add_server_key(host_key)

    def _run() -> None:
        transport.start_server(server=srv)
        while transport.is_active():
            channel = transport.accept(10.0)
            if channel is None:
                break
            if not srv.cmd_event.wait(5.0):
                channel.close()
                continue
            cmd = srv.cmd
            srv.cmd_event.clear()
            if cmd == "whoami":
                channel.send(b"war\n")
                channel.send_exit_status(0)
            elif cmd == "fail_cmd":
                channel.send_stderr(b"Command failed with error\n")
                channel.send_exit_status(2)
            channel.close()

    th = threading.Thread(target=_run, daemon=True)
    th.start()

    profile = SshProfile(host="localhost", port=22, username="war", password="s3cret", timeout=5.0)
    client = RemoteShellClient(profile)
    client.connect(sock=client_side)

    res1 = client.exec("whoami")
    assert res1.ok is True
    assert res1.rc == 0
    assert "war" in res1.stdout

    res2 = client.exec("fail_cmd")
    assert res2.ok is False
    assert res2.rc == 2
    assert "Command failed" in res2.stderr

    client.close()
