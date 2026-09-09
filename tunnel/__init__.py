"""
AZZAZEL VPN — tunnel
====================

Módulo de túneles: SSH, port forwarding local (-L), remoto (-R) y dinámico SOCKS5 (-D).
"""

from tunnel.ssh_tunnel import (
    ForwardRule,
    ForwardStats,
    ForwardType,
    PARAMIKO_AVAILABLE,
    SshTunnelError,
    SshTunnelManager,
)

__version__: str = "1.0.0"
__all__: list[str] = [
    "ForwardRule",
    "ForwardStats",
    "ForwardType",
    "PARAMIKO_AVAILABLE",
    "SshTunnelError",
    "SshTunnelManager",
]
