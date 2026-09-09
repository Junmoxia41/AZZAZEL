"""
AZZAZEL protocol/version.py — Identificación canónica y versiones de AZZ1.
"""
from __future__ import annotations

PROTOCOL_NAME: str = "AZZ1"
PROTOCOL_VERSION: int = 1
WIRE_VERSION_MAJOR: int = 1
WIRE_VERSION_MINOR: int = 0
WIRE_VERSION: tuple[int, int] = (WIRE_VERSION_MAJOR, WIRE_VERSION_MINOR)

MIN_SUPPORTED_VERSION: int = 1
MAX_SUPPORTED_VERSION: int = 1

CONTROL_MAGIC: bytes = b"AZZ-C1\n"   # Datagramas de control/handshake JSON
FRAME_MAGIC: bytes = b"AZZ1"        # Datagramas de datos binarios cifrados

def is_supported_version(version: int) -> bool:
    """Valida si la versión del protocolo remoto es compatible."""
    return MIN_SUPPORTED_VERSION <= version <= MAX_SUPPORTED_VERSION
