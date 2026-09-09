"""
AZZAZEL VPN — core
==================

Núcleo del sistema: motor principal, configuración, criptografía, eventos, sesiones y logging.
"""

from core.version import __version__, get_version_info

__all__: list[str] = ["__version__", "get_version_info"]
