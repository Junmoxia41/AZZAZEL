"""
AZZAZEL core/version.py — Origen canónico de versión del producto.
"""
from __future__ import annotations

__version__ = "1.0.0"
__product_name__ = "AZZAZEL VPN"
__description__ = "Enterprise Network Warfare & Multi-Hop Proxy Suite"
__author__ = "AZZAZEL Core Engineering Team"
__license__ = "MIT"
__release_date__ = "2026-09-08"

def get_version_info() -> dict[str, str]:
    """Retorna los metadatos completos de la versión actual."""
    return {
        "version": __version__,
        "product_name": __product_name__,
        "description": __description__,
        "author": __author__,
        "license": __license__,
        "release_date": __release_date__,
    }
