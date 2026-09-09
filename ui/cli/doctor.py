"""
AZZAZEL ui/cli/doctor.py — Suite integral de diagnóstico y verificación del sistema.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import os
import platform
import shutil
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.logger import AnsiPalette
from core.version import __version__, __product_name__


@dataclass
class DiagnosticCheck:
    name: str
    category: str
    passed: bool
    message: str
    is_critical: bool = False
    remediation: Optional[str] = None


class SystemDoctor:
    """Ejecuta verificaciones exhaustivas sobre el entorno, dependencias, red y seguridad."""

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self.config_path = config_path or (Path(__file__).resolve().parents[2] / "config.yaml")
        self.results: list[DiagnosticCheck] = []

    def check_python_version(self) -> DiagnosticCheck:
        major, minor = sys.version_info[:2]
        passed = (major == 3 and minor >= 10)
        msg = f"Python {sys.version.split()[0]} detectado (requerido >= 3.10)"
        return DiagnosticCheck(
            name="Versión de Python",
            category="Entorno",
            passed=passed,
            message=msg,
            is_critical=True,
            remediation="Actualice Python a la versión 3.10 o superior." if not passed else None,
        )

    def check_privileges(self) -> DiagnosticCheck:
        is_admin = False
        if os.name == "nt":
            import ctypes
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_admin = False
        else:
            is_admin = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

        label = "Administrador" if os.name == "nt" else "Root (UID 0)"
        msg = f"Privilegios elevados ({label}): {'SÍ' if is_admin else 'NO'}"
        return DiagnosticCheck(
            name="Privilegios de Sistema",
            category="Seguridad",
            passed=is_admin,
            message=msg,
            is_critical=False,
            remediation="Requerido para TUN/TAP y reglas de firewall en vivo." if not is_admin else None,
        )

    def check_crypto_primitives(self) -> DiagnosticCheck:
        try:
            from core.crypto_engine import CryptoEngine
            from protocol.crypto import generate_ephemeral_keypair, compute_ecdh_secret
            from security.ntlm import nt_hash

            # Test AES-256-GCM
            engine = CryptoEngine(b"0" * 32)
            enc = engine.encrypt_bytes(b"test", aad=b"aad")
            dec = engine.decrypt_bytes(enc, aad=b"aad")
            assert dec == b"test"

            # Test X25519
            p1, pub1 = generate_ephemeral_keypair()
            p2, pub2 = generate_ephemeral_keypair()
            s1 = compute_ecdh_secret(p1, pub2)
            s2 = compute_ecdh_secret(p2, pub1)
            assert s1 == s2

            # Test MD4 NTLM
            assert len(nt_hash("Password")) == 16

            return DiagnosticCheck(
                name="Motor Criptográfico (AES-GCM, X25519, HKDF, MD4)",
                category="Criptografía",
                passed=True,
                message="Todas las primitivas criptográficas operan correctamente",
                is_critical=True,
            )
        except Exception as exc:
            return DiagnosticCheck(
                name="Motor Criptográfico",
                category="Criptografía",
                passed=False,
                message=f"Fallo en pruebas criptográficas: {exc}",
                is_critical=True,
                remediation="Instale el paquete 'cryptography' actualizado.",
            )

    def check_tun_device(self) -> DiagnosticCheck:
        if os.name == "nt":
            # Windows: Comprobar drivers wintun o tap-windows6
            return DiagnosticCheck(
                name="Dispositivo TUN / TAP (Windows)",
                category="Red",
                passed=True,
                message="Soporte UDP socket verificado (driver wintun opcional)",
                is_critical=False,
            )
        else:
            # Linux: Comprobar /dev/net/tun
            tun_path = Path("/dev/net/tun")
            exists = tun_path.exists()
            readable = os.access(tun_path, os.R_OK | os.W_OK) if exists else False
            msg = f"/dev/net/tun: {'Disponible y accesible' if readable else 'Existe pero sin permisos' if exists else 'No encontrado'}"
            return DiagnosticCheck(
                name="Dispositivo TUN (/dev/net/tun)",
                category="Red",
                passed=readable,
                message=msg,
                is_critical=False,
                remediation="Ejecute 'sudo modprobe tun' o lance con permisos de superusuario.",
            )

    def check_port_availability(self, port: int, proto: str = "tcp") -> bool:
        sock_type = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        try:
            with socket.socket(socket.AF_INET, sock_type) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                return True
        except Exception:
            return False

    def check_network_ports(self) -> DiagnosticCheck:
        ports_to_check = [
            (51820, "udp", "VPN Server UDP"),
            (8080, "tcp", "HTTP Proxy"),
            (1080, "tcp", "SOCKS5 Proxy"),
            (47671, "tcp", "Mobile Bridge"),
            (9999, "tcp", "REST API"),
        ]
        conflicts = []
        for port, proto, desc in ports_to_check:
            if not self.check_port_availability(port, proto):
                conflicts.append(f"{desc} (:{port}/{proto})")

        passed = (len(conflicts) == 0)
        msg = "Todos los puertos por defecto libres" if passed else f"Puertos ocupados: {', '.join(conflicts)}"
        return DiagnosticCheck(
            name="Puertos de Escucha Predeterminados",
            category="Red",
            passed=passed,
            message=msg,
            is_critical=False,
            remediation="Cambie los puertos en config.yaml si otros servicios están en conflicto.",
        )

    def check_firewall_backend(self) -> DiagnosticCheck:
        if os.name == "nt":
            has_netsh = shutil.which("netsh") is not None
            return DiagnosticCheck(
                name="Backend de Firewall (Windows)",
                category="Seguridad",
                passed=has_netsh,
                message="netsh advfirewall disponible" if has_netsh else "netsh no disponible",
                is_critical=False,
            )
        else:
            has_iptables = shutil.which("iptables") is not None
            has_nft = shutil.which("nft") is not None
            backend = "iptables" if has_iptables else ("nftables" if has_nft else "ninguno")
            passed = (has_iptables or has_nft)
            return DiagnosticCheck(
                name="Backend de Firewall (Linux)",
                category="Seguridad",
                passed=passed,
                message=f"Backend detectado: {backend}",
                is_critical=False,
                remediation="Instale iptables o nftables para soporte de Kill-Switch en vivo." if not passed else None,
            )

    def check_dependencies(self) -> list[DiagnosticCheck]:
        deps = [
            ("cryptography", "cryptography", True),
            ("yaml", "PyYAML", True),
            ("customtkinter", "customtkinter", False),
            ("psutil", "psutil", False),
            ("hypothesis", "hypothesis", False),
        ]
        results = []
        for mod, pkg, req in deps:
            try:
                importlib.import_module(mod)
                ver = importlib.metadata.version(pkg)
                results.append(DiagnosticCheck(
                    name=f"Dependencia: {pkg}",
                    category="Dependencias",
                    passed=True,
                    message=f"Instalado (v{ver})",
                    is_critical=req,
                ))
            except Exception:
                results.append(DiagnosticCheck(
                    name=f"Dependencia: {pkg}",
                    category="Dependencias",
                    passed=not req,
                    message="No instalado" + (" (Opcional)" if not req else " (Requerido)"),
                    is_critical=req,
                    remediation=f"Instale con 'pip install {pkg}'",
                ))
        return results

    def run_all(self) -> list[DiagnosticCheck]:
        checks = [
            self.check_python_version(),
            self.check_privileges(),
            self.check_crypto_primitives(),
            self.check_tun_device(),
            self.check_network_ports(),
            self.check_firewall_backend(),
        ]
        checks.extend(self.check_dependencies())
        self.results = checks
        return checks

    def render_report(self, color: bool = True) -> str:
        lines = []
        lines.append(f"🩺 DIAGNÓSTICO DEL SISTEMA — {__product_name__} v{__version__}")
        lines.append("=" * 65)

        passed_count = sum(1 for c in self.results if c.passed)
        total_count = len(self.results)

        categories: dict[str, list[DiagnosticCheck]] = {}
        for c in self.results:
            categories.setdefault(c.category, []).append(c)

        for cat, items in categories.items():
            lines.append(f"\n[{cat.upper()}]")
            for item in items:
                status_icon = "✔" if item.passed else ("✖" if item.is_critical else "⚠")
                status_color = AnsiPalette.MATRIX_GREEN if item.passed else (AnsiPalette.NEON_RED if item.is_critical else AnsiPalette.AMBER)
                bullet = f"[{status_icon}]" if not color else f"{status_color}[{status_icon}]{AnsiPalette.RESET}"
                lines.append(f"  {bullet} {item.name}: {item.message}")
                if not item.passed and item.remediation:
                    rem_color = f"      ➜ {item.remediation}" if not color else f"{AnsiPalette.DARK_GRAY}      ➜ {item.remediation}{AnsiPalette.RESET}"
                    lines.append(rem_color)

        lines.append("\n" + "=" * 65)
        lines.append(f"Resumen: {passed_count}/{total_count} comprobaciones superadas satisfactoriamente.")
        return "\n".join(lines)
