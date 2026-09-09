#!/usr/bin/env python3
"""
AZZAZEL VPN — install_deps.py
=============================
Instalador inteligente y auditor dinámico de dependencias para AZZAZEL VPN.

Capacidades principales:
1. Análisis de AST: Escanea todos los archivos .py del proyecto para detectar
   librerías importadas en caliente (incluso si no están en requirements.txt).
2. Inspección de Requirements: Parsea requirements.txt y pyproject.toml.
3. Mapeo Canónico: Resuelve nombres de importación a paquetes PyPI (ej. yaml -> PyYAML, PIL -> Pillow).
4. Verificación de Entorno: Detecta versiones instaladas vs requeridas en tiempo real.
5. Instalación Automatizada: Descarga e instala dependencias faltantes vía pip de forma segura.
6. Soporte Multiplataforma Real: Activa Virtual Terminal Processing en Windows cmd.exe / PowerShell.
7. Alineación Perfecta de Tablas: Calcula anchos de columnas basados en longitud visual real (sin artefactos ANSI).

Uso:
    python install_deps.py             # Escaneo interactivo e instalación de faltantes
    python install_deps.py --check     # Solo auditoría (no modifica el sistema)
    python install_deps.py --dev       # Incluye herramientas de auditoría, tests y linters
    python install_deps.py --upgrade   # Actualiza dependencias existentes
    python install_deps.py -y          # Modo no interactivo (CI / despliegue)
"""

from __future__ import annotations

import argparse
import ast
import enum
import importlib
import importlib.metadata
import importlib.util
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

# ---------------------------------------------------------------------------
# Inicialización de Consola Windows (Virtual Terminal Processing)
# ---------------------------------------------------------------------------
def setup_windows_vt_mode() -> bool:
    """Habilita el modo Virtual Terminal Processing en Windows cmd.exe / PowerShell."""
    if os.name != "nt":
        return True

    # 1. Intentar activar mediante colorama si está disponible
    try:
        import colorama
        if hasattr(colorama, "just_fix_windows_console"):
            colorama.just_fix_windows_console()
            return True
        elif hasattr(colorama, "init"):
            colorama.init(autoreset=False)
            return True
    except Exception:
        pass

    # 2. Intentar activar directamente con la API nativa de Windows (kernel32.dll)
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h_stdout = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if h_stdout and h_stdout != -1:
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h_stdout, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(h_stdout, mode.value | 0x0004)
        
        h_stderr = kernel32.GetStdHandle(-12)  # STD_ERROR_HANDLE
        if h_stderr and h_stderr != -1:
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h_stderr, ctypes.byref(mode)):
                kernel32.SetConsoleMode(h_stderr, mode.value | 0x0004)
        return True
    except Exception:
        return False


def stdout_supports_color() -> bool:
    """Determina si la salida estándar admite secuencias de escape ANSI."""
    if os.environ.get("AZZAZEL_FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return setup_windows_vt_mode()
    return True


# ---------------------------------------------------------------------------
# Paleta de Colores ANSI Universal (16 Colores de Alta Compatibilidad)
# ---------------------------------------------------------------------------
class Color:
    """Códigos ANSI universales compatibles con Windows 10/11, PowerShell, cmd y Linux."""
    MATRIX_GREEN = "\033[92m"   # Verde brillante
    NEON_CYAN    = "\033[96m"   # Cyan brillante
    NEON_MAGENTA = "\033[95m"   # Magenta brillante
    NEON_RED     = "\033[91m"   # Rojo brillante
    AMBER        = "\033[93m"   # Amarillo / Ámbar
    DARK_GRAY    = "\033[90m"   # Gris oscuro / Bordes
    WHITE        = "\033[97m"   # Blanco brillante
    BOLD         = "\033[1m"
    DIM          = "\033[2m"
    RESET        = "\033[0m"


class PlainColor:
    """Paleta vacía para cuando el color esté desactivado."""
    MATRIX_GREEN = ""
    NEON_CYAN    = ""
    NEON_MAGENTA = ""
    NEON_RED     = ""
    AMBER        = ""
    DARK_GRAY    = ""
    WHITE        = ""
    BOLD         = ""
    DIM          = ""
    RESET        = ""


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

def visible_len(text: str) -> int:
    """Calcula la longitud de caracteres visibles ignorando códigos de escape ANSI."""
    return len(_ANSI_RE.sub("", text))


def pad_visible(text: str, width: int, align: str = "left") -> str:
    """Alinea el texto respetando el ancho visual real de la consola."""
    vlen = visible_len(text)
    spaces = max(0, width - vlen)
    if align == "right":
        return (" " * spaces) + text
    return text + (" " * spaces)


# ---------------------------------------------------------------------------
# Mapeo de Nombres de Módulos (Import) -> Paquetes PyPI
# ---------------------------------------------------------------------------
MODULE_TO_PYPI: dict[str, str] = {
    "yaml": "PyYAML",
    "PIL": "Pillow",
    "cryptography": "cryptography",
    "webview": "pywebview",
    "psutil": "psutil",
    "paramiko": "paramiko",
    "colorama": "colorama",
    "hypothesis": "hypothesis",
    "pytest": "pytest",
    "pytest_cov": "pytest-cov",
    "ruff": "ruff",
    "mypy": "mypy",
    "bandit": "bandit",
    "scapy": "scapy",
    "qrcode": "qrcode",
    "pyzbar": "pyzbar",
    "wakeonlan": "wakeonlan",
    "zeroconf": "zeroconf",
    "aiohttp": "aiohttp",
    "websockets": "websockets",
    "dns": "dnspython",
    "nmap": "python-nmap",
    "netifaces": "netifaces",
    "anyio": "anyio",
}

# Paquetes y módulos propios de AZZAZEL (no deben buscarse en PyPI)
PROJECT_LOCAL_PACKAGES = {
    "azzazel",
    "install_deps",
    "run_tests",
    "core",
    "protocol",
    "vpn",
    "proxy",
    "bridge",
    "firewall",
    "network",
    "tunnel",
    "monitoring",
    "security",
    "ui",
    "remote",
    "plugins",
    "tests",
    "scripts",
}

# Dependencias de auditoría, desarrollo y linters recomendadas
DEV_AUDIT_PACKAGES: dict[str, str] = {
    "pytest": "pytest>=8.0.0",
    "pytest-cov": "pytest-cov>=5.0.0",
    "hypothesis": "hypothesis>=6.100.0",
    "ruff": "ruff>=0.4.0",
    "mypy": "mypy>=1.10.0",
    "bandit": "bandit>=1.7.8",
}


class DependencyCategory(enum.Enum):
    CORE = "Core / Cripto"
    GUI = "Interfaz Gráfica"
    NETWORK = "Red / Túneles"
    DEV = "Desarrollo / Tests"
    AUDIT = "Auditoría / Calidad"


class DependencyStatus(enum.Enum):
    INSTALLED = "INSTALLED"
    MISSING = "MISSING"
    OUTDATED = "OUTDATED"


@dataclass
class DependencyItem:
    pypi_name: str
    import_name: str
    required_spec: str = ""
    installed_version: Optional[str] = None
    status: DependencyStatus = DependencyStatus.MISSING
    category: DependencyCategory = DependencyCategory.CORE
    files_referencing: list[str] = field(default_factory=list)
    declared_in_requirements: bool = False
    is_dev: bool = False

    @property
    def install_target(self) -> str:
        """Cadena para pasar a pip install."""
        if self.required_spec:
            return f"{self.pypi_name}{self.required_spec}"
        return self.pypi_name


# ---------------------------------------------------------------------------
# Analizador AST y Escáner de Proyecto
# ---------------------------------------------------------------------------
class DependencyAnalyzer:
    """Inspecciona el código fuente de AZZAZEL y analiza requisitos."""

    def __init__(self, project_root: Path) -> None:
        self.root = project_root
        self.requirements_path = project_root / "requirements.txt"
        self.pyproject_path = project_root / "pyproject.toml"

        # Obtener módulos de la librería estándar de Python
        self.stdlib_modules = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else {
            "os", "sys", "time", "json", "hashlib", "hmac", "asyncio", "socket",
            "struct", "threading", "urllib", "dataclasses", "typing", "pathlib",
            "secrets", "shlex", "subprocess", "logging", "ctypes", "re", "math",
            "collections", "enum", "argparse", "getpass", "importlib", "signal",
            "unicodedata", "shutil", "tempfile", "queue", "io", "base64", "ipaddress"
        }

    def scan_codebase_imports(self) -> dict[str, list[str]]:
        """Recorre todos los ficheros .py extrayendo importaciones externas."""
        imported_modules: dict[str, list[str]] = {}
        ignore_dirs = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", "build", "dist"}

        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                file_path = Path(dirpath) / fname
                rel_path = file_path.relative_to(self.root).as_posix()

                try:
                    tree = ast.parse(file_path.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    continue

                for node in ast.walk(tree):
                    mod_name = None
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            mod_name = alias.name.split(".")[0]
                            self._record_import(mod_name, rel_path, imported_modules)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        mod_name = node.module.split(".")[0]
                        self._record_import(mod_name, rel_path, imported_modules)

        return imported_modules

    def _record_import(self, mod_name: str, rel_path: str, storage: dict[str, list[str]]) -> None:
        if not mod_name or mod_name in self.stdlib_modules or mod_name in PROJECT_LOCAL_PACKAGES:
            return
        if mod_name.startswith("_"):
            return
        storage.setdefault(mod_name, []).append(rel_path)

    def parse_requirements_file(self) -> dict[str, tuple[str, str]]:
        """Lee requirements.txt y extrae librerías declaradas y versiones."""
        requirements: dict[str, tuple[str, str]] = {}
        if not self.requirements_path.exists():
            return requirements

        content = self.requirements_path.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            sline = line.strip()
            if not sline or sline.startswith("#"):
                continue

            # Eliminar comentarios inline
            if "#" in sline:
                sline = sline.split("#", 1)[0].strip()

            # Separar marcadores de entorno (ej. ; sys_platform == 'win32')
            if ";" in sline:
                sline, marker = sline.split(";", 1)
                sline = sline.strip()
                marker = marker.strip()
                if "win32" in marker and sys.platform != "win32":
                    continue

            # Extraer nombre y specifier
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(.*)$", sline)
            if match:
                pkg_name = match.group(1)
                spec = match.group(2).strip()
                requirements[pkg_name.lower()] = (pkg_name, spec)

        return requirements

    def inspect_dependencies(self, include_dev: bool = False) -> list[DependencyItem]:
        """Realiza el cruce completo entre AST, requirements.txt y el entorno Python."""
        code_imports = self.scan_codebase_imports()
        req_declared = self.parse_requirements_file()

        items: dict[str, DependencyItem] = {}

        # 1. Procesar todo lo encontrado en el código fuente (AST)
        for import_name, files in code_imports.items():
            pypi_name = MODULE_TO_PYPI.get(import_name, import_name)
            pypi_key = pypi_name.lower()

            req_tuple = req_declared.get(pypi_key)
            spec = req_tuple[1] if req_tuple else ""
            declared = (req_tuple is not None)

            cat = self._classify_category(pypi_name, files)

            item = DependencyItem(
                pypi_name=pypi_name,
                import_name=import_name,
                required_spec=spec,
                category=cat,
                files_referencing=files,
                declared_in_requirements=declared,
                is_dev=(cat in (DependencyCategory.DEV, DependencyCategory.AUDIT)),
            )
            items[pypi_key] = item

        # 2. Procesar lo que está en requirements.txt pero no detectado por AST
        for pypi_key, (raw_name, spec) in req_declared.items():
            if pypi_key not in items:
                cat = self._classify_category(raw_name, [])
                items[pypi_key] = DependencyItem(
                    pypi_name=raw_name,
                    import_name=raw_name,
                    required_spec=spec,
                    category=cat,
                    declared_in_requirements=True,
                    is_dev=(cat in (DependencyCategory.DEV, DependencyCategory.AUDIT)),
                )

        # 3. Añadir dependencias de Dev/Auditoría si se solicita
        if include_dev:
            for dev_pypi, dev_spec in DEV_AUDIT_PACKAGES.items():
                dev_key = dev_pypi.lower()
                spec_clean = re.sub(r"^[A-Za-z0-9_\-\.]+", "", dev_spec)
                if dev_key in items:
                    items[dev_key].is_dev = True
                    if not items[dev_key].required_spec:
                        items[dev_key].required_spec = spec_clean
                else:
                    items[dev_key] = DependencyItem(
                        pypi_name=dev_pypi,
                        import_name=dev_pypi.replace("-", "_"),
                        required_spec=spec_clean,
                        category=DependencyCategory.AUDIT if dev_pypi in ("ruff", "mypy", "bandit") else DependencyCategory.DEV,
                        declared_in_requirements=False,
                        is_dev=True,
                    )

        # 4. Verificar qué está instalado en el entorno
        for item in items.values():
            installed_ver = self._get_installed_version(item.pypi_name, item.import_name)
            item.installed_version = installed_ver

            if installed_ver is None:
                item.status = DependencyStatus.MISSING
            else:
                item.status = DependencyStatus.INSTALLED

        # Ordenar por categoría y nombre
        return sorted(items.values(), key=lambda x: (x.category.value, x.pypi_name.lower()))

    def _classify_category(self, pypi_name: str, files: list[str]) -> DependencyCategory:
        low = pypi_name.lower()
        if low in ("cryptography", "pyyaml", "colorama"):
            return DependencyCategory.CORE
        if low in ("pywebview", "pillow"):
            return DependencyCategory.GUI
        if low in ("psutil", "paramiko", "scapy", "aiohttp", "websockets", "dnspython", "python-nmap", "netifaces"):
            return DependencyCategory.NETWORK
        if low in ("pytest", "pytest-cov", "pytest-asyncio", "hypothesis", "anyio"):
            return DependencyCategory.DEV
        if low in ("ruff", "mypy", "bandit"):
            return DependencyCategory.AUDIT

        for f in files:
            if "gui" in f:
                return DependencyCategory.GUI
            if "test" in f:
                return DependencyCategory.DEV
            if "network" in f or "vpn" in f or "tunnel" in f or "proxy" in f or "bridge" in f:
                return DependencyCategory.NETWORK

        return DependencyCategory.CORE

    def _get_installed_version(self, pypi_name: str, import_name: str) -> Optional[str]:
        # 1. Probar por metadata de distribución
        try:
            return importlib.metadata.version(pypi_name)
        except Exception:
            pass

        # 2. Probar por import_name
        try:
            return importlib.metadata.version(import_name)
        except Exception:
            pass

        # 3. Probar find_spec
        try:
            spec = importlib.util.find_spec(import_name)
            if spec is not None:
                try:
                    mod = importlib.import_module(import_name)
                    return getattr(mod, "__version__", "instalado")
                except Exception:
                    return "instalado"
        except Exception:
            pass

        return None


# ---------------------------------------------------------------------------
# Gestor de Instalación de Pip
# ---------------------------------------------------------------------------
class PipInstaller:
    """Ejecuta instalaciones pip controladas."""

    @staticmethod
    def install(packages: list[str], upgrade: bool = False) -> tuple[bool, str]:
        if not packages:
            return True, "Nada que instalar."

        cmd = [sys.executable, "-m", "pip", "install"]
        if upgrade:
            cmd.append("--upgrade")
        cmd.extend(packages)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            success = (proc.returncode == 0)
            output = proc.stdout if success else (proc.stderr or proc.stdout)
            return success, output.strip()
        except Exception as exc:
            return False, f"Error ejecutando pip: {exc}"


# ---------------------------------------------------------------------------
# Renderizado de Interfaz Visual
# ---------------------------------------------------------------------------
class VisualPresenter:
    """Renderiza el informe visual y tablas en consola con alineación exacta."""

    @staticmethod
    def print_header(use_color: bool = True) -> None:
        c = Color if use_color else PlainColor
        banner = f"""{c.MATRIX_GREEN}
  █████╗ ███████╗███████╗ █████╗ ███████╗███████╗██╗     
 ██╔══██╗╚══███╔╝╚══███╔╝██╔══██╗╚══███╔╝██╔════╝██║     
 ███████║  ███╔╝   ███╔╝ ███████║  ███╔╝ █████╗  ██║     
 ██╔══██║ ███╔╝   ███╔╝  ██╔══██║ ███╔╝  ██╔══╝  ██║     
 ██║  ██║███████╗███████╗██║  ██║███████╗███████╗███████╗
 ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝{c.RESET}
{c.NEON_CYAN} [⚡] INSTALADOR INTELIGENTE DE DEPENDENCIAS Y AUDITOR DE CÓDIGO{c.RESET}
{c.DARK_GRAY} ----------------------------------------------------------------------{c.RESET}
"""
        print(banner)

    @staticmethod
    def render_table(items: list[DependencyItem], use_color: bool = True) -> None:
        c = Color if use_color else PlainColor

        w_pypi = 20
        w_cat = 22
        w_req = 16
        w_inst = 16
        w_stat = 12

        # Cabecera de tabla
        h_pypi = pad_visible("PAQUETE PYPI", w_pypi)
        h_cat = pad_visible("CATEGORÍA", w_cat)
        h_req = pad_visible("REQUERIDO", w_req)
        h_inst = pad_visible("INSTALADO", w_inst)
        h_stat = pad_visible("ESTADO", w_stat)

        print(f" {c.NEON_CYAN}{h_pypi} {h_cat} {h_req} {h_inst} {h_stat}{c.RESET}")
        print(f" {c.DARK_GRAY}{'─'*w_pypi} {'─'*w_cat} {'─'*w_req} {'─'*w_inst} {'─'*w_stat}{c.RESET}")

        for it in items:
            cat_label = it.category.value
            req_label = it.required_spec if it.required_spec else "(cualquiera)"
            inst_label = f"v{it.installed_version}" if it.installed_version else "No instalado"

            if it.status == DependencyStatus.INSTALLED:
                st_badge = f"{c.MATRIX_GREEN}✔ INSTALADO{c.RESET}"
                inst_col = f"{c.MATRIX_GREEN}{pad_visible(inst_label, w_inst)}{c.RESET}"
            elif it.status == DependencyStatus.MISSING:
                st_badge = f"{c.NEON_RED}✖ FALTA{c.RESET}"
                inst_col = f"{c.NEON_RED}{pad_visible(inst_label, w_inst)}{c.RESET}"
            else:
                st_badge = f"{c.AMBER}⚠ OBSOLETO{c.RESET}"
                inst_col = f"{c.AMBER}{pad_visible(inst_label, w_inst)}{c.RESET}"

            if not it.declared_in_requirements:
                pkg_raw = f"{it.pypi_name}*"
                pkg_colored = f"{c.WHITE}{it.pypi_name}{c.RESET}{c.AMBER}*{c.RESET}"
                pkg_col = pad_visible(pkg_colored, w_pypi)
            else:
                pkg_col = f"{c.WHITE}{pad_visible(it.pypi_name, w_pypi)}{c.RESET}"

            cat_col = f"{c.DARK_GRAY}{pad_visible(cat_label, w_cat)}{c.RESET}"
            req_col = pad_visible(req_label, w_req)

            print(f" {pkg_col} {cat_col} {req_col} {inst_col} {st_badge}")

        print(f" {c.DARK_GRAY}{'─'*w_pypi} {'─'*w_cat} {'─'*w_req} {'─'*w_inst} {'─'*w_stat}{c.RESET}")
        if any(not it.declared_in_requirements for it in items):
            print(f" {c.AMBER}* Paquete detectado dinámicamente en el código pero no listado en requirements.txt{c.RESET}\n")


# ---------------------------------------------------------------------------
# Sincronizador de requirements.txt
# ---------------------------------------------------------------------------
def sync_requirements_file(req_path: Path, items: list[DependencyItem]) -> bool:
    """Añade librerías detectadas por AST que falten en requirements.txt."""
    if not req_path.exists():
        return False

    content = req_path.read_text(encoding="utf-8")
    added_lines = []

    for it in items:
        if not it.declared_in_requirements and not it.is_dev:
            target = it.install_target
            if it.pypi_name.lower() not in content.lower():
                added_lines.append(f"{target:<24} # Detectado automáticamente por AST en el proyecto")

    if added_lines:
        new_content = content.rstrip() + "\n\n# --- Detectadas dinámicamente por install_deps.py ---\n" + "\n".join(added_lines) + "\n"
        req_path.write_text(new_content, encoding="utf-8")
        return True
    return False


# ---------------------------------------------------------------------------
# Función Principal
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="install_deps.py",
        description="Instalador inteligente de dependencias con análisis estático de código para AZZAZEL VPN.",
    )
    parser.add_argument("--check", "--dry-run", action="store_true",
                        help="Solo analiza y muestra el reporte sin realizar instalaciones")
    parser.add_argument("--dev", action="store_true",
                        help="Incluye dependencias completas de desarrollo, testing y linters (pytest-cov, ruff, mypy, bandit)")
    parser.add_argument("--upgrade", "-U", action="store_true",
                        help="Fuerza la actualización de dependencias ya instaladas a su última versión")
    parser.add_argument("--sync-reqs", action="store_true",
                        help="Sincroniza requirements.txt agregando librerías no declaradas halladas en código")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Instala automáticamente sin solicitar confirmación interactiva")
    parser.add_argument("--no-color", action="store_true",
                        help="Desactiva los códigos de color ANSI")

    args = parser.parse_args(argv)
    use_color = stdout_supports_color() and not args.no_color
    c = Color if use_color else PlainColor

    project_root = Path(__file__).resolve().parent
    analyzer = DependencyAnalyzer(project_root)

    VisualPresenter.print_header(use_color=use_color)
    print(f"🔍 Analizando código fuente y requirements en: {project_root} ...\n")

    items = analyzer.inspect_dependencies(include_dev=args.dev)
    VisualPresenter.render_table(items, use_color=use_color)

    missing = [it for it in items if it.status == DependencyStatus.MISSING]
    installed_count = len(items) - len(missing)

    print(f"📊 {c.NEON_CYAN}Resumen de Análisis:{c.RESET}")
    print(f"   • Total de dependencias requeridas: {len(items)}")
    print(f"   • Instaladas y verificadas:         {c.MATRIX_GREEN}{installed_count}{c.RESET}")
    print(f"   • Pendientes de instalación:        {c.NEON_RED if missing else c.MATRIX_GREEN}{len(missing)}{c.RESET}\n")

    if args.sync_reqs:
        updated = sync_requirements_file(analyzer.requirements_path, items)
        if updated:
            print(f"📝 {c.MATRIX_GREEN}requirements.txt actualizado con las dependencias descubiertas en código.{c.RESET}\n")

    if not missing and not args.upgrade:
        print(f"✨ {c.MATRIX_GREEN}¡Todo listo! Todas las dependencias del proyecto están instaladas y operativas.{c.RESET}")
        return 0

    if args.check:
        if missing:
            print(f"⚠️ {c.AMBER}Modo --check: Se detectaron dependencias faltantes.{c.RESET}")
            return 1
        return 0

    packages_to_install = [it.install_target for it in missing]
    if args.upgrade:
        packages_to_install = [it.install_target for it in items]

    if not args.yes:
        action_name = "actualizar" if args.upgrade else "instalar"
        print(f"📦 Paquetes a {action_name}: {', '.join(packages_to_install)}")
        try:
            ans = input(f"\n¿Desea proceder con la instalación vía pip? [S/n]: ").strip().lower()
            if ans and ans not in ("s", "si", "y", "yes"):
                print(f"{c.AMBER}Instalación cancelada por el usuario.{c.RESET}")
                return 0
        except (KeyboardInterrupt, EOFError):
            print(f"\n{c.AMBER}Operación cancelada.{c.RESET}")
            return 130

    print(f"\n🚀 {c.NEON_CYAN}Invocando pip para instalar dependencias...{c.RESET}")
    ok, pip_output = PipInstaller.install(packages_to_install, upgrade=args.upgrade)

    if ok:
        print(f"✅ {c.MATRIX_GREEN}Instalación completada con éxito.{c.RESET}")
        print("🔄 Verificando integridad del entorno...")
        post_items = analyzer.inspect_dependencies(include_dev=args.dev)
        still_missing = [it for it in post_items if it.status == DependencyStatus.MISSING]
        if not still_missing:
            print(f"🎉 {c.MATRIX_GREEN}Todas las librerías han sido validadas e integradas satisfactoriamente.{c.RESET}")
            return 0
        else:
            print(f"⚠️ {c.AMBER}Algunas librerías no pudieron verificarse tras la instalación: {[it.pypi_name for it in still_missing]}{c.RESET}")
            return 1
    else:
        print(f"❌ {c.NEON_RED}Fallo durante la ejecución de pip:{c.RESET}")
        print(pip_output)
        return 1


if __name__ == "__main__":
    sys.exit(main())
