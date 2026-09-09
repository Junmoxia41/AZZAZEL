#!/usr/bin/env python3
"""
AZZAZEL VPN — azzazel.py
=========================

Entry point principal de la suite. Orquesta la secuencia de arranque:

    1. Splash Matrix (si hay TTY y animaciones activas)
    2. Banner AZZAZEL con gradiente neón
    3. Detección de plataforma (SO, Python, privilegios)
    4. Verificación de dependencias (obligatorias vs opcionales)
    5. Carga de configuración (config.yaml) + motor criptográfico
    6. Configuración del logging según el YAML
    7. Despacho según flags: menú interactivo / setup / daemon / status

Modos de arranque::

    python azzazel.py                      # splash + menú interactivo (CLI)
    python azzazel.py --mode server        # fuerza modo servidor y abre menú
    python azzazel.py --mode client        # fuerza modo cliente
    python azzazel.py --mode bridge        # fuerza modo puente PC↔Móvil
    python azzazel.py --daemon --mode server          # daemon = servidor VPN real
    python azzazel.py --daemon --mode client --peer 10.0.0.1:51820
                                                      # daemon = túnel cliente a un peer
    python azzazel.py --gui                # GUI (Sprint 6) — cae a CLI si falta
    python azzazel.py --cli                # fuerza CLI (incluso si ui.mode=gui)
    python azzazel.py --daemon             # servicio headless (sin TTY)
    python azzazel.py --setup              # wizard de configuración inicial
    python azzazel.py --status             # informe del sistema y sale
    python azzazel.py --no-anim            # sin animaciones (CI, tmux...)

Compatible con Windows y Linux (Python 3.10+). Códigos de salida:
0 = OK · 1 = error fatal de arranque · 130 = cancelado por el usuario.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import importlib
import importlib.metadata
import logging
import os
import platform
import signal
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

# Azzazel vive en la raíz del proyecto: sus paquetes son importables tal cual.
from core.version import __version__, __product_name__
from core.logger import (
    AnsiPalette,
    get_logger,
    install_global_exception_hook,
    setup_logger,
)
from core.crypto_engine import CryptoEngine, generate_pin, random_token
from core.config_manager import (
    ConfigManager,
    ConfigValidationError,
    SECRET_FIELDS,
)
from ui.cli import ascii_art as art

APP_NAME = __product_name__

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"

_log = get_logger("main")

# ---------------------------------------------------------------------------
# Helpers de color/ancho (consola real vs pipes)
# ---------------------------------------------------------------------------
def _stdout_supports_color() -> bool:
    if os.environ.get("AZZAZEL_FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


COLOR_ENABLED = _stdout_supports_color()


def _c(text: str, ansi: str) -> str:
    """Colorea ``text`` solo si la consola admite ANSI."""
    return f"{ansi}{text}{AnsiPalette.RESET}" if COLOR_ENABLED else text


def _cell_len(text: str) -> int:
    """Ancho en celdas de terminal (Emojis/CJK cuentan 2, ANSI no cuenta)."""
    plain = art.strip_ansi(text)
    return sum(
        2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        for ch in plain
    )


def _cell_pad(text: str, width: int) -> str:
    """Rellena con espacios a la derecha hasta ``width`` celdas."""
    return text + " " * max(0, width - _cell_len(text))


# ---------------------------------------------------------------------------
# Plataforma y dependencias
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PlatformInfo:
    """Información del sistema anfitrión detectada al arrancar."""

    system: str            # "Windows" | "Linux" | "Darwin" | ...
    release: str
    machine: str
    python: str
    is_admin: bool

    @property
    def is_windows(self) -> bool:
        return self.system == "Windows"

    @property
    def is_posix(self) -> bool:
        return os.name == "posix"


def detect_platform() -> PlatformInfo:
    """Detecta SO, arquitectura, versión de Python y privilegios.

    Privilegios: ``root`` (uid 0) en POSIX; ``IsUserAnAdmin`` en Windows
    (ctypes, sin dependencias externas).
    """
    is_admin = False
    if os.name == "posix":
        is_admin = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    elif os.name == "nt":  # pragma: no cover (Windows)
        try:
            import ctypes

            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False
    info = PlatformInfo(
        system=platform.system() or "Desconocido",
        release=platform.release(),
        machine=platform.machine(),
        python=platform.python_version(),
        is_admin=is_admin,
    )
    _log.info("Plataforma: %s %s (%s) · Python %s · admin=%s",
              info.system, info.release, info.machine, info.python,
              info.is_admin)
    return info


@dataclass(frozen=True)
class Dependency:
    """Una dependencia del proyecto y su estado de instalación."""

    module: str            # nombre importable
    package: str           # nombre en pip
    required: bool         # obligatoria para el núcleo actual
    purpose: str           # para qué se usa
    sprint: str            # sprint donde entra en juego


DEPENDENCIES: tuple[Dependency, ...] = (
    Dependency("yaml", "pyyaml", True, "config.yaml", "S1"),
    Dependency("cryptography", "cryptography", True, "AES-256-GCM", "S1"),
    Dependency("colorama", "colorama", False, "ANSI consola Windows", "S1"),
    Dependency("rich", "rich", False, "tablas y formato CLI", "S1"),
    Dependency("qrcode", "qrcode", False, "QR del bridge", "S4"),
    Dependency("psutil", "psutil", False, "monitoreo del sistema", "S5"),
    Dependency("dns", "dnspython", False, "herramientas DNS", "S5"),
    Dependency("scapy", "scapy", False, "sniffer / paquetes", "S5"),
    Dependency("paramiko", "paramiko", False, "túneles SSH", "S7"),
    Dependency("customtkinter", "customtkinter", False, "GUI (Sprint 6)", "S6"),
)


@dataclass(frozen=True)
class DependencyStatus:
    """Estado resuelto de una dependencia."""

    dep: Dependency
    installed: bool
    version: str = ""


def check_dependencies() -> list[DependencyStatus]:
    """Resuelve qué dependencias están instaladas (sin lanzar errores)."""
    statuses: list[DependencyStatus] = []
    for dep in DEPENDENCIES:
        try:
            importlib.import_module(dep.module)
            installed = True
            version = importlib.metadata.version(dep.package)
        except Exception:
            installed, version = False, ""
        statuses.append(DependencyStatus(dep=dep, installed=installed,
                                         version=version))
    return statuses


def missing_required(statuses: Sequence[DependencyStatus]) -> list[Dependency]:
    """Devuelve las dependencias OBLIGATORIAS ausentes."""
    return [s.dep for s in statuses if s.dep.required and not s.installed]


# ---------------------------------------------------------------------------
# Contexto de aplicación
# ---------------------------------------------------------------------------
@dataclass
class AppContext:
    """Estado arrancado de la aplicación (config, crypto, flags)."""

    args: argparse.Namespace
    platform: PlatformInfo
    project_root: Path
    crypto: CryptoEngine
    config_manager: ConfigManager
    deps: list[DependencyStatus] = field(default_factory=list)

    @property
    def config(self):
        """Acceso directo a la configuración activa."""
        return self.config_manager.config


def bootstrap(args: argparse.Namespace) -> AppContext:
    """Ejecuta la fase de arranque: plataforma → crypto → config → logging.

    La configuración se carga con reparación tolerante (los avisos
    quedan en el log). Tras el bootstrap el logging ya obedece al
    ``config.yaml`` del usuario.
    """
    plat = detect_platform()
    deps = check_dependencies()

    missing = missing_required(deps)
    if missing:
        names = ", ".join(d.package for d in missing)
        print(_c(f"[✗] Faltan dependencias OBLIGATORIAS: {names}",
                 AnsiPalette.NEON_RED))
        print(f"    Instálalas con: pip install {names}")
        _log.error("Dependencias obligatorias ausentes: %s", names)
        raise SystemExit(1)

    crypto = CryptoEngine.for_machine(PROJECT_ROOT / "data")
    cm = ConfigManager(args.config, crypto=crypto)
    config = cm.load_or_create()
    cm.ensure_directories()

    log_cfg = config.azzazel.logging.to_logger_config()
    log_file = Path(log_cfg.log_file)
    if not log_file.is_absolute():
        log_cfg.log_file = str(PROJECT_ROOT / log_file)
    setup_logger(log_cfg, force=True)
    install_global_exception_hook()

    for warning in cm.last_warnings:
        _log.warning("Config: %s", warning)
    _log.success("Bootstrap completado (config: %s).", cm.path)
    return AppContext(
        args=args, platform=plat, project_root=PROJECT_ROOT,
        crypto=crypto, config_manager=cm, deps=deps,
    )


# ---------------------------------------------------------------------------
# Splash de arranque
# ---------------------------------------------------------------------------
def run_splash(enabled: bool) -> None:
    """Secuencia de arranque: lluvia Matrix + banner + mensajes de boot."""
    if not enabled:
        art.print_banner()
        return
    art.clear_screen()
    art.matrix_rain(duration=2.2)
    art.print_banner()
    theme = art.get_theme()
    boot_lines = [
        "[*] Inicializando núcleo AZZAZEL v1.0...",
        "[*] Cargando subsistemas criptográficos [AES-256-GCM]...",
        "[*] Verificando integridad de la configuración...",
    ]
    art.type_lines(boot_lines, cps=220, line_pause=0.08,
                   color=theme.secondary if COLOR_ENABLED else None)


# ---------------------------------------------------------------------------
# Menú principal (diseño exacto de la especificación)
# ---------------------------------------------------------------------------
_MENU_W = 58  # ancho interior del marco

_MODULE_ROADMAP: dict[str, tuple[str, str, str]] = {
    "1": ("VPN Manager",       "vpn/tunnel_manager.py",   "Sprint 3 ✔ LISTO (--daemon --mode server|client)"),
    "2": ("Proxy Suite",       "proxy/proxy_chain.py",    "Sprint 2 ✔ LISTO"),
    "3": ("Tunnel Manager",    "tunnel/ssh_tunnel.py",    "Sprint 7 ✔ LISTO (menú 3: SSH -L/-R/-D)"),
    "4": ("Network Tools",     "network/scanner.py",      "Sprint 5 ✔ LISTO"),
    "5": ("Firewall",          "firewall/fw_manager.py",  "Sprint 7 ✔ LISTO (menú 5: plan dry-run)"),
    "6": ("Bridge PC↔Mobile",  "bridge/mobile_bridge.py", "Sprint 4 ✔ LISTO (--daemon --mode bridge)"),
    "7": ("Monitoring",        "monitoring/dashboard.py", "Sprint 7 ✔ LISTO (menú 7: WAR ROOM)"),
    "8": ("Settings",          "core/config_manager.py",  "Sprint 1 (base lista)"),
    "9": ("Remote Access",     "remote/remote_shell.py",  "Sprint 7 ✔ LISTO (menú 9: ssh exec)"),
}


@dataclass(frozen=True)
class MenuStatus:
    """Datos que alimenta el footer del menú (tiempo real en el futuro)."""

    online: bool
    clients: int
    upload_rate: str
    bridge: str          # "ACTIVE" | "OFF"
    proxy: str           # "CHAINED" | "LOCAL" | "OFF"
    tunnel: str          # "UP" | "DOWN"


def gather_menu_status(ctx: AppContext) -> MenuStatus:
    """Construye el estado del footer a partir de la configuración real."""
    cfg = ctx.config
    upstream = cfg.proxy.upstream.enabled
    return MenuStatus(
        online=True,
        clients=0,  # los clientes reales llegarán con vpn/tunnel_manager
        upload_rate="0.0 MB/s",
        bridge="ACTIVE" if cfg.bridge.enabled else "OFF",
        proxy="CHAINED" if upstream else ("LOCAL" if cfg.proxy.local.enabled
                                          else "OFF"),
        tunnel="UP" if cfg.vpn.enabled else "DOWN",
    )


def _dot(active: bool) -> str:
    """Indicador de estado: ● verde (activo) / ○ gris (inactivo)."""
    sym = "●" if active else "○"
    color = AnsiPalette.MATRIX_GREEN if active else AnsiPalette.DARK_GRAY
    return _c(sym, color)


def render_main_menu(status: MenuStatus) -> str:
    """Renderiza el menú principal con el diseño de la especificación.

    El ancho se calcula en CELDAS (los emojis cuentan doble), por lo
    que el marco queda rectangular en terminales reales.
    """
    theme = art.get_theme()
    border = theme.secondary if COLOR_ENABLED else ""
    rst = AnsiPalette.RESET if COLOR_ENABLED else ""

    def b(text_part: str = "") -> str:
        return f"{border}{text_part}{rst}"

    def key(n: str) -> str:
        return _c(f"[{n}]", theme.tertiary)

    def label(text: str) -> str:
        return _c(text, theme.primary)

    def row(content: str) -> str:
        return f"{b('║')}  {_cell_pad(content, _MENU_W - 2)}{b('║')}"

    top = b("╔" + "═" * _MENU_W + "╗")
    sep = b("╠" + "═" * _MENU_W + "╣")
    bot = b("╚" + "═" * _MENU_W + "╝")

    def centered(text: str) -> str:
        pad = _MENU_W - _cell_len(text)
        left = pad // 2
        return f"{b('║')}{' ' * left}{text}{' ' * (pad - left)}{b('║')}"

    lines = [
        top,
        centered(_c(APP_NAME + " v1.0", theme.primary)),
        centered(_c("Advanced Network Warfare Suite", theme.primary)),
        sep,
        row(""),
        row(f"{key('1')} 🔒 {label('VPN Manager')}          "
            f"{key('6')} 🌉 {label('Bridge PC↔Mobile')}"),
        row(f"{key('2')} 🔄 {label('Proxy Suite')}          "
            f"{key('7')} 📊 {label('Monitoring')}"),
        row(f"{key('3')} 🚇 {label('Tunnel Manager')}       "
            f"{key('8')} 🔧 {label('Settings')}"),
        row(f"{key('4')} 🌐 {label('Network Tools')}        "
            f"{key('9')} 📡 {label('Remote Access')}"),
        row(f"{key('5')} 🛡️  {label('Firewall')}             "
            f"{key('0')} ❌ {label('Exit')}"),
        row(""),
        sep,
        row(f"Status: {_dot(status.online)} "
            f"{_c('ONLINE' if status.online else 'OFFLINE', theme.primary)}"
            f" | Clients: {status.clients} | Upload: {status.upload_rate}"),
        row(f"Bridge: {_dot(status.bridge == 'ACTIVE')} {status.bridge}"
            f" | Proxy: {_dot(status.proxy != 'OFF')} {status.proxy}"
            f" | Tunnel: {_dot(status.tunnel == 'UP')} {status.tunnel}"),
        bot,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Informe de estado (comando `status` y flag --status)
# ---------------------------------------------------------------------------
def count_encrypted_tokens(config_path: Path) -> int:
    """Cuenta valores cifrados reales en el YAML (ignora comentarios).

    Un valor cifrado siempre sigue el patrón ``clave: ENC[...]:<token>``;
    las líneas de comentario (``#``) se excluyen para no contar la
    cabecera informativa del archivo.
    """
    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError:
        return 0
    return sum(
        1
        for line in raw.splitlines()
        if not line.lstrip().startswith("#") and "ENC[AES-256-GCM]:" in line
    )


def render_status_report(ctx: AppContext) -> str:
    """Informe técnico real del sistema (config, deps, seguridad, red)."""
    cfg = ctx.config
    plat = ctx.platform
    theme = art.get_theme()

    def ok(b: bool) -> str:
        return _c("OK" if b else "FALTA",
                  AnsiPalette.MATRIX_GREEN if b else AnsiPalette.NEON_RED)

    sections: list[tuple[str, list[str]]] = []

    admin_label = "root" if plat.is_posix else "Administrador"
    sections.append(("SISTEMA", [
        f"SO: {plat.system} {plat.release} ({plat.machine})",
        f"Python: {plat.python} · Privilegios {admin_label}: "
        f"{'SÍ' if plat.is_admin else 'no'}",
    ]))

    sections.append(("APLICACIÓN", [
        f"Versión: {__version__} · Modo: {cfg.azzazel.mode} · "
        f"Tema: {cfg.azzazel.ui.theme}",
        f"Config: {ctx.config_manager.path}",
        f"Avisos config última carga: {len(ctx.config_manager.last_warnings)}",
    ]))

    req = [s for s in ctx.deps if s.dep.required]
    opt = [s for s in ctx.deps if not s.dep.required]
    dep_lines = [f"[{ok(s.installed)}] {s.dep.package:<14} "
                 f"{s.version or '-':<8} requerida · {s.dep.purpose}"
                 for s in req]
    dep_lines += [
        f"[{_c('OK' if s.installed else 'pendiente', AnsiPalette.MATRIX_GREEN if s.installed else AnsiPalette.AMBER)}] "
        f"{s.dep.package:<14} {s.version or '-':<8} opcional ({s.dep.sprint}) · {s.dep.purpose}"
        for s in opt
    ]
    sections.append(("DEPENDENCIAS", dep_lines))

    key_file = ctx.project_root / "data" / ".azzazel.key"
    encrypted = count_encrypted_tokens(ctx.config_manager.path)
    secrets_set = sum(
        1 for path in SECRET_FIELDS if ctx.config_manager.get(path)
    )
    sections.append(("SEGURIDAD", [
        f"Clave de máquina: {'presente (0600)' if key_file.exists() else 'AUSENTE'}",
        f"Secretos definidos: {secrets_set} · tokens cifrados en disco: {encrypted}",
        f"Algoritmo: {cfg.azzazel.security.encryption_algorithm}",
    ]))

    sections.append(("RED (escuchas previstas)", [
        f"VPN {cfg.vpn.protocol}: {cfg.vpn.server.listen_address}:"
        f"{cfg.vpn.server.listen_port} ({'on' if cfg.vpn.enabled else 'off'})",
        f"Proxy local: http {cfg.proxy.local.http_port} · "
        f"socks5 {cfg.proxy.local.socks5_port}",
        f"Upstream: {(cfg.proxy.upstream.host or 'no configurado') + ':' + str(cfg.proxy.upstream.port) if cfg.proxy.upstream.enabled else 'desactivado'}",
        f"API REST: {cfg.api.host}:{cfg.api.port} ({'on' if cfg.api.enabled else 'off'})",
    ]))

    peer_env = os.environ.get("AZZAZEL_VPN_PEER", "") or "no definido"
    vpn_key_state = "presente (cifrada en disco)" \
        if cfg.vpn.keys.private_key else "AUSENTE — setup pendiente"
    sections.append(("MODO ACTIVO (runtime)", [
        f"Modo persistido: {cfg.azzazel.mode} "
        f"(se arranca con --daemon, --mode y --peer)",
        f"Clave VPN (PSK): {vpn_key_state}",
        f"Peer cliente VPN: {peer_env} "
        f"(--peer o AZZAZEL_VPN_PEER al lanzar en modo client)",
        f"Bridge PC↔móvil: {'ON' if cfg.bridge.enabled else 'OFF'} "
        f"(puerto por defecto 47671 si se activa)",
        f"Kill-switch cliente: {'armado' if cfg.vpn.client.kill_switch else 'desactivado'}",
    ]))

    out: list[str] = []
    for title, body in sections:
        out.append(art.box(body, title=title, style="single",
                           border_color=theme.secondary if COLOR_ENABLED else None,
                           pad_v=0))
        out.append("")
    return "\n".join(out).rstrip()


# ---------------------------------------------------------------------------
# Wizard de configuración inicial (--setup, versión ligera del wizard 1/5)
# ---------------------------------------------------------------------------
def _ask(prompt: str, default: str = "") -> str:
    """input() con valor por defecto visible."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"    > {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return value or default


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    """Pregunta [s/N] o [S/n]."""
    hint = "[S/n]" if default else "[s/N]"
    value = _ask(f"{prompt} {hint}").lower()
    if not value:
        return default
    return value.startswith(("s", "y"))


def _ask_port(prompt: str, default: int) -> int:
    """Puerto validado 1-65535 (con reintentos)."""
    for _ in range(3):
        value = _ask(prompt, str(default))
        try:
            port = int(value)
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass
        print(_c("    [!] Puerto inválido; debe ser 1-65535.",
                 AnsiPalette.AMBER))
    return default


def run_setup_wizard(ctx: AppContext) -> int:
    """Wizard inicial ligero: proxy corporativo + token de API.

    Wizard operativo: proxy corporativo, token de API y clave PSK de la
    VPN propia (todo lo necesario para lanzar los servicios reales del
    daemon). La contraseña del proxy y la clave VPN quedan cifradas en
    disco vía CryptoEngine.
    """
    theme = art.get_theme()
    art.print_box(
        [_c("AZZAZEL SETUP WIZARD", theme.primary),
         "Configuración inicial del entorno"],
        style="double", align="center", width=48,
        border_color=theme.secondary if COLOR_ENABLED else None,
    )
    cm = ctx.config_manager
    print()

    print(_c("─ Paso 1/3: Proxy corporativo (upstream) ─", theme.secondary))
    if _ask_yes_no("¿Tu PC sale a internet a través de un proxy?"):
        cm.set("proxy.upstream.enabled", True)
        cm.set("proxy.upstream.host",
               _ask("Host del proxy (p. ej. proxy.empresa.com)"))
        cm.set("proxy.upstream.port", _ask_port("Puerto", 8080))

        auths = ("basic", "ntlm", "kerberos", "digest")
        for i, name in enumerate(auths, 1):
            print(f"      [{i}] {name}")
        idx = _ask("Tipo de autenticación [1-4]", "1")
        auth = auths[int(idx) - 1] if idx.isdigit() and 1 <= int(idx) <= 4 else "basic"
        cm.set("proxy.upstream.auth_type", auth)

        if auth in ("ntlm", "kerberos"):
            cm.set("proxy.upstream.domain",
                   _ask("Dominio (p. ej. EMPRESA)", ""))
        cm.set("proxy.upstream.username", _ask("Usuario"))
        try:
            password = getpass.getpass("    > Contraseña (no se muestra): ")
        except (EOFError, KeyboardInterrupt):
            password = ""
        if password:
            cm.set("proxy.upstream.password", password)
        cm.set("proxy.upstream.ssl_verify",
               _ask_yes_no("¿El proxy hace SSL inspection? (verificar CA)",
                           default=True))
        print(_c("    [✓] Proxy corporativo registrado.", 
                 AnsiPalette.MATRIX_GREEN))
    else:
        cm.set("proxy.upstream.enabled", False)

    print()
    print(_c("─ Paso 2/3: Seguridad del panel/API ─", theme.secondary))
    if _ask_yes_no("¿Generar un auth_token aleatorio para la API REST?",
                   default=True):
        cm.set("api.auth_token", random_token(24))
        print(_c("    [✓] Token de API generado (guardado cifrado).",
                 AnsiPalette.MATRIX_GREEN))

    print()
    print(_c("─ Paso 3/3: Clave de la VPN propia (servidor/túnel) ─",
             theme.secondary))
    existing = bool(cm.get("vpn.keys.private_key"))
    prompt = ("Ya existe una clave VPN. ¿La REGENERAMOS?" if existing
              else "¿Generamos clave aleatoria para la VPN ahora?")
    if _ask_yes_no(prompt, default=not existing):
        new_key = random_token(48)
        cm.set("vpn.keys.private_key", new_key)
        import hashlib as _sha
        cm.set("vpn.keys.public_key",
               _sha.sha256(new_key.encode("utf-8")).hexdigest()[:44])
        print(_c("    [✓] Clave VPN generada (guardada CIFRADA; actúa "
                 "como PSK del túnel; comparte la config con tus nodos).",
                 AnsiPalette.MATRIX_GREEN))
    else:
        print("    Saltando generación; el daemon server exigirá que "
              "existan claves.")

    try:
        problems = cm.validate()
    except ConfigValidationError as err:  # pragma: no cover
        problems = err.errors
    cm.save()
    print()
    print(_c("╔══ SETUP COMPLETO ══╗", theme.primary))
    print(f"    Configuración guardada en: {cm.path}")
    print("    La contraseña del upstream quedó cifrada (ENC[AES-256-GCM]).")
    if problems:
        print(_c(f"    Revísales estos {len(problems)} aviso(s):",
                 AnsiPalette.AMBER))
        for p in problems:
            print(f"      - {p}")
    _log.success("Wizard --setup completado.")
    return 0


# ---------------------------------------------------------------------------
# Selector de interfaz (launcher): consola vs ventana
# ---------------------------------------------------------------------------
def choose_ui_mode(ctx: AppContext, forced: Optional[str] = None) -> str:
    """Resuelve si arrancar en ``cli`` (consola) o ``gui`` (ventana).

    Orden de precedencia:

    1. Flags explícitos (``--cli`` / ``--gui``) — nunca preguntan.
    2. ``ui.mode`` en config: ``cli``/``gui`` → se usa directamente.
    3. ``ui.mode: ask`` → el launcher PREGUNTA al usuario y persiste su
       elección en ``config.yaml`` (así la siguiente vez arranca directo
       en su modo preferido). Sin TTY (pipes/servicios), cae a ``cli``.
       La variable ``AZZAZEL_ASK_UI=1`` fuerza la pregunta incluso sin
       TTY (útil para pruebas).

    Returns:
        ``"cli"`` o ``"gui"``.
    """
    if forced in ("cli", "gui"):
        return forced
    mode = ctx.config.azzazel.ui.mode
    if mode in ("cli", "gui"):
        return mode

    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not interactive and os.environ.get("AZZAZEL_ASK_UI") != "1":
        _log.info("ui.mode=ask sin terminal interactiva: arranco en CLI.")
        return "cli"

    theme = art.get_theme()
    print(art.box(
        [
            _c("¿Cómo prefieres trabajar con AZZAZEL?", theme.primary),
            "",
            f"{_c('[1]', theme.tertiary)} 🖥️  CONSOLA  — terminal hacker "
            f"(matrix, efectos, prompt azzazel>)",
            f"{_c('[2]', theme.tertiary)} 🪟 VENTANA  — programa normal, "
            f"ventana oscura con paneles",
            "",
            _c("Tu elección se guarda en config.yaml (ui.mode). "
               "Cámbiala cuando quieras con --cli / --gui.",
               theme.secondary),
        ],
        title="AZZAZEL LAUNCHER", style="double", width=64,
        border_color=theme.secondary if COLOR_ENABLED else None,
    ))
    choice_raw = _ask("Modo [1-2]", "1")
    choice = "gui" if choice_raw.strip() == "2" else "cli"
    ctx.config_manager.set("azzazel.ui.mode", choice)
    ctx.config_manager.save()
    art.type_text(
        f"[✓] Preferencia guardada: {'VENTANA (GUI)' if choice == 'gui' else 'CONSOLA (CLI)'}",
        cps=200, color=theme.primary if COLOR_ENABLED else None,
    )
    _log.info("ui.mode elegido por el usuario: %s (persistido).", choice)
    return choice


def launch_gui(ctx: AppContext) -> int:
    """Lanza la ventana de escritorio (mismo diseño que la app web/PWA).

    Prioriza la ventana WebView (``ui.webapp``), que carga el HTML/CSS/JS
    real de la PWA — login, ajustes y proxy corporativo con la interfaz
    unificada. Si ``pywebview`` o el build de la PWA no están disponibles,
    cae a la ventana legada de CustomTkinter y, si tampoco es viable, a CLI.
    """
    try:
        from ui.webapp.desktop_window import check_desktop_webview_support, run_desktop_app
        ok, reason = check_desktop_webview_support()
        if ok:
            return run_desktop_app()
        _log.warning("Ventana WebView no disponible (%s); probando GUI legada.", reason)
    except Exception as exc:  # noqa: BLE001 - seguir intentando con la GUI legada
        _log.warning("No se pudo cargar la ventana WebView: %s", exc)

    try:
        from ui.gui.app import check_gui_support, run_gui
    except Exception as exc:  # noqa: BLE001 - fallback duro a CLI
        print(_c(f"[✗] No se pudo cargar ninguna GUI: {exc}",
                 AnsiPalette.NEON_RED))
        _log.error("Import de GUI fallido: %s", exc)
        return run_interactive(ctx)

    ok, reason = check_gui_support()
    if not ok:
        print(_c(f"[i] La ventana no puede abrirse aquí: {reason}",
                 AnsiPalette.AMBER))
        print(_c("    Arrancando en modo CONSOLA…", AnsiPalette.AMBER))
        _log.warning("GUI no soportada (%s); fallback a CLI.", reason)
        return run_interactive(ctx)
    try:
        return run_gui(ctx.config_manager)
    except Exception as exc:  # noqa: BLE001 - display caído a mitad, etc.
        _log.error("La GUI murió inesperadamente: %s", exc, exc_info=True)
        print(_c(f"[✗] La ventana falló: {exc}. Sigo en CONSOLA.",
                 AnsiPalette.NEON_RED))
        return run_interactive(ctx)


# ---------------------------------------------------------------------------
# Runtime de servicios reales (daemon: server / client / bridge)
# ---------------------------------------------------------------------------
def _parse_peer(text: str, default_port: int = 51820
                ) -> tuple[str, int]:
    """Parsea ``host[:puerto]`` con mensajes de error accionables."""
    text = (text or "").strip()
    if not text:
        raise ValueError("peer vacío")
    host, sep, port_s = text.rpartition(":")
    if not sep:
        return text, default_port
    try:
        port = int(port_s)
    except ValueError as exc:
        raise ValueError(f"puerto inválido en peer: {port_s!r}") from exc
    if not (1 <= port <= 65535):
        raise ValueError("puerto de peer fuera de rango (1-65535)")
    return host or text, port


def resolve_client_peer(cli_peer: Optional[str]) -> Optional[tuple[str, int]]:
    """Resuelve el peer del cliente VPN: --peer > env AZZAZEL_VPN_PEER."""
    raw = cli_peer if cli_peer is not None else os.environ.get(
        "AZZAZEL_VPN_PEER", "")
    raw = raw.strip()
    if not raw:
        return None
    return _parse_peer(raw)


async def _start_api_service(ctx: AppContext, handles: list) -> None:
    """API REST + telemetría compartida del modo activo (S7).

    Registra la sonda vital del daemon y arranca el servidor HTTP si
    ``api.enabled=true``; cierra limpiamente vía handle "api".
    """
    from monitoring.metrics import LOG_RING, UPTIME, VITALS
    UPTIME.mark_started()
    UPTIME.mark_started()  # idempotente
    VITALS.register("azzazel", lambda: {
        "mode": ctx.config.azzazel.mode,
        "version": __version__,
        "theme": ctx.config.azzazel.ui.theme,
    })
    if LOG_RING not in logging.getLogger().handlers:
        logging.getLogger().addHandler(LOG_RING)
        logging.getLogger().setLevel(logging.DEBUG)
    if not ctx.config.api.enabled:
        _log.info("api.enabled=false en config.yaml; API REST desactivada "
                  "(telemetry sigue viva vía vitals/metrics).")
        return
    from monitoring.api_server import ApiServer
    api = ApiServer.from_config(ctx.config_manager)
    try:
        api.start_background()
    except RuntimeError as exc:
        _log.error("%s", exc)
        return
    handles.append(("api", api))
    _log.info("WAR ROOM web: http://127.0.0.1:%d (token=%s).", api.port,
              "sí" if api.auth_token else "NO — configura api.auth_token")


async def _start_services(ctx: AppContext,
                          cli_peer: Optional[str]) -> tuple[list, int]:
    """Arranca los servicios del modo activo (``azzazel.mode``).

    Returns:
        ``(handles, rc)`` — handles arrancados (en orden) y código de
        retorno para main (0 = todo arriba, 1 = fallo de arranque con la
        guía ya registrada en el log).
    """
    cfg = ctx.config
    mode = cfg.azzazel.mode
    handles: list = []
    await _start_api_service(ctx, handles)  # telemetría siempre viva

    if mode == "server":
        if not cfg.vpn.enabled:
            _log.warning("vpn.enabled=false en config.yaml; el daemon "
                         "queda en espera como heartbeat.")
            return handles, 0
        if not cfg.vpn.keys.private_key:
            _log.error(
                "vpn.keys.private_key está vacía: ejecuta "
                "'python azzazel.py --setup' y acepta la generación de "
                "clave (o cm.set('vpn.keys.private_key', <token>)).")
            return handles, 1
        from monitoring.metrics import VITALS
        from vpn.tunnel_manager import TunnelServer
        server = TunnelServer.from_config(ctx.config_manager)
        await server.start()
        handles.append(("vpn-server", server))
        VITALS.register("vpn-server", lambda s=server: {
            "port": s.port, "sessions": s.active_sessions,
            "subnet": cfg.vpn.server.tunnel_subnet,
        })
        _log.success("SERVICIO VPN ARRIBA: %s:%s (máx %s clientes).",
                     cfg.vpn.server.listen_address,
                     server.port, cfg.vpn.server.max_clients)
        return handles, 0

    if mode == "client":
        peer = resolve_client_peer(cli_peer)
        if peer is None:
            _log.error(
                "Modo client sin peer: pasa '--peer host[:puerto]' o "
                "exporta AZZAZEL_VPN_PEER=host[:puerto] (sin peer no hay "
                "túnel que abrir).")
            return handles, 1
        if not cfg.vpn.keys.private_key:
            _log.error("vpn.keys.private_key vacía (misma PSK que el "
                       "servidor); ejecútalo --setup antes.")
            return handles, 1
        from vpn.tunnel_manager import KillSwitch, TunnelClient, HandshakeError
        kill = KillSwitch(armed=cfg.vpn.client.kill_switch,
                          hook=lambda reason: _log.error(
                              "KILL SWITCH activo — razón: %s", reason))
        client = TunnelClient(
            cfg.vpn.keys.private_key, peer[0], peer[1],
            keepalive=cfg.vpn.server.keepalive,
            max_retries=10,  # política por defecto; relanzar daemon reinicia
            kill_switch=kill,
        )
        try:
            await client.connect()
        except HandshakeError as exc:
            _log.error("No se pudo abrir el túnel a %s:%s (%s). "
                       "Comprueba PSK/estado del servidor.", peer[0],
                       peer[1], exc)
            return handles, 1
        client.start_background()
        handles.append(("vpn-client", client))
        from monitoring.metrics import VITALS
        VITALS.register("vpn-client", lambda c=client: c.stats())
        _log.success("TÚNEL VPN ESTABLECIDO con %s:%s (kill_switch=%s).",
                     peer[0], peer[1], "ON" if kill.armed else "off")
        return handles, 0

    if mode == "bridge":
        if not cfg.bridge.enabled:
            _log.warning("bridge.enabled=false en config.yaml; "
                         "actívalo y relanza para compartir el PC↔móvil.")
            return handles, 0
        from bridge.mobile_bridge import MobileBridge
        bridge = MobileBridge(
            config_manager=ctx.config_manager,
            host="0.0.0.0",
            pin_callback=lambda pin, name: _log.success(
                "📱 PIN DE EMPAREJAMIENTO PARA %s → %s (60s TTL)",
                name, pin),
        )
        await bridge.start()
        handles.append(("bridge", bridge))
        from monitoring.metrics import VITALS
        VITALS.register("bridge", lambda b=bridge: b.status())
        _log.success("BRIDGE ARRIBA: %s:%s — los móviles se emparejan "
                     "por PIN y navegan vía tu ProxyChain.",
                     bridge.host, bridge.port)
        return handles, 0

    _log.error("Modo desconocido en config: %r", mode)
    return handles, 1


async def _daemon_async(ctx: AppContext, cli_peer: Optional[str]) -> int:
    """Cuerpo async del daemon: servicios vivos + heartbeat + señales."""
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _armed_stop() -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _armed_stop)
        except (NotImplementedError, ValueError, RuntimeError):
            try:
                signal.signal(sig, lambda *_a, _l=loop, _s=stop_event:
                              _l.call_soon_threadsafe(_s.set))
            except (ValueError, OSError):  # pragma: no cover
                pass

    cfg = ctx.config
    _log.info("DAEMON AZZAZEL iniciado (PID %d, modo=%s).", os.getpid(),
              cfg.azzazel.mode)

    handles, rc = await _start_services(ctx, cli_peer)
    if rc != 0:
        for _name, handle in reversed(handles):
            close = getattr(handle, "stop", getattr(handle, "close", None))
            if close:
                await close()
        return rc

    heartbeats = 0
    try:
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=20.0)
            except asyncio.TimeoutError:
                pass
            heartbeats += 1
            vitals: list[str] = []
            for name, handle in handles:
                if name == "vpn-server":
                    vitals.append(
                        f"vpn:puerto={handle.port} "
                        f"sesiones={handle.active_sessions}")
                elif name == "vpn-client":
                    st = handle.stats()
                    vitals.append(
                        f"túnel={'on' if st['connected'] else 'CAÍDO'} "
                        f"ka_ok={st['rx_keepalives']} "
                        f"kill_switch={'ENGAGED' if st['kill_switch'] else 'off'}")
                elif name == "bridge":
                    st = handle.status()
                    vitals.append(
                        f"bridge:puerto={st['port']} "
                        f"sesiones={st['sessions']} "
                        f"whitelist={st['whitelisted']}")
            _log.info("heartbeat #%d · %s", heartbeats,
                      " | ".join(vitals) or "sin servicios (idle)")
    finally:
        for name, handle in reversed(handles):
            close = getattr(handle, "stop", getattr(handle, "close", None))
            if close is not None:
                try:
                    await close()
                    _log.info("Servicio %s detenido limpiamente.", name)
                except Exception as exc:  # noqa: BLE001 - seguir cerrando
                    _log.error("Error cerrando %s: %s", name, exc)
        _log.success("Daemon detenido limpiamente (0 fugas de recursos).")
    return 0


def run_daemon(ctx: AppContext, cli_peer: Optional[str] = None) -> int:
    """Ejecuta AZZAZEL como servicio sin interfaz (systemd/Task Scheduler).

    Arranca los servicios reales del modo activo y los detiene con
    cierre limpio ante SIGINT/SIGTERM.
    """
    try:
        return asyncio.run(_daemon_async(ctx, cli_peer))
    except KeyboardInterrupt:
        _log.warning("Apagado por Ctrl+C.")
        return 0


# ---------------------------------------------------------------------------
# Modo interactivo (shell `azzazel > `)
# ---------------------------------------------------------------------------
CommandHandler = Callable[[AppContext, list[str]], Optional[bool]]


def _cmd_banner(ctx: AppContext, _argv: list[str]) -> None:
    art.print_banner()


def _cmd_clear(ctx: AppContext, _argv: list[str]) -> None:
    art.clear_screen()


def _cmd_status(ctx: AppContext, _argv: list[str]) -> None:
    print(render_status_report(ctx))


def _cmd_version(ctx: AppContext, _argv: list[str]) -> None:
    theme = art.get_theme()
    print(_c(f"{APP_NAME} v{__version__} — modo {ctx.config.azzazel.mode}",
             theme.primary))


def _cmd_theme(ctx: AppContext, argv: list[str]) -> None:
    if not argv:
        print(f"    Tema actual: {art.get_theme().name} "
              f"(disponibles: matrix, cyber, blood)")
        return
    try:
        art.set_theme(argv[0])
    except ValueError as exc:
        print(_c(f"    [!] {exc}", AnsiPalette.AMBER))
        return
    ctx.config_manager.set("azzazel.ui.theme", art.get_theme().name)
    ctx.config_manager.save()
    print(_c(f"    [✓] Tema '{art.get_theme().name}' aplicado y persistido.",
             AnsiPalette.MATRIX_GREEN))


def _cmd_help(ctx: AppContext, _argv: list[str]) -> None:
    theme = art.get_theme()
    lines = [
        f"{_c(x, theme.tertiary):<20} {desc}"
        for x, desc in (
            ("help",   "Muestra esta ayuda"),
            ("status", "Informe técnico del sistema"),
            ("version","Versión y modo actual"),
            ("theme",  "theme matrix|cyber|blood — cambia el tema (persiste)"),
            ("banner", "Reimprime el banner AZZAZEL"),
            ("clear",  "Limpia la terminal"),
            ("1-9",    "Abre un módulo de la suite (ver roadmap abajo)"),
            ("exit/0", "Salida limpia"),
        )
    ]
    lines.append("")
    lines.append(_c("Roadmap de módulos:", theme.secondary))
    for digit, (name, file_, sprint) in sorted(_MODULE_ROADMAP.items()):
        lines.append(f"  [{digit}] {name:<18} {file_:<30} {sprint}")
    print(art.box(lines, title="AYUDA", style="single",
                  border_color=theme.secondary if COLOR_ENABLED else None))


def _cmd_network_tools(ctx: AppContext, argv: list[str]) -> None:
    """Network Tools en vivo: escáner de puertos + sweep de red (S5).

    Uso rápido: ``4 <host> [puertos]`` (p. ej. ``4 localhost 22,80,443``)
    o ``4 sweep <cidr>``; sin args, un mini-wizard interactivo.
    """
    from network.scanner import (NetworkEnumerator, PortScanner,
                                 parse_ports)
    theme = art.get_theme()
    print()

    # Sub-comando de barrido de subred (TCP-ping honesto, sin ICMP raw)
    if len(argv) >= 2 and argv[0].lower() == "sweep":
        try:
            enum = NetworkEnumerator()
            up = enum.sweep_sync(argv[1])
        except ValueError as exc:
            print(_c(f"    [✗] {exc}", AnsiPalette.AMBER))
            return
        print(_c(f"    Hosts vivos en {argv[1]}: {up or '∅'}",
                 AnsiPalette.MATRIX_GREEN))
        return

    if argv:  # quick-pass por argumentos
        host = argv[0]
        spec = argv[1] if len(argv) > 1 else "22,80,443,47671,51820"
        banners = True
    else:     # mini-wizard
        theme = art.get_theme()
        print(_c("─ AZZAZEL NETWORK TOOLS ─", theme.tertiary))
        host = _ask("Objetivo (host/IP)", "localhost")
        spec = _ask("Puertos (ej. 22,80,443 o 1-1024)",
                    "22,80,443,47671,51820")
        banners = _ask_yes_no("¿Banner grabbing (escucha pasiva)?",
                              default=True)

    try:
        ports = parse_ports(spec)
    except ValueError as exc:
        print(_c(f"    [✗] {exc}", AnsiPalette.AMBER))
        return

    scanner = PortScanner(timeout=0.8, concurrency=256,
                          banner_grab=banners)
    every = max(1, len(ports) // 40)
    _log.info("Network Tools: escaneando %s (%d puertos, banner=%s).",
              host, len(ports), banners)

    def _dot(done: int, total: int) -> None:  # noqa: ANN001
        if done % every == 0 or done == total:
            sys.stdout.write(".")
            sys.stdout.flush()

    try:
        report = scanner.scan(host, ports, on_progress=_dot)
    except (ValueError, RuntimeError) as exc:
        print(_c(f"    [✗] {exc}", AnsiPalette.AMBER))
        return
    print()  # tras los puntos de progreso
    print(art.box(report.render(color=COLOR_ENABLED).splitlines(),
                  title="INFORME DE ESCANEO", style="single",
                  border_color=theme.secondary if COLOR_ENABLED else None,
                  pad_v=0))
    if not argv:  # sweep opcional solo en modo wizard
        cidr = _ask("¿Barrido TCP-ping de una subred? (CIDR o vacío "
                    "para saltar)", "")
        if cidr.strip():
            try:
                up = NetworkEnumerator().sweep_sync(cidr.strip())
                print(_c(f"    Hosts vivos: {up or '∅'}",
                         AnsiPalette.MATRIX_GREEN))
            except ValueError as exc:
                print(_c(f"    [✗] {exc}", AnsiPalette.AMBER))


def _cmd_firewall_panel(ctx: AppContext, argv: list[str]) -> None:
    """Panel Firewall (S7): política de config + plan de kill-switch.

    Nunca toca la máquina: todo se muestra en modo DRY-RUN; aplicar de
    verdad requiere ``FirewallManager(dry_run=False)`` y privilegios.
    """
    from firewall.fw_manager import FirewallManager, vpn_only_rules
    cfg = ctx.config.firewall
    theme = art.get_theme()
    print()
    print(_c("─ AZZAZEL FIREWALL MANAGER (plan dry-run) ─", theme.tertiary))
    print(f"    enabled={cfg.enabled} · default_policy="
          f"{cfg.default_policy} · reglas en config: {len(cfg.rules)}")
    for line in cfg.rules:
        print(f"      · {line}")

    peer = resolve_client_peer(None)
    if peer is not None:
        endpoint_host, endpoint_port = peer[0], peer[1]
    else:
        endpoint_host, endpoint_port = "192.0.2.10", \
            ctx.config.vpn.server.listen_port
        print(_c("    (sin peer definido: plan kill-switch con endpoint "
                 "de ejemplo 192.0.2.10; exporta AZZAZEL_VPN_PEER para "
                 "el real)", AnsiPalette.AMBER))

    mgr = FirewallManager(dry_run=True,
                          default_policy=cfg.default_policy
                          if cfg.default_policy in ("allow", "deny")
                          else "allow")
    for rule in vpn_only_rules(endpoint_host, endpoint_port):
        mgr.add_rule(rule)
    print(art.box(mgr.render_plan(), title="PLAN KILL-SWITCH (vpn_only)",
                  style="single",
                  border_color=theme.primary if COLOR_ENABLED else None,
                  pad_v=0))
    print(_c("    ℹ Aplicar real requiere root/Administrador y "
             "dry_run=False (auditado antes de tocar la máquina).",
             theme.secondary))


_MENU_API: dict[str, object] = {"server": None}  # API viva desde el menú


def _cmd_monitoring_panel(ctx: AppContext, _argv: list[str]) -> None:
    """Panel Monitoring/API (S7): arranca la REST + WAR ROOM en vivo.

    Si la API ya está corriendo (daemon o arranque anterior en esta
    shell), solo re-imprime datos de acceso. Sin token, avisa en ámbar.
    """
    from monitoring.api_server import ApiServer
    theme = art.get_theme()
    print()
    print(_c("─ AZZAZEL MONITORING / WAR ROOM ─", theme.tertiary))

    server = _MENU_API["server"]
    if server is None:
        from monitoring.metrics import LOG_RING, UPTIME, VITALS
        UPTIME.mark_started()
        VITALS.register("azzazel", lambda: {
            "mode": ctx.config.azzazel.mode,
            "version": __version__, "ui": "cli",
        })
        if LOG_RING not in logging.getLogger().handlers:
            logging.getLogger().addHandler(LOG_RING)
        server = ApiServer.from_config(ctx.config_manager)
        try:
            server.start_background()
        except RuntimeError as exc:
            print(_c(f"    [✗] {exc}", AnsiPalette.AMBER))
            return
        _MENU_API["server"] = server

    tips = [
        f"Consola web: http://127.0.0.1:{server.port}",
        f"Auth: {'Bearer ' + server.auth_token[:8] + '…' if server.auth_token else 'SIN TOKEN (api.auth_token vacío)'}",
        "Endpoints: /api/v1/{health|status|metrics|logs|config|events}",
        f"CORS: {server.cors_origins} · rate: {server.rate.limit}/min",
        "Ejemplo: curl -H 'Authorization: Bearer <token>' "
        f"http://127.0.0.1:{server.port}/api/v1/status",
    ]
    print(art.box(tips, title="API REST EMBEBIDA", style="single",
                  border_color=theme.secondary if COLOR_ENABLED else None,
                  pad_v=0))
    if _ask_yes_no("¿Abrir la WAR ROOM en tu navegador?", default=False):
        import webbrowser
        webbrowser.open(f"http://127.0.0.1:{server.port}")


def _cmd_remote_panel(ctx: AppContext, argv: list[str]) -> None:
    """Acceso remoto SSH (S7): wizard de credenciales + exec en vivo."""
    from remote.remote_shell import (PARAMIKO_AVAILABLE,
                                     RemoteShellClient, RemoteShellError,
                                     SshProfile)
    theme = art.get_theme()
    print()
    print(_c("─ AZZAZEL REMOTE ACCESS (SSH) ─", theme.tertiary))
    if not PARAMIKO_AVAILABLE:
        print(_c("    [✗] paramiko no instalado: pip install paramiko",
                 AnsiPalette.AMBER))
        return
    host = argv[0] if argv else _ask("Host SSH (nombre/IP)")
    username = argv[1] if len(argv) > 1 else _ask("Usuario")
    port = 22
    if len(argv) > 2 and argv[2].isdigit():
        port = int(argv[2])
    use_key = _ask_yes_no("¿Autenticación con fichero de clave?",
                          default=False)
    password = key_path = ""
    if use_key:
        key_path = _ask("Ruta clave privada (PEM/OpenSSH)")
    else:
        try:
            password = getpass.getpass(
                "    > Contraseña SSH (no se muestra): ")
        except (EOFError, KeyboardInterrupt):
            print()
            return
    command = argv[3] if len(argv) > 3 else \
        _ask("Comando remoto a ejecutar", "uname -a; whoami")
    try:
        profile = SshProfile(host=host, port=port, username=username,
                             password=password, key_path=key_path)
    except ValueError as exc:
        print(_c(f"    [✗] {exc}", AnsiPalette.AMBER))
        return
    try:
        with RemoteShellClient(profile) as sh:
            result = sh.exec(command)
    except RemoteShellError as exc:
        print(_c(f"    [✗] {exc}", AnsiPalette.AMBER))
        return
    print(art.box(result.render().splitlines(),
                  title=f"EJECUCIÓN REMOTA ({host})",
                  style="single",
                  border_color=theme.primary if COLOR_ENABLED else None,
                  pad_v=0))


def _cmd_tunnel_panel(ctx: AppContext, argv: list[str]) -> None:
    """Túneles SSH y Port Forwarding (S7): -L local, -R remoto, -D dinámico."""
    from tunnel.ssh_tunnel import (ForwardRule, ForwardType, PARAMIKO_AVAILABLE,
                                   SshTunnelManager, SshTunnelError)
    from remote.remote_shell import SshProfile
    theme = art.get_theme()
    print()
    print(_c("─ AZZAZEL SSH TUNNEL MANAGER (PORT FORWARDING) ─", theme.tertiary))
    if not PARAMIKO_AVAILABLE:
        print(_c("    [✗] paramiko no instalado: pip install paramiko",
                 AnsiPalette.AMBER))
        return

    if argv and argv[0] in ("-L", "-R", "-D", "local", "remote", "dynamic"):
        flag = argv[0].upper()
    else:
        print(_c("Seleccione modo de túnel:", theme.secondary))
        print("  [1] Local Port Forward (-L)   — Acceso local a servicio remoto")
        print("  [2] Dynamic SOCKS5 (-D)       — Proxy dinámico sobre SSH")
        print("  [3] Remote Port Forward (-R)  — Exponer servicio local en SSH remoto")
        choice = _ask("Opción", "1")
        flag = "-D" if choice == "2" else ("-R" if choice == "3" else "-L")

    host = _ask("Host SSH (servidor)", "localhost")
    port = 22
    if ":" in host:
        host, _, p_str = host.rpartition(":")
        port = int(p_str)
    username = _ask("Usuario SSH", "root")
    try:
        password = getpass.getpass("    > Contraseña SSH (no se muestra): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return

    try:
        profile = SshProfile(host=host, port=port, username=username, password=password)
    except ValueError as exc:
        print(_c(f"    [✗] {exc}", AnsiPalette.AMBER))
        return

    tunnel = SshTunnelManager(profile)

    if flag in ("-L", "LOCAL", "1"):
        lport = int(_ask("Puerto local de escucha", "8080"))
        rhost = _ask("Host remoto destino", "127.0.0.1")
        rport = int(_ask("Puerto remoto destino", "80"))
        rule = tunnel.add_local_forward("cli-local", lport, rhost, rport)
    elif flag in ("-D", "DYNAMIC", "2"):
        lport = int(_ask("Puerto local para proxy SOCKS5", "1080"))
        rule = tunnel.add_dynamic_forward("cli-socks", lport)
    else:
        rport = int(_ask("Puerto remoto en servidor SSH", "9000"))
        lhost = _ask("Host local destino", "127.0.0.1")
        lport = int(_ask("Puerto local destino", "3000"))
        rule = tunnel.add_remote_forward("cli-remote", rport, lhost, lport)

    print(_c(f"[*] Conectando a {username}@{host}:{port} y activando {rule.render()}...", theme.secondary))
    try:
        tunnel.start()
    except Exception as exc:
        print(_c(f"    [✗] Error iniciando túnel: {exc}", AnsiPalette.AMBER))
        return

    status_box = [
        "ESTADO: ACTIVO ✔",
        f"HOST:   {username}@{host}:{port}",
        f"REGLA:  {rule.render()}",
        "",
        "Presione ENTER para detener el túnel y cerrar conexiones.",
    ]
    print(art.box(status_box, title="TÚNEL SSH EN EJECUCIÓN", style="round",
                  border_color=theme.primary if COLOR_ENABLED else None))
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    tunnel.stop()
    print(_c("    [»] Túnel SSH detenido correctamente.", theme.secondary))


def _cmd_module_stub(digit: str) -> CommandHandler:
    """Handler para módulos cuyo sprint aún no ha llegado."""

    def _handler(ctx: AppContext, _argv: list[str]) -> None:
        name, file_, sprint = _MODULE_ROADMAP[digit]
        theme = art.get_theme()
        _log.info("Módulo invocado: %s (pendiente: %s).", name, file_)
        msg = [
            _c(f"[{digit}] {name}", theme.tertiary),
            "",
            f"Implementación prevista: {file_}",
            f"Hitos: {sprint}",
            "",
            _c("El command router ya reconoce esta opción; el módulo",
               theme.primary),
            _c("se enganchará aquí cuando su sprint se desarrolle.",
               theme.primary),
        ]
        print(art.box(msg, title="MÓDULO EN HOJA DE RUTA", style="round",
                      border_color=theme.secondary if COLOR_ENABLED else None))

    return _handler


def build_command_table() -> dict[str, CommandHandler]:
    """Registro central de comandos de la shell interactiva."""
    table: dict[str, CommandHandler] = {
        "help": _cmd_help, "h": _cmd_help, "?": _cmd_help,
        "status": _cmd_status,
        "version": _cmd_version,
        "theme": _cmd_theme,
        "banner": _cmd_banner,
        "clear": _cmd_clear, "cls": _cmd_clear,
        "dashboard": _cmd_module_stub("7"),
    }
    for digit in "123456789":
        table[digit] = _cmd_module_stub(digit)
    table["3"] = _cmd_tunnel_panel     # Sprint 7: SSH Tunnel Manager (-L/-R/-D)
    table["4"] = _cmd_network_tools     # Sprint 5: Network Tools en vivo
    table["5"] = _cmd_firewall_panel    # Sprint 7: Firewall Manager plan
    table["7"] = _cmd_monitoring_panel  # Sprint 7: API/WAR ROOM en vivo
    table["9"] = _cmd_remote_panel      # Sprint 7: SSH exec en vivo
    return table


def run_interactive(ctx: AppContext) -> int:
    """Shell interactiva ``azzazel > `` con el menú principal."""
    commands = build_command_table()
    theme = art.get_theme()

    print(render_main_menu(gather_menu_status(ctx)))
    print(_c("  Escribe 'help' para ver todos los comandos.\n",
             theme.secondary))

    prompt = _c("azzazel > ", AnsiPalette.MATRIX_GREEN)
    exit_requested = False
    while not exit_requested:
        try:
            raw = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            break
        raw = raw.strip()
        if not raw:
            continue
        verb, *argv = raw.split()
        verb = verb.lower()
        if verb in ("0", "exit", "quit", "q", "salir"):
            exit_requested = True
            continue
        handler = commands.get(verb)
        if handler is None:
            _log.warning("Comando desconocido: %s", verb)
            print(_c(f"    [?] Comando desconocido: '{verb}'. "
                     f"Escribe 'help'.", AnsiPalette.AMBER))
            continue
        try:
            handler(ctx, argv)
        except Exception as exc:  # noqa: BLE001 - la shell no debe morir
            _log.error("Error ejecutando '%s': %s", verb, exc, exc_info=True)
            print(_c(f"    [✗] Error en '{verb}': {exc}",
                     AnsiPalette.NEON_RED))

    art.type_text("Cerrando sesión... canal cifrado desconectado.",
                  cps=180, color=(art.get_theme().secondary
                                  if COLOR_ENABLED else None))
    _log.success("Sesión interactiva finalizada.")
    return 0


# ---------------------------------------------------------------------------
# Parser de argumentos
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de la línea de comandos."""
    parser = argparse.ArgumentParser(
        prog="azzazel",
        description="AZZAZEL VPN v1.0 — Advanced Network Warfare Suite",
        epilog="Sin flags: splash + menú interactivo CLI.",
    )
    parser.add_argument("--mode", choices=("server", "client", "bridge"),
                        help="Modo de operación (se persiste en config.yaml)")
    parser.add_argument("--peer", type=str, default=None,
                        help="Servidor VPN remoto host[:puerto] para "
                             "--mode client (alt: env AZZAZEL_VPN_PEER)")
    ui_group = parser.add_mutually_exclusive_group()
    ui_group.add_argument("--gui", action="store_true",
                          help="Interfaz gráfica (Sprint 6; cae a CLI si falta customtkinter)")
    ui_group.add_argument("--cli", action="store_true",
                          help="Fuerza la interfaz de terminal")
    parser.add_argument("--daemon", action="store_true",
                        help="Modo servicio headless (sin menú, con heartbeat)")
    parser.add_argument("--setup", action="store_true",
                        help="Wizard de configuración inicial")
    parser.add_argument("--status", action="store_true",
                        help="Informe del sistema y salir")
    parser.add_argument("--doctor", action="store_true",
                        help="Ejecuta diagnóstico integral del sistema (dependencias, red, crypto)")
    parser.add_argument("--install-deps", action="store_true",
                        help="Analiza el código y requirements e instala dependencias faltantes")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH,
                        help="Ruta alternativa de config.yaml")
    parser.add_argument("--no-anim", action="store_true",
                        help="Desactiva animaciones del arranque")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} v{__version__}")
    return parser


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    """Punto de entrada: parsea args, hace bootstrap y despacha el modo."""
    args = build_parser().parse_args(argv)
    theme = art.set_theme("matrix")  # mientras no haya config cargada

    plat_preview = args.status or args.daemon or args.no_anim or not sys.stdout.isatty()
    if not plat_preview:
        run_splash(enabled=True)

    ctx = bootstrap(args)

    # Tema persistente elegido por el usuario en config.yaml
    try:
        art.set_theme(ctx.config.azzazel.ui.theme)
    except ValueError:
        _log.warning("Tema en config inválido; se mantiene '%s'.", theme.name)

    # El modo forzado por CLI se persiste
    if args.mode:
        ctx.config_manager.set("azzazel.mode", args.mode)
        ctx.config_manager.save()
        _log.info("Modo forzado por CLI: %s (persistido).", args.mode)

    if args.doctor:
        from ui.cli.doctor import SystemDoctor
        doc = SystemDoctor(config_path=args.config)
        doc.run_all()
        print(doc.render_report(color=COLOR_ENABLED))
        return 0

    if args.install_deps:
        import install_deps
        return install_deps.main(["-y"])

    if args.status:
        print(render_status_report(ctx))
        return 0
    if args.setup:
        return run_setup_wizard(ctx)
    if args.daemon or os.environ.get("AZZAZEL_DAEMON"):
        return run_daemon(ctx, getattr(args, "peer", None))

    forced_ui = "gui" if args.gui else ("cli" if args.cli else None)
    ui_choice = choose_ui_mode(ctx, forced=forced_ui)
    if ui_choice == "gui":
        return launch_gui(ctx)
    return run_interactive(ctx)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Ctrl+C en cualquier punto del arranque: salida ordenada.
        print()
        try:
            _log.warning("Arranque interrumpido por el usuario (Ctrl+C).")
        finally:
            sys.exit(130)
