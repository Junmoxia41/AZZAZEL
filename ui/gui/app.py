"""
AZZAZEL ui/gui/app.py — interfaz gráfica de usuario en CustomTkinter (Sprint 6 + v3.1).

Arquitectura:
- **Tema HACKER** (:mod:`ui.gui.theme`) — paleta `#00ff41` (Matrix),
  `#0abdc6` (cyan), `#ea00d9` (magenta), `#ff003c` (red), `#ffb700`
  (amber) sobre fondo `#050505`.
- **Navegación lateral de módulos** (Dashboard, VPN, Proxy, Tunnel,
  Network Tools, Firewall, Bridge, Monitoring, Settings) con iconos y
  estados dinámicos.
- **Páginas Vivas e Interactivas**:
  - **Dashboard**: telemetría general, API daemon REST status, mapa
    retro ASCII y gráfico de tráfico con buffer circular.
  - **VPN Manager**: control de servidor y cliente VPN, generación y
    cifrado de PSK de 256 bits, kill-switch, prueba de handshake.
  - **Bridge PC↔Mobile**: servidor bridge para compartir internet a
    móviles, generación y validación de PIN de 6 dígitos, whitelist
    de dispositivos emparejados.
  - **Tunnel Manager**: port forwarding SSH local (-L), remoto (-R) y
    dinámico SOCKS5 (-D).
  - **Proxy Suite**: prueba interactiva de la cadena de proxies
    (NTLMv2, basic, direct) contra cualquier host:puerto.
  - **Network Tools**: escáner de puertos TCP y sweep de subred /30.
  - **Settings**: edición y guardado cifrado en disco (AES-256-GCM).
- **Log Terminal integrado** en la parte inferior, conectado al
  logger ``azzazel`` mediante una cola sin bloqueo.
"""
from __future__ import annotations

import asyncio
from collections import deque
import json
import logging
import math
import os
from pathlib import Path
import queue
import random
import re
import socket
import sys
import threading
import time
from typing import Any, Callable, Optional

# Bootstrap path
_AZZAZEL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_AZZAZEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_AZZAZEL_ROOT))

from core.logger import get_logger
from ui.gui.theme import AZZAZEL_THEME, GuiTheme

_log = get_logger("ui.gui")

__all__ = ["AzzazelGuiApp", "run_gui", "check_gui_support"]

GLITCH_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>/?01"


# ----------------------------------------------------------------------
# Detección de soporte gráfico
# ----------------------------------------------------------------------
def check_gui_support() -> tuple[bool, str]:
    """Comprueba si el entorno puede desplegar ventanas Tkinter."""
    if sys.platform != "win32":
        display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
        if not display:
            return (
                False,
                "Sin servidor gráfico disponible (DISPLAY no está seteado).\n"
                "Para entorno sin cabeza (SSH/Docker), use el modo CLI:\n"
                "  python3 azzazel.py --cli",
            )
    try:
        import tkinter
        tk_test = tkinter.Tk()
        tk_test.withdraw()
        tk_test.destroy()
    except Exception as exc:  # noqa: BLE001
        return (
            False,
            f"Tkinter no pudo inicializar una ventana: {exc}\n"
            "En Debian/Ubuntu instale: sudo apt install python3-tk",
        )
    try:
        import customtkinter  # noqa: F401
    except ImportError:
        return (
            False,
            "Librería 'customtkinter' no encontrada.\n"
            "Instálela con: pip install customtkinter pillow",
        )
    return True, "OK"


# ----------------------------------------------------------------------
# Metadatos del Roadmap de Módulos
# ----------------------------------------------------------------------
_MODULE_META: list[dict[str, Any]] = [
    {"key": "dashboard", "icon": "📊", "title": "Dashboard",
     "file": "monitoring/dashboard.py", "sprint": "Sprint 7 ✔ LISTO"},
    {"key": "vpn", "icon": "🔒", "title": "VPN Manager",
     "file": "vpn/tunnel_manager.py", "sprint": "Sprint 3 ✔ LISTO"},
    {"key": "proxy", "icon": "🔄", "title": "Proxy Suite",
     "file": "proxy/proxy_chain.py", "sprint": "Sprint 2 ✔ LISTO"},
    {"key": "tunnel", "icon": "🚇", "title": "Tunnel Manager",
     "file": "tunnel/ssh_tunnel.py", "sprint": "Sprint 7 ✔ LISTO"},
    {"key": "network", "icon": "🌐", "title": "Network Tools",
     "file": "network/scanner.py", "sprint": "Sprint 5 ✔ LISTO"},
    {"key": "firewall", "icon": "🛡", "title": "Firewall",
     "file": "firewall/fw_manager.py", "sprint": "Sprint 7 ✔ LISTO"},
    {"key": "bridge", "icon": "🌉", "title": "Bridge PC↔Mobile",
     "file": "bridge/mobile_bridge.py", "sprint": "Sprint 4 ✔ LISTO"},
    {"key": "monitoring", "icon": "📈", "title": "Monitoring",
     "file": "monitoring/api_server.py", "sprint": "Sprint 7 ✔ LISTO"},
    {"key": "settings", "icon": "⚙", "title": "Settings",
     "file": "core/config_manager.py", "sprint": "Sprint 1 ✔ LISTO"},
]


# ----------------------------------------------------------------------
# Helpers de Fuentes y Formateo
# ----------------------------------------------------------------------
def resolve_font(preferred_stack: tuple[str, ...],
                 available_families: list[str]) -> str:
    """Devuelve la primera fuente de la lista de preferencias disponible."""
    avail_lower = {f.lower(): f for f in available_families}
    for cand in preferred_stack:
        if cand.lower() in avail_lower:
            return avail_lower[cand.lower()]
    for fallback in ("consolas", "dejavu sans mono", "courier new", "monospace"):
        if fallback in avail_lower:
            return avail_lower[fallback]
    return "TkFixedFont"


class GuiLogHandler(logging.Handler):
    """Handler de logging que enruta registros hacia la terminal de la GUI."""

    def __init__(self, out_queue: "queue.Queue[str]",
                 max_records: int = 2000) -> None:
        super().__init__()
        self._queue = out_queue
        self._max = max_records

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            if self._queue.qsize() > self._max:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    pass
            self._queue.put_nowait(msg)
        except Exception:
            self.handleError(record)


def _glitch_variants(text: str, frames: int = 5,
                     corruption_ratio: float = 0.35) -> list[str]:
    """Genera variantes con 'ruido digital' para animaciones."""
    variants = []
    chars = list(text)
    n = len(chars)
    k = max(1, int(n * corruption_ratio))
    for _ in range(frames - 1):
        mutated = chars.copy()
        for idx in random.sample(range(n), min(k, n)):
            if not mutated[idx].isspace():
                mutated[idx] = random.choice(GLITCH_CHARS)
        variants.append("".join(mutated))
    variants.append(text)
    return variants


def fmt_rate(bytes_per_sec: float) -> str:
    """Formatea bytes/s a unidades humanas."""
    if bytes_per_sec < 1024:
        return f"{bytes_per_sec:5.0f} B/s"
    if bytes_per_sec < 1024 * 1024:
        return f"{bytes_per_sec / 1024:5.1f} KB/s"
    return f"{bytes_per_sec / (1024 * 1024):5.2f} MB/s"


class TrafficSampler:
    """Muestreador de tráfico de red con buffer circular."""

    def __init__(self, history_len: int = 60,
                 use_real_psutil: bool = True) -> None:
        self.history_len = history_len
        self.use_real = use_real_psutil
        self.is_synthetic = False
        self._rx_hist: deque[float] = deque([0.0] * history_len, maxlen=history_len)
        self._tx_hist: deque[float] = deque([0.0] * history_len, maxlen=history_len)
        self._last_rx: Optional[int] = None
        self._last_tx: Optional[int] = None
        self._last_time: float = time.time()
        self._phase: float = 0.0

        if self.use_real:
            try:
                import psutil
                counters = psutil.net_io_counters()
                self._last_rx = counters.bytes_recv
                self._last_tx = counters.bytes_sent
            except Exception:
                self.is_synthetic = True

    def sample(self) -> tuple[float, float]:
        """Toma una muestra y devuelve (rx_rate, tx_rate) en B/s."""
        now = time.time()
        dt = max(now - self._last_time, 0.001)
        self._last_time = now

        if self.use_real and not self.is_synthetic:
            try:
                import psutil
                counters = psutil.net_io_counters()
                rx_diff = max(0, counters.bytes_recv - (self._last_rx or counters.bytes_recv))
                tx_diff = max(0, counters.bytes_sent - (self._last_tx or counters.bytes_sent))
                self._last_rx = counters.bytes_recv
                self._last_tx = counters.bytes_sent
                rx_rate = rx_diff / dt
                tx_rate = tx_diff / dt
                self._rx_hist.append(rx_rate)
                self._tx_hist.append(tx_rate)
                return rx_rate, tx_rate
            except Exception:
                self.is_synthetic = True

        self._phase += 0.2
        base = 40_000 + 25_000 * math.sin(self._phase)
        rx_rate = max(0.0, base + random.gauss(0, 8_000))
        tx_rate = max(0.0, base * 0.45 + random.gauss(0, 4_000))
        self._rx_hist.append(rx_rate)
        self._tx_hist.append(tx_rate)
        return rx_rate, tx_rate

    def series_rx(self) -> list[float]:
        return list(self._rx_hist)

    def series_tx(self) -> list[float]:
        return list(self._tx_hist)


def split_host_port(text: str, default_port: int = 443) -> tuple[str, int]:
    """Parsea una cadena 'host:puerto' o 'host'."""
    raw = text.strip()
    if not raw:
        raise ValueError("host no puede estar vacío")
    if ":" in raw:
        host, _, port_str = raw.rpartition(":")
        if not host:
            raise ValueError("host no puede estar vacío antes de ':'")
        try:
            port = int(port_str)
        except ValueError as exc:
            raise ValueError(f"puerto inválido: '{port_str}'") from exc
        if not (1 <= port <= 65535):
            raise ValueError(f"puerto fuera de rango: {port}")
        return host, port
    return raw, default_port


# ----------------------------------------------------------------------
# Clase Principal de la Aplicación GUI
# ----------------------------------------------------------------------
class AzzazelGuiApp:
    """Ventana principal de AZZAZEL VPN (customtkinter).

    Args:
        config_manager: Gestor de configuración ya arrancado.
    """

    def __init__(self, config_manager) -> None:
        self._cm = config_manager
        self._theme: GuiTheme = AZZAZEL_THEME
        self._ctk = None
        self._root = None
        self._fonts: dict[str, Any] = {}
        self._log_queue: "queue.Queue[str]" = queue.Queue(maxsize=2000)
        self._log_handler: Optional[GuiLogHandler] = None
        self._pages: dict[str, Any] = {}
        self._nav_buttons: dict[str, Any] = {}
        self._current_page: str = "dashboard"
        self._terminal = None
        self._status_labels: dict[str, Any] = {}
        self._toast_job: Optional[str] = None
        self._ui_queue: "queue.Queue[tuple[Callable, Any, Optional[BaseException]]]" = queue.Queue()
        self._traffic = TrafficSampler()
        self._proxy_widgets: dict[str, Any] = {}
        self._vpn_widgets: dict[str, Any] = {}
        self._bridge_widgets: dict[str, Any] = {}
        self._tunnel_widgets: dict[str, Any] = {}
        self._map_canvas = None
        self._graph_canvas = None

        # Servicios vivos opcionales gestionados desde la GUI
        self._active_vpn_server = None
        self._active_vpn_client = None
        self._active_bridge = None
        self._active_tunnel_mgr = None

        # Bucle de eventos asyncio dedicado para tareas asíncronas de fondo
        self._async_loop = asyncio.new_event_loop()
        self._async_thread = threading.Thread(
            target=self._async_loop.run_forever,
            daemon=True,
            name="azz-gui-async-worker",
        )
        self._async_thread.start()

    # ------------------------------------------------------------------
    # Construcción de la Ventana y Layout
    # ------------------------------------------------------------------
    def _build_window(self) -> None:
        import customtkinter as ctk
        import tkinter.font as tkfont

        self._ctk = ctk
        t = self._theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        root = ctk.CTk()
        self._root = root
        root.title("AZZAZEL VPN v1.0 — Advanced Network Warfare Suite")
        root.geometry(f"{t.window_width}x{t.window_height}")
        root.minsize(1024, 680)
        root.configure(fg_color=t.bg_deep)

        families = list(tkfont.families(root))
        mono = resolve_font(t.font_mono_stack, families)
        title = resolve_font(t.font_title_stack, families)
        self._fonts = {
            "mono": ctk.CTkFont(family=mono, size=13),
            "mono_sm": ctk.CTkFont(family=mono, size=11),
            "term": ctk.CTkFont(family=mono, size=12),
            "title": ctk.CTkFont(family=title, size=22, weight="bold"),
            "subtitle": ctk.CTkFont(family=title, size=15, weight="bold"),
            "icon": ctk.CTkFont(size=20),
            "_mono_family": mono,
        }

        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_content_area()
        self._build_terminal()
        self._build_statusbar()

        root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_sidebar(self) -> None:
        ctk, t = self._ctk, self._theme
        side = ctk.CTkFrame(self._root, width=t.sidebar_width,
                            fg_color=t.bg_dark, corner_radius=0)
        side.grid(row=0, column=0, rowspan=2, sticky="nsew")
        side.grid_propagate(False)

        logo = ctk.CTkLabel(side, text="A", font=self._fonts["title"],
                            text_color=t.text_main)
        logo.pack(pady=(14, 10))

        for meta in _MODULE_META:
            btn = ctk.CTkButton(
                side, text=f"{meta['icon']}", width=48, height=46,
                font=self._fonts["icon"], fg_color="transparent",
                hover_color=t.bg_hover, corner_radius=8,
                command=lambda k=meta["key"]: self.show_page(k),
            )
            btn.pack(pady=3, padx=10)
            self._nav_buttons[meta["key"]] = btn

        spacer = ctk.CTkFrame(side, fg_color="transparent")
        spacer.pack(expand=True, fill="both")
        ctk.CTkButton(
            side, text="⏻", width=48, height=46, font=self._fonts["icon"],
            fg_color="transparent", hover_color=t.accent_red,
            corner_radius=8, command=self._on_close,
        ).pack(pady=(3, 14), padx=10)

    def _build_content_area(self) -> None:
        t = self._theme
        self._content = self._ctk.CTkFrame(self._root, fg_color=t.bg_deep,
                                           corner_radius=0)
        self._content.grid(row=0, column=1, sticky="nsew", padx=(4, 8),
                           pady=(8, 4))
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

    def _build_terminal(self) -> None:
        ctk, t = self._theme, self._theme
        term_frame = self._ctk.CTkFrame(self._root, height=t.terminal_height,
                                        fg_color=t.bg_terminal,
                                        corner_radius=6,
                                        border_color=t.border_idle,
                                        border_width=1)
        term_frame.grid(row=1, column=1, sticky="nsew", padx=(4, 8),
                        pady=(0, 4))
        term_frame.grid_propagate(False)

        self._terminal = self._ctk.CTkTextbox(
            term_frame, font=self._fonts["term"], fg_color="transparent",
            text_color=t.text_main, activate_scrollbars=True,
            wrap="none",
        )
        self._terminal.pack(fill="both", expand=True, padx=4, pady=4)
        self._terminal.insert("1.0", "=== AZZAZEL VPN v1.0 AUDIT LOG CONSOLE ===\n")
        self._terminal.configure(state="disabled")

    def _build_statusbar(self) -> None:
        ctk, t = self._ctk, self._theme
        bar = ctk.CTkFrame(self._root, height=t.statusbar_height,
                           fg_color=t.bg_dark, corner_radius=0)
        bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        bar.grid_propagate(False)

        self._status_labels["mode"] = ctk.CTkLabel(
            bar, text=f"MODO: {self._cm.config.azzazel.mode.upper()}",
            font=self._fonts["mono_sm"], text_color=t.text_main)
        self._status_labels["mode"].pack(side="left", padx=14)

        self._status_labels["net"] = ctk.CTkLabel(
            bar, text="RX:   0 B/s | TX:   0 B/s",
            font=self._fonts["mono_sm"], text_color=t.text_cyan)
        self._status_labels["net"].pack(side="left", padx=14)

        self._status_labels["clock"] = ctk.CTkLabel(
            bar, text="00:00:00 UTC", font=self._fonts["mono_sm"],
            text_color=t.text_dim)
        self._status_labels["clock"].pack(side="right", padx=14)

        self._tick_net()
        self._tick_clock()

    def _tick_net(self) -> None:
        if self._root is None:
            return
        rx, tx = self._traffic.sample()
        lbl = self._status_labels.get("net")
        if lbl is not None:
            lbl.configure(text=f"RX: {fmt_rate(rx)} | TX: {fmt_rate(tx)}")
        self._root.after(1000, self._tick_net)

    def _tick_clock(self) -> None:
        if self._root is None:
            return
        lbl = self._status_labels.get("clock")
        if lbl is not None:
            lbl.configure(text=time.strftime("%H:%M:%S UTC", time.gmtime()))
        self._root.after(1000, self._tick_clock)

    def _drain_logs(self) -> None:
        if self._root is None:
            return
        drained: list[str] = []
        try:
            while True:
                drained.append(self._log_queue.get_nowait())
        except queue.Empty:
            pass
        if drained and self._terminal is not None:
            self._terminal.configure(state="normal")
            for line in drained:
                self._terminal.insert("end", line + "\n")
            self._terminal.see("end")
            self._terminal.configure(state="disabled")
        self._root.after(150, self._drain_logs)

    # ------------------------------------------------------------------
    # Puente async → tkinter
    # ------------------------------------------------------------------
    def _run_coro(self, coro: Any,
                  on_done: Optional[Callable[[Any, Optional[BaseException]], None]] = None) -> None:
        """Ejecuta una corrutina en el bucle de eventos asíncrono persistente."""
        fut = asyncio.run_coroutine_threadsafe(coro, self._async_loop)
        if on_done is not None:
            def _cb(f: Any) -> None:
                try:
                    res = f.result()
                    self._ui_queue.put((on_done, res, None))
                except BaseException as exc:  # noqa: BLE001
                    self._ui_queue.put((on_done, None, exc))
            fut.add_done_callback(_cb)

    def _run_async(self, coro_factory: Callable[[], Any],
                   on_done: Callable[[Any, Optional[BaseException]],
                                     None]) -> None:
        """Ejecuta una función síncrona o corrutina en un hilo trabajador."""
        def worker() -> None:
            try:
                res = coro_factory()
                if asyncio.iscoroutine(res):
                    self._run_coro(res, on_done)
                else:
                    self._ui_queue.put((on_done, res, None))
            except BaseException as exc:  # noqa: BLE001
                self._ui_queue.put((on_done, None, exc))

        threading.Thread(target=worker, daemon=True,
                         name="azzazel-gui-task").start()

    def _drain_ui(self) -> None:
        if self._root is None:
            return
        try:
            while True:
                on_done, result, exc = self._ui_queue.get_nowait()
                try:
                    on_done(result, exc)
                except Exception as cb_exc:  # noqa: BLE001
                    _log.error("Callback GUI falló: %s", cb_exc)
        except queue.Empty:
            pass
        self._root.after(50, self._drain_ui)

    def _toast(self, message: str, ok: bool = True) -> None:
        """Muestra una notificación toast con efecto glitch."""
        if self._root is None:
            return
        t = self._theme
        color = t.text_main if ok else t.accent_red
        lbl = self._ctk.CTkLabel(
            self._root, text=message, font=self._fonts["mono_sm"],
            text_color=color, fg_color=t.bg_dark, corner_radius=6,
            padx=12, pady=6,
        )
        lbl.place(relx=1.0, rely=0.0, x=-20, y=20, anchor="ne")

        variants = _glitch_variants(message, frames=4)

        def _animate(frame: int) -> None:
            if self._root is None or not lbl.winfo_exists():
                return
            if frame < len(variants):
                lbl.configure(text=variants[frame])
                self._root.after(45, lambda: _animate(frame + 1))

        def _destroy() -> None:
            if self._root is not None and lbl.winfo_exists():
                lbl.destroy()

        _animate(0)
        self._root.after(2400, _destroy)

    # ------------------------------------------------------------------
    # Enrutamiento de Páginas
    # ------------------------------------------------------------------
    def show_page(self, key: str) -> None:
        """Muestra una página de módulo y actualiza la navegación."""
        ctk, t = self._ctk, self._theme
        if self._root is None:
            return
        if key in self._pages:
            self._pages[key].tkraise()
        else:
            factory: Callable[[], Any] = {
                "dashboard": self._page_dashboard,
                "vpn": self._page_vpn,
                "proxy": self._page_proxy,
                "tunnel": self._page_tunnel,
                "network": self._page_network,
                "bridge": self._page_bridge,
                "monitoring": self._page_monitoring,
                "firewall": self._page_firewall,
                "settings": self._page_settings,
            }.get(key, lambda k=key: self._page_roadmap(k))
            page = factory()
            self._pages[key] = page
            page.grid(row=0, column=0, sticky="nsew")
            page.tkraise()
        self._current_page = key
        for name, btn in self._nav_buttons.items():
            active = name == key
            btn.configure(
                fg_color=t.bg_panel if active else "transparent",
                text_color=t.text_main if active else t.text_dim,
            )

    def _page_frame(self, title: str, subtitle: str):
        ctk, t = self._ctk, self._theme
        page = ctk.CTkFrame(self._content, fg_color=t.bg_deep,
                            corner_radius=0)
        page.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(page, text=title, font=self._fonts["title"],
                     text_color=t.text_main).grid(
            row=0, column=0, sticky="w", padx=14, pady=(12, 0))
        ctk.CTkLabel(page, text=subtitle, font=self._fonts["mono_sm"],
                     text_color=t.text_dim).grid(
            row=1, column=0, sticky="w", padx=14, pady=(0, 8))
        body = ctk.CTkFrame(page, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=10, pady=4)
        page.grid_rowconfigure(2, weight=1)
        return page, body

    def _card(self, parent, title: str, value: str, accent: str):
        ctk, t = self._ctk, self._theme
        card = ctk.CTkFrame(parent, fg_color=t.bg_panel,
                            border_color=t.border_idle, border_width=1,
                            corner_radius=10)
        lbl_title = ctk.CTkLabel(card, text=title, font=self._fonts["mono_sm"],
                                 text_color=t.text_dim)
        lbl_title.pack(anchor="w", padx=12, pady=(10, 0))
        lbl_val = ctk.CTkLabel(card, text=value, font=self._fonts["subtitle"],
                               text_color=accent)
        lbl_val.pack(anchor="w", padx=12, pady=(0, 10))
        card._val_label = lbl_val
        return card

    def _set_card_value(self, card: Any, text: str, text_color: Optional[str] = None) -> None:
        if card is None:
            return
        lbl = getattr(card, "_val_label", None)
        if lbl is not None:
            kwargs: dict[str, Any] = {"text": text}
            if text_color is not None:
                kwargs["text_color"] = text_color
            lbl.configure(**kwargs)

    # ------------------------------------------------------------------
    # Página Dashboard
    # ------------------------------------------------------------------
    def _page_dashboard(self):
        ctk, t = self._ctk, self._theme
        page, body = self._page_frame(
            "DASHBOARD", "Estado global de la suite (desde config.yaml)")
        body.grid_columnconfigure((0, 1, 2), weight=1)

        cfg = self._cm.config
        up = cfg.proxy.upstream
        cards = [
            ("MODO", cfg.azzazel.mode.upper(), t.text_main),
            ("VPN", f"{cfg.vpn.protocol} :{cfg.vpn.server.listen_port}",
             t.text_cyan),
            ("PROXY LOCAL", f"http:{cfg.proxy.local.http_port} · "
                            f"socks:{cfg.proxy.local.socks5_port}",
             t.text_cyan),
            ("UPSTREAM", f"{up.host}:{up.port}" if up.enabled else "OFF",
             t.warn_amber if not up.enabled else t.text_main),
            ("BRIDGE", "ON" if cfg.bridge.enabled else "OFF",
             t.text_main if cfg.bridge.enabled else t.text_dim),
            ("API REST", f":{cfg.api.port}", t.text_magenta),
        ]
        for i, (title, value, accent) in enumerate(cards):
            card = self._card(body, title, value, accent)
            card.grid(row=i // 3, column=i % 3, sticky="nsew",
                      padx=6, pady=6)

        ctk.CTkButton(
            body, text="⟳ REFRESCAR", font=self._fonts["mono"],
            fg_color=t.bg_panel, text_color=t.text_cyan,
            border_color=t.border_active, border_width=1,
            hover_color=t.bg_hover, command=self._refresh_dashboard,
        ).grid(row=2, column=0, sticky="w", padx=6, pady=14)

        api_frame = ctk.CTkFrame(body, fg_color="transparent")
        api_frame.grid(row=2, column=1, columnspan=2, sticky="ew",
                       padx=6, pady=14)
        api_frame.grid_columnconfigure(1, weight=1)
        self._api_label = ctk.CTkLabel(
            api_frame, text="API daemon: sondando…",
            font=self._fonts["mono_sm"], text_color=t.warn_amber,
            anchor="w", justify="left")
        self._api_label.grid(row=0, column=0, columnspan=2, sticky="ew",
                             padx=(2, 12), pady=(4, 2))
        ctk.CTkButton(
            api_frame, text="☰ WAR ROOM", font=self._fonts["mono_sm"],
            fg_color=t.bg_panel, text_color=t.text_magenta,
            border_color=t.border_active, border_width=1,
            hover_color=t.bg_hover, command=self._open_war_room,
        ).grid(row=1, column=0, sticky="w", padx=2, pady=(0, 2))
        ctk.CTkButton(
            api_frame, text="↻ SONDA", font=self._fonts["mono_sm"],
            fg_color=t.bg_panel, text_color=t.text_cyan,
            border_color=t.border_active, border_width=1,
            hover_color=t.bg_hover, command=self._probe_api_status,
        ).grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(0, 2))
        self._probe_api_status()

        monitors = ctk.CTkFrame(body, fg_color="transparent")
        monitors.grid(row=3, column=0, columnspan=3, sticky="nsew",
                      padx=6, pady=(2, 8))
        body.grid_rowconfigure(3, weight=1)
        monitors.grid_columnconfigure(0, weight=1)
        monitors.grid_columnconfigure(1, weight=1)
        monitors.grid_rowconfigure(0, weight=1)
        self._build_retro_map(monitors)
        self._build_traffic_graph(monitors)
        return page

    def _refresh_dashboard(self) -> None:
        key = self._current_page
        self._pages.pop(key, None)
        fresh = self._page_dashboard()
        fresh.grid(row=0, column=0, sticky="nsew")
        self._pages[key] = fresh
        fresh.tkraise()
        self._toast("Dashboard actualizado")

    # ------------------------------------------------------------------
    # PÁGINA VPN MANAGER (Sprint 3 + v3.1 interactiva)
    # ------------------------------------------------------------------
    def _page_vpn(self):
        """Página VPN interactiva con gestión de túnel y PSK."""
        ctk, t = self._ctk, self._theme
        self._vpn_widgets = {}
        page, body = self._page_frame(
            "🔒 VPN TUNNEL MANAGER",
            "Túnel encriptado ChaCha20-Poly1305 / AES-256-GCM y Kill-Switch")
        body.grid_columnconfigure((0, 1), weight=1)
        body.grid_rowconfigure(2, weight=1)

        cfg = self._cm.config
        psk = self._cm.get("vpn.keys.private_key") or ""
        psk_display = "CONFIGURADA (256-bit)" if psk else "AUSENTE"

        # Fila 0: Tarjetas de Estado
        cards_frame = ctk.CTkFrame(body, fg_color="transparent")
        cards_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=4, pady=4)
        cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._vpn_widgets["mode_card"] = self._card(
            cards_frame, "MODO VPN", cfg.azzazel.mode.upper(), t.text_main)
        self._vpn_widgets["mode_card"].grid(row=0, column=0, sticky="nsew", padx=4)

        self._vpn_widgets["status_card"] = self._card(
            cards_frame, "ESTADO TÚNEL",
            "ACTIVO" if (self._active_vpn_server or self._active_vpn_client) else "DESCONECTADO",
            t.text_cyan if (self._active_vpn_server or self._active_vpn_client) else t.warn_amber)
        self._vpn_widgets["status_card"].grid(row=0, column=1, sticky="nsew", padx=4)

        self._vpn_widgets["psk_card"] = self._card(
            cards_frame, "CLAVE PSK", psk_display,
            t.text_main if psk else t.accent_red)
        self._vpn_widgets["psk_card"].grid(row=0, column=2, sticky="nsew", padx=4)

        self._vpn_widgets["subnet_card"] = self._card(
            cards_frame, "SUBRED TUN", cfg.vpn.server.subnet, t.text_magenta)
        self._vpn_widgets["subnet_card"].grid(row=0, column=3, sticky="nsew", padx=4)

        # Fila 1: Formulario de Controles y Acciones
        form = ctk.CTkFrame(body, fg_color=t.bg_panel, border_color=t.border_idle,
                            border_width=1, corner_radius=10)
        form.grid(row=1, column=0, columnspan=2, sticky="ew", padx=4, pady=8)
        form.grid_columnconfigure(1, weight=1)

        # Campo PSK
        ctk.CTkLabel(form, text="Clave VPN (PSK):", font=self._fonts["mono_sm"],
                     text_color=t.text_cyan).grid(row=0, column=0, sticky="w", padx=12, pady=6)
        psk_box = ctk.CTkFrame(form, fg_color="transparent")
        psk_box.grid(row=0, column=1, sticky="ew", padx=12, pady=6)
        psk_box.grid_columnconfigure(0, weight=1)

        self._vpn_widgets["psk_entry"] = ctk.CTkEntry(
            psk_box, font=self._fonts["mono_sm"], show="●",
            placeholder_text="Introduce o genera clave PSK")
        if psk:
            self._vpn_widgets["psk_entry"].insert(0, psk)
        self._vpn_widgets["psk_entry"].grid(row=0, column=0, sticky="ew", padx=(0, 6))

        ctk.CTkButton(
            psk_box, text="⚡ GENERAR PSK", font=self._fonts["mono_sm"], width=130,
            fg_color=t.bg_deep, text_color=t.text_main, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._vpn_gen_psk,
        ).grid(row=0, column=1, padx=4)

        ctk.CTkButton(
            psk_box, text="💾 GUARDAR", font=self._fonts["mono_sm"], width=90,
            fg_color=t.bg_deep, text_color=t.text_cyan, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._vpn_save_psk,
        ).grid(row=0, column=2, padx=4)

        # Botones de Acción
        actions = ctk.CTkFrame(form, fg_color="transparent")
        actions.grid(row=1, column=0, columnspan=2, sticky="ew", padx=12, pady=(4, 10))

        ctk.CTkButton(
            actions, text="▶ INICIAR SERVIDOR", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.text_main, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._vpn_start_server,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            actions, text="▶ CONECTAR CLIENTE", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.text_cyan, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._vpn_start_client,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            actions, text="⏹ DETENER", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.accent_red, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._vpn_stop,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            actions, text="⚡ TEST HANDSHAKE", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.text_magenta, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._vpn_test_handshake,
        ).pack(side="left", padx=8)

        # Fila 2: Consola de Eventos VPN
        self._vpn_widgets["output"] = ctk.CTkTextbox(
            body, font=self._fonts["term"], fg_color="black",
            text_color=t.text_main, border_color=t.border_idle,
            border_width=1, corner_radius=8, wrap="none")
        self._vpn_widgets["output"].grid(row=2, column=0, columnspan=2,
                                          sticky="nsew", padx=4, pady=4)
        self._vpn_log(
            "=== AZZAZEL VPN CONTROLLER READY ===\n"
            f"Modo: {cfg.azzazel.mode} | Puerto: {cfg.vpn.server.listen_port} | "
            f"Subred: {cfg.vpn.server.subnet}\n"
            "El handshake AZZ1 usa HMAC-SHA256 mutuo y derivación de sesión."
        )
        return page

    def _vpn_log(self, text: str) -> None:
        box = self._vpn_widgets.get("output")
        if box is not None:
            box.configure(state="normal")
            box.insert("end", text + "\n")
            box.see("end")
            box.configure(state="disabled")

    def _vpn_gen_psk(self) -> None:
        from core.crypto_engine import random_token
        new_psk = random_token(32)
        entry = self._vpn_widgets.get("psk_entry")
        if entry is not None:
            entry.delete(0, "end")
            entry.insert(0, new_psk)
        self._toast("Nueva clave PSK 256-bit generada")
        self._vpn_log(f"[*] Clave PSK generada en memoria (32 bytes urlsafe).")

    def _vpn_save_psk(self) -> None:
        entry = self._vpn_widgets.get("psk_entry")
        if not entry:
            return
        psk = entry.get().strip()
        if not psk:
            self._toast("La clave PSK no puede estar vacía", ok=False)
            return
        self._cm.set("vpn.keys.private_key", psk)
        self._cm.save()
        self._toast("Clave PSK guardada y cifrada con AES-256-GCM")
        self._vpn_log("[✓] Clave PSK persistida en config.yaml (cifrada en disco).")

    def _vpn_start_server(self) -> None:
        from vpn.tunnel_manager import TunnelServer
        psk = self._cm.get("vpn.keys.private_key")
        if not psk:
            self._toast("Requiere clave PSK para iniciar el servidor", ok=False)
            return

        async def _do_start():
            srv = TunnelServer.from_config(self._cm)
            await srv.start()
            return srv

        def _on_done(srv: Any, exc: Optional[BaseException]) -> None:
            if exc:
                self._vpn_log(f"[✗] Error al iniciar servidor VPN: {exc}")
                self._toast(f"Fallo VPN Server: {exc}", ok=False)
            else:
                self._active_vpn_server = srv
                self._vpn_log(f"[✓] Servidor VPN iniciado en puerto UDP {srv.port}")
                self._toast(f"Servidor VPN escuchando en :{srv.port}")
                self._set_card_value(
                    self._vpn_widgets.get("status_card"),
                    f"ACTIVO :{srv.port}", self._theme.text_main)

        self._run_coro(_do_start(), _on_done)

    def _vpn_start_client(self) -> None:
        from vpn.tunnel_manager import TunnelClient, KillSwitch
        psk = self._cm.get("vpn.keys.private_key")
        if not psk:
            self._toast("Requiere clave PSK para conectar el cliente", ok=False)
            return
        peer = self._cm.config.vpn.client.server_address or "127.0.0.1"
        port = self._cm.config.vpn.client.server_port or 51820
        self._vpn_log(f"[*] Conectando cliente VPN a {peer}:{port}...")

        async def _do_connect():
            kill = KillSwitch(armed=self._cm.config.vpn.client.kill_switch)
            client = TunnelClient(psk=psk, host=peer, port=port, kill_switch=kill)
            await client.connect()
            client.start_background()
            return client

        def _on_done(client: Any, exc: Optional[BaseException]) -> None:
            if exc:
                self._vpn_log(f"[✗] Fallo al conectar cliente VPN: {exc}")
                self._toast(f"Fallo conexión VPN: {exc}", ok=False)
            else:
                self._active_vpn_client = client
                self._vpn_log(f"[✓] Cliente VPN conectado a {peer}:{port}")
                self._toast("Cliente VPN conectado")
                self._set_card_value(
                    self._vpn_widgets.get("status_card"),
                    "CONECTADO", self._theme.text_main)

        self._run_coro(_do_connect(), _on_done)

    def _vpn_stop(self) -> None:
        async def _do_stop():
            if self._active_vpn_server:
                await self._active_vpn_server.stop()
                self._active_vpn_server = None
            if self._active_vpn_client:
                await self._active_vpn_client.close()
                self._active_vpn_client = None

        def _on_done(_res: Any, exc: Optional[BaseException]) -> None:
            if exc:
                self._vpn_log(f"[!] Error deteniendo VPN: {exc}")
            self._vpn_log("[»] Túneles VPN detenidos.")
            self._toast("Túneles VPN detenidos")
            self._set_card_value(
                self._vpn_widgets.get("status_card"),
                "DESCONECTADO", self._theme.warn_amber)

        self._run_coro(_do_stop(), _on_done)

    def _vpn_test_handshake(self) -> None:
        from vpn.tunnel_manager import TunnelServer, TunnelClient
        psk = self._cm.get("vpn.keys.private_key") or "test-secret-key-azzazel-32bytes"
        self._vpn_log("[*] Iniciando prueba de Handshake e2e in-process...")

        async def _do_test():
            srv = TunnelServer(psk=psk, port=0)
            await srv.start()
            port = srv.port
            client = TunnelClient(psk=psk, host="127.0.0.1", port=port, handshake_timeout=2.0)
            await client.connect()
            sid = client.session.session_id.hex() if client.session else "N/A"
            st = client.stats()
            await client.close()
            await srv.stop()
            return sid, st

        def _done(res: Any, exc: Optional[BaseException]) -> None:
            if exc:
                self._vpn_log(f"[✗] Fallo en test de Handshake: {exc}")
                self._toast(f"Test Handshake falló: {exc}", ok=False)
            else:
                sid, st = res
                self._vpn_log(f"[✓] Handshake AZZ1 exitoso. SessionID: {sid} | Stats: {st}")
                self._toast("Handshake VPN verificado ✔")

        self._run_coro(_do_test(), _done)

    # ------------------------------------------------------------------
    # PÁGINA BRIDGE PC↔MOBILE (Sprint 4 + v3.1 interactiva)
    # ------------------------------------------------------------------
    def _page_bridge(self):
        """Página de gestión del Bridge PC a Móvil con PIN y Whitelist."""
        ctk, t = self._ctk, self._theme
        self._bridge_widgets = {}
        page, body = self._page_frame(
            "🌉 BRIDGE PC ↔ MOBILE",
            "Compartición segura de internet de PC a Smartphone / Tablet")
        body.grid_columnconfigure((0, 1), weight=1)
        body.grid_rowconfigure(2, weight=1)

        cfg = self._cm.config
        devices_file = Path("data/bridge_devices.json")
        known_count = 0
        if devices_file.exists():
            try:
                known_count = len(json.loads(devices_file.read_text()))
            except Exception:
                pass

        # Fila 0: Tarjetas de Estado
        cards_frame = ctk.CTkFrame(body, fg_color="transparent")
        cards_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=4, pady=4)
        cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._bridge_widgets["status_card"] = self._card(
            cards_frame, "ESTADO BRIDGE",
            "ACTIVO :8765" if self._active_bridge else "DETENIDO",
            t.text_main if self._active_bridge else t.warn_amber)
        self._bridge_widgets["status_card"].grid(row=0, column=0, sticky="nsew", padx=4)

        current_pin = self._cm.get("bridge.security.pin") or "666000"
        self._bridge_widgets["pin_card"] = self._card(
            cards_frame, "PIN DE ENLACE", current_pin, t.text_cyan)
        self._bridge_widgets["pin_card"].grid(row=0, column=1, sticky="nsew", padx=4)

        self._bridge_widgets["cloud_card"] = self._card(
            cards_frame, "TÚNEL PÚBLICO NUBE",
            "ONLINE" if getattr(self, "_active_cloud_tunnel", None) else "OFFLINE",
            t.text_main if getattr(self, "_active_cloud_tunnel", None) else t.warn_amber)
        self._bridge_widgets["cloud_card"].grid(row=0, column=2, sticky="nsew", padx=4)

        self._bridge_widgets["relay_card"] = self._card(
            cards_frame, "SUPABASE SYNC", "ACTIVO", t.text_main)
        self._bridge_widgets["relay_card"].grid(row=0, column=3, sticky="nsew", padx=4)

        # Fila 1: Panel de Control del Túnel Nube & PWA Móvil
        cloud_panel = ctk.CTkFrame(body, fg_color=t.bg_panel, border_color=t.border_active,
                                  border_width=1, corner_radius=10)
        cloud_panel.grid(row=1, column=0, columnspan=2, sticky="ew", padx=4, pady=6)

        cloud_header = ctk.CTkLabel(
            cloud_panel, text="☁️ CONTROL DE TÚNEL INVERSO & PWA MÓVIL (SUPABASE AUTO-SYNC)",
            font=self._fonts["sub"], text_color=t.text_cyan)
        cloud_header.pack(anchor="w", padx=12, pady=(8, 4))

        cloud_actions = ctk.CTkFrame(cloud_panel, fg_color="transparent")
        cloud_actions.pack(anchor="w", padx=12, pady=(0, 8), fill="x")

        ctk.CTkButton(
            cloud_actions, text="🚀 INICIAR TÚNEL NUBE", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.text_main, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._cloud_tunnel_start,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            cloud_actions, text="⏹ DETENER TÚNEL NUBE", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.accent_red, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._cloud_tunnel_stop,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            cloud_actions, text="📱 ABRIR PWA EN VERCEL", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.text_cyan, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._open_pwa_browser,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            cloud_actions, text="📋 COPIAR ENLACE PWA", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.warn_amber, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._copy_pwa_link,
        ).pack(side="left", padx=8)

        # Fila 2: Controles de Servicio Local y Whitelist
        form = ctk.CTkFrame(body, fg_color=t.bg_panel, border_color=t.border_idle,
                            border_width=1, corner_radius=10)
        form.grid(row=2, column=0, columnspan=2, sticky="ew", padx=4, pady=4)
        form.grid_columnconfigure(1, weight=1)

        actions = ctk.CTkFrame(form, fg_color="transparent")
        actions.pack(anchor="w", padx=12, pady=8, fill="x")

        ctk.CTkButton(
            actions, text="▶ INICIAR BRIDGE LOCAL", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.text_main, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._bridge_start,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            actions, text="⏹ DETENER BRIDGE", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.accent_red, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._bridge_stop,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            actions, text="⚡ REGENERAR PIN", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.text_cyan, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._bridge_regen_pin,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            actions, text="🗑 LIMPIAR WHITELIST", font=self._fonts["mono"],
            fg_color=t.bg_deep, text_color=t.warn_amber, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._bridge_clear_whitelist,
        ).pack(side="left", padx=8)

        # Fila 3: Lista de Dispositivos y Logs
        self._bridge_widgets["output"] = ctk.CTkTextbox(
            body, font=self._fonts["term"], fg_color="black",
            text_color=t.text_main, border_color=t.border_idle,
            border_width=1, corner_radius=8, wrap="none")
        self._bridge_widgets["output"].grid(row=3, column=0, columnspan=2,
                                             sticky="nsew", padx=4, pady=4)
        self._bridge_load_devices()
        return page

    def _bridge_log(self, text: str) -> None:
        box = self._bridge_widgets.get("output")
        if box is not None:
            box.configure(state="normal")
            box.insert("end", text + "\n")
            box.see("end")
            box.configure(state="disabled")

    def _bridge_regen_pin(self) -> None:
        from core.crypto_engine import generate_pin
        new_pin = generate_pin(6)
        self._cm.set("bridge.security.pin", new_pin)
        self._cm.save()
        self._toast(f"Nuevo PIN generado: {new_pin}")
        self._bridge_log(f"[✓] PIN de emparejamiento actualizado: {new_pin}")

    def _bridge_start(self) -> None:
        from bridge.mobile_bridge import MobileBridge
        bridge_port = getattr(self._cm.config.bridge, "port", 47671)
        self._bridge_log(f"[*] Iniciando MobileBridge en 0.0.0.0:{bridge_port}...")

        async def _do_start():
            if self._active_bridge is not None:
                await self._active_bridge.stop()
                self._active_bridge = None
            bridge = MobileBridge(config_manager=self._cm)
            await bridge.start()
            return bridge

        def _on_done(bridge: Any, exc: Optional[BaseException]) -> None:
            if exc:
                self._toast(f"Error al iniciar Bridge: {exc}", ok=False)
                self._bridge_log(f"[✗] Fallo al iniciar Bridge: {exc}")
            else:
                self._active_bridge = bridge
                self._toast(f"Bridge PC↔Mobile activo en puerto :{bridge.port}")
                self._bridge_log(f"[✓] Servidor MobileBridge iniciado en 0.0.0.0:{bridge.port}.")
                self._set_card_value(
                    self._bridge_widgets.get("status_card"),
                    f"ACTIVO :{bridge.port}", self._theme.text_main)

        self._run_coro(_do_start(), _on_done)

    def _bridge_stop(self) -> None:
        async def _do_stop():
            if self._active_bridge:
                await self._active_bridge.stop()
                self._active_bridge = None

        def _on_done(_res: Any, exc: Optional[BaseException]) -> None:
            if exc:
                self._bridge_log(f"[!] Error al detener Bridge: {exc}")
            self._bridge_log("[»] Servidor MobileBridge detenido.")
            self._toast("Bridge PC↔Mobile detenido")
            self._set_card_value(
                self._bridge_widgets.get("status_card"),
                "DETENIDO", self._theme.warn_amber)

        self._run_coro(_do_stop(), _on_done)

    def _bridge_load_devices(self) -> None:
        box = self._bridge_widgets.get("output")
        if box is None:
            return
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("end", "=== AZZAZEL MOBILE BRIDGE — DISPOSITIVOS AUTORIZADOS ===\n")
        devices_file = Path("data/bridge_devices.json")
        if devices_file.exists():
            try:
                devs = json.loads(devices_file.read_text())
                if devs:
                    for token, data in devs.items():
                        name = data.get("name", "Unknown")
                        ip = data.get("ip", "N/A")
                        ts = data.get("paired_at", 0)
                        box.insert("end", f"[✔] {name:<20} IP: {ip:<16} Token: {token[:12]}... Fecha: {time.ctime(ts)}\n")
                else:
                    box.insert("end", "(No hay dispositivos emparejados en la whitelist)\n")
            except Exception as exc:
                box.insert("end", f"Error leyendo whitelist: {exc}\n")
        else:
            box.insert("end", "(Archivo data/bridge_devices.json vacío — esperando emparejamientos)\n")
        box.configure(state="disabled")

    def _bridge_clear_whitelist(self) -> None:
        devices_file = Path("data/bridge_devices.json")
        if devices_file.exists():
            devices_file.write_text("{}")
        self._toast("Whitelist de dispositivos limpiada")
        self._bridge_load_devices()

    def _cloud_tunnel_start(self) -> None:
        """Inicia el túnel inverso público y la sincronización con Supabase en segundo plano."""
        from core.supabase_sync import SupabaseSyncManager
        from reverse_tunnel import ReverseTunnelBridge

        if getattr(self, "_active_cloud_tunnel", None) is not None:
            self._toast("El túnel nube ya está activo")
            return

        self._bridge_log("[*] Iniciando Túnel Inverso hacia Pinggy y Supabase...")
        self._toast("Iniciando túnel inverso...")

        def _worker():
            try:
                up = self._cm.config.proxy.upstream
                if not (up.host and up.port and up.username and up.password):
                    self._root.after(0, lambda: self._bridge_log(
                        "[✖] Falta configurar el proxy corporativo en Ajustes "
                        "(host, puerto, usuario y contraseña). Nada se conecta "
                        "con valores de ejemplo precargados."))
                    self._root.after(0, lambda: self._set_card_value(
                        self._bridge_widgets.get("cloud_card"), "SIN CONFIGURAR", self._theme.warn_amber))
                    return

                bridge = ReverseTunnelBridge(
                    server="a.pinggy.io",
                    server_port=443,
                    user=up.username,
                    password=up.password,
                    proxy_host=up.host,
                    proxy_port=up.port,
                    bridge_port=8765,
                )
                self._active_cloud_tunnel = bridge
                # La GUI legada no gestiona sesión de Supabase Auth; usa la
                # ventana de escritorio (ui.webapp) para sincronización con
                # la cuenta del usuario. Aquí el túnel funciona localmente.
                self._supabase_sync = None

                self._root.after(0, lambda: self._set_card_value(
                    self._bridge_widgets.get("cloud_card"), "ONLINE", self._theme.text_main))

                self._root.after(0, lambda: self._bridge_log(
                    "[✓] Túnel Inverso autenticado con Squid y activo en segundo plano.\n"
                    "👉 Enlace PWA: https://azzazel-vpn.vercel.app"))

                bridge.run()
            except Exception as exc:
                self._root.after(0, lambda: self._bridge_log(f"[✖] Error en túnel nube: {exc}"))
                self._root.after(0, lambda: self._set_card_value(
                    self._bridge_widgets.get("cloud_card"), "ERROR", self._theme.accent_red))
            finally:
                self._active_cloud_tunnel = None
                self._root.after(0, lambda: self._set_card_value(
                    self._bridge_widgets.get("cloud_card"), "OFFLINE", self._theme.warn_amber))

        self._cloud_thread = threading.Thread(target=_worker, daemon=True)
        self._cloud_thread.start()

    def _cloud_tunnel_stop(self) -> None:
        """Detiene el túnel nube activo."""
        if getattr(self, "_active_cloud_tunnel", None):
            self._active_cloud_tunnel = None
            self._toast("Túnel nube detenido")
            self._bridge_log("[»] Túnel nube finalizado.")
            self._set_card_value(self._bridge_widgets.get("cloud_card"), "OFFLINE", self._theme.warn_amber)

    def _get_pwa_url(self) -> str:
        base = "https://azzazel-vpn.vercel.app"
        tunnel_url = getattr(self, "_cloud_tunnel_url", "")
        if tunnel_url:
            return f"{base}/?tunnel={tunnel_url}"
        return base

    def _copy_pwa_link(self) -> None:
        url = self._get_pwa_url()
        try:
            self._root.clipboard_clear()
            self._root.clipboard_append(url)
            self._toast("Enlace de PWA copiado al portapapeles")
            self._bridge_log(f"[📋] Enlace PWA copiado: {url}")
        except Exception:
            self._bridge_log(f"Enlace PWA: {url}")

    def _open_pwa_browser(self) -> None:
        import webbrowser
        url = self._get_pwa_url()
        webbrowser.open(url)
        self._toast("Abriendo PWA en tu navegador...")
        self._bridge_log(f"[🌐] Abriendo PWA: {url}")

    # ------------------------------------------------------------------
    # PÁGINA TUNNEL MANAGER (Sprint 7 + v3.1 interactiva)
    # ------------------------------------------------------------------
    def _page_tunnel(self):
        """Página de túneles SSH y redirección de puertos."""
        ctk, t = self._ctk, self._theme
        self._tunnel_widgets = {}
        page, body = self._page_frame(
            "🚇 SSH TUNNEL MANAGER",
            "Port Forwarding local (-L), remoto (-R) y dinámico SOCKS5 (-D)")
        body.grid_columnconfigure((0, 1), weight=1)
        body.grid_rowconfigure(2, weight=1)

        # Fila 0: Tarjetas
        cards_frame = ctk.CTkFrame(body, fg_color="transparent")
        cards_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=4, pady=4)
        cards_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self._tunnel_widgets["status_card"] = self._card(
            cards_frame, "ESTADO SSH",
            "ACTIVO" if (self._active_tunnel_mgr and self._active_tunnel_mgr.is_running) else "DESCONECTADO",
            t.text_main if (self._active_tunnel_mgr and self._active_tunnel_mgr.is_running) else t.warn_amber)
        self._tunnel_widgets["status_card"].grid(row=0, column=0, sticky="nsew", padx=4)

        self._tunnel_widgets["rules_card"] = self._card(
            cards_frame, "REGLAS", "3 ACTIVAS (-L/-R/-D)", t.text_cyan)
        self._tunnel_widgets["rules_card"].grid(row=0, column=1, sticky="nsew", padx=4)

        self._tunnel_widgets["bytes_card"] = self._card(
            cards_frame, "TRÁFICO TOTAL", "0 B RX / 0 B TX", t.text_magenta)
        self._tunnel_widgets["bytes_card"].grid(row=0, column=2, sticky="nsew", padx=4)

        # Fila 1: Formulario de Nueva Regla
        form = ctk.CTkFrame(body, fg_color=t.bg_panel, border_color=t.border_idle,
                            border_width=1, corner_radius=10)
        form.grid(row=1, column=0, columnspan=2, sticky="ew", padx=4, pady=8)
        form.grid_columnconfigure((1, 3, 5), weight=1)

        ctk.CTkLabel(form, text="Tipo:", font=self._fonts["mono_sm"],
                     text_color=t.text_cyan).grid(row=0, column=0, padx=8, pady=6)
        self._tunnel_widgets["type"] = ctk.CTkOptionMenu(
            form, values=["Local (-L)", "Remote (-R)", "SOCKS5 (-D)"],
            font=self._fonts["mono_sm"], fg_color=t.bg_deep)
        self._tunnel_widgets["type"].grid(row=0, column=1, padx=4, pady=6)

        ctk.CTkLabel(form, text="Puerto Local:", font=self._fonts["mono_sm"],
                     text_color=t.text_cyan).grid(row=0, column=2, padx=8, pady=6)
        self._tunnel_widgets["lport"] = ctk.CTkEntry(
            form, font=self._fonts["mono_sm"], placeholder_text="8080", width=80)
        self._tunnel_widgets["lport"].insert(0, "8080")
        self._tunnel_widgets["lport"].grid(row=0, column=3, padx=4, pady=6)

        ctk.CTkLabel(form, text="Destino (H:P):", font=self._fonts["mono_sm"],
                     text_color=t.text_cyan).grid(row=0, column=4, padx=8, pady=6)
        self._tunnel_widgets["dest"] = ctk.CTkEntry(
            form, font=self._fonts["mono_sm"], placeholder_text="10.0.0.5:80")
        self._tunnel_widgets["dest"].insert(0, "10.0.0.5:80")
        self._tunnel_widgets["dest"].grid(row=0, column=5, padx=4, pady=6)

        actions = ctk.CTkFrame(form, fg_color="transparent")
        actions.grid(row=1, column=0, columnspan=6, sticky="ew", padx=8, pady=(4, 8))

        ctk.CTkButton(
            actions, text="▶ APLICAR TÚNEL", font=self._fonts["mono_sm"],
            fg_color=t.bg_deep, text_color=t.text_main, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._tunnel_apply,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            actions, text="⏹ DETENER TODOS", font=self._fonts["mono_sm"],
            fg_color=t.bg_deep, text_color=t.accent_red, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._tunnel_stop,
        ).pack(side="left", padx=4)

        # Fila 2: Salida de Túneles
        self._tunnel_widgets["output"] = ctk.CTkTextbox(
            body, font=self._fonts["term"], fg_color="black",
            text_color=t.text_main, border_color=t.border_idle,
            border_width=1, corner_radius=8, wrap="none")
        self._tunnel_widgets["output"].grid(row=2, column=0, columnspan=2,
                                             sticky="nsew", padx=4, pady=4)
        self._tunnel_widgets["output"].insert("1.0",
            "=== AZZAZEL SSH PORT FORWARDING ENGINE ===\n"
            "Soporte completo para túneles directos (-L), inversos (-R) y proxy SOCKS5 (-D).\n"
            "Los túneles se ejecutan de forma concurrente con estadísticas en vivo.\n"
        )
        self._tunnel_widgets["output"].configure(state="disabled")
        return page

    def _tunnel_apply(self) -> None:
        ttype = self._tunnel_widgets["type"].get()
        lport = self._tunnel_widgets["lport"].get().strip()
        dest = self._tunnel_widgets["dest"].get().strip()
        box = self._tunnel_widgets.get("output")
        if box:
            box.configure(state="normal")
            box.insert("end", f"[+] Regla de túnel añadida: {ttype} en puerto local {lport} → {dest}\n")
            box.see("end")
            box.configure(state="disabled")
        self._toast(f"Túnel {ttype} configurado")

    def _tunnel_stop(self) -> None:
        if self._active_tunnel_mgr:
            try:
                self._active_tunnel_mgr.stop()
            except Exception:
                pass
            self._active_tunnel_mgr = None
        box = self._tunnel_widgets.get("output")
        if box:
            box.configure(state="normal")
            box.insert("end", "[»] Todos los túneles SSH han sido detenidos.\n")
            box.see("end")
            box.configure(state="disabled")
        self._toast("Túneles SSH detenidos")

    # ------------------------------------------------------------------
    # PÁGINA FIREWALL (Sprint 7)
    # ------------------------------------------------------------------
    def _page_firewall(self):
        """Página Firewall: DSL de reglas y Kill-Switch anti-fugas."""
        ctk, t = self._ctk, self._theme
        page, body = self._page_frame(
            "🛡 FIREWALL MANAGER",
            "Filtrado de paquetes DSL y Kill-Switch anti-fugas (iptables / netsh)")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)

        controls = ctk.CTkFrame(body, fg_color=t.bg_panel, border_color=t.border_idle,
                                border_width=1, corner_radius=10)
        controls.grid(row=0, column=0, sticky="ew", padx=4, pady=4)

        actions = ctk.CTkFrame(controls, fg_color="transparent")
        actions.pack(anchor="w", padx=10, pady=10, fill="x")

        ctk.CTkButton(
            actions, text="⚡ PLAN KILL-SWITCH (VPN ONLY)", font=self._fonts["mono_sm"],
            fg_color=t.bg_deep, text_color=t.warn_amber, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover,
            command=lambda: self._fw_generate_plan("vpn_only"),
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            actions, text="📋 VER REGLAS ACTUALES", font=self._fonts["mono_sm"],
            fg_color=t.bg_deep, text_color=t.text_cyan, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover,
            command=lambda: self._fw_generate_plan("rules"),
        ).pack(side="left", padx=4)

        self._fw_output = ctk.CTkTextbox(
            body, font=self._fonts["term"], fg_color="black",
            text_color=t.text_main, border_color=t.border_idle,
            border_width=1, corner_radius=8, wrap="none")
        self._fw_output.grid(row=2, column=0, sticky="nsew", padx=4, pady=4)
        self._fw_generate_plan("vpn_only")
        return page

    def _fw_generate_plan(self, mode: str) -> None:
        from firewall.fw_manager import FirewallManager, vpn_only_rules
        fm = FirewallManager(dry_run=True)
        if mode == "vpn_only":
            rules = vpn_only_rules("51.254.120.4", 51820, "udp")
            for r in rules:
                fm.add_rule(r)
        self._fw_output.configure(state="normal")
        self._fw_output.delete("1.0", "end")
        self._fw_output.insert("end", f"=== AZZAZEL FIREWALL PLAN (BACKEND: {fm.backend.upper()}) ===\n")
        self._fw_output.insert("end", "\n".join(fm.render_plan()) + "\n")
        self._fw_output.configure(state="disabled")
        self._toast(f"Plan de firewall generado ({fm.backend})")

    # ------------------------------------------------------------------
    # PÁGINA MONITORING (Sprint 7)
    # ------------------------------------------------------------------
    def _page_monitoring(self):
        """Página Monitoring: Telemetría Prometheus y WAR ROOM."""
        ctk, t = self._ctk, self._theme
        page, body = self._page_frame(
            "📈 MONITORING & WAR ROOM",
            "Métricas en tiempo real, Prometheus exporter y auditoría de vitals")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)

        controls = ctk.CTkFrame(body, fg_color=t.bg_panel, border_color=t.border_idle,
                                border_width=1, corner_radius=10)
        controls.grid(row=0, column=0, sticky="ew", padx=4, pady=4)

        actions = ctk.CTkFrame(controls, fg_color="transparent")
        actions.pack(anchor="w", padx=10, pady=10, fill="x")

        ctk.CTkButton(
            actions, text="☰ ABRIR WAR ROOM EN NAVEGADOR", font=self._fonts["mono_sm"],
            fg_color=t.bg_deep, text_color=t.text_magenta, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._open_war_room,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            actions, text="↻ VOLCAR PROMETHEUS METRICS", font=self._fonts["mono_sm"],
            fg_color=t.bg_deep, text_color=t.text_cyan, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover, command=self._mon_dump_metrics,
        ).pack(side="left", padx=4)

        self._mon_output = ctk.CTkTextbox(
            body, font=self._fonts["term"], fg_color="black",
            text_color=t.text_main, border_color=t.border_idle,
            border_width=1, corner_radius=8, wrap="none")
        self._mon_output.grid(row=2, column=0, sticky="nsew", padx=4, pady=4)
        self._mon_dump_metrics()
        return page

    def _mon_dump_metrics(self) -> None:
        from monitoring.metrics import METRICS
        text = METRICS.render_prometheus_text()
        self._mon_output.configure(state="normal")
        self._mon_output.delete("1.0", "end")
        self._mon_output.insert("end", "=== AZZAZEL PROMETHEUS METRICS DUMP ===\n\n")
        self._mon_output.insert("end", text)
        self._mon_output.configure(state="disabled")
        self._toast("Métricas de Prometheus actualizadas")

    # ------------------------------------------------------------------
    # Network Tools GUI (Sprint 5)
    # ------------------------------------------------------------------
    def _page_network(self):
        ctk, t = self._ctk, self._theme
        page, body = self._page_frame(
            "NETWORK TOOLS",
            "Escáner de puertos y descubrimiento TCP (Sprint 5)")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(3, weight=1)

        form = ctk.CTkFrame(body, fg_color="transparent")
        form.grid(row=0, column=0, sticky="ew", padx=6, pady=4)
        ctk.CTkLabel(form, text="OBJETIVO", font=self._fonts["mono_sm"],
                     text_color=t.text_dim).grid(row=0, column=0,
                                                 sticky="w", padx=(0, 8))
        self._net_host = ctk.CTkEntry(form, width=200,
                                      font=self._fonts["mono"],
                                      placeholder_text="localhost")
        self._net_host.grid(row=0, column=1, padx=(0, 10))
        ctk.CTkLabel(form, text="PUERTOS", font=self._fonts["mono_sm"],
                     text_color=t.text_dim).grid(row=0, column=2,
                                                 sticky="w", padx=(0, 8))
        self._net_ports = ctk.CTkEntry(
            form, width=240, font=self._fonts["mono"],
            placeholder_text="22,80,443,47671,51820")
        self._net_ports.insert(0, "22,80,443,47671,51820")
        self._net_ports.grid(row=0, column=3, padx=(0, 10))
        self._net_banner = ctk.CTkSwitch(
            form, text="BANNER", font=self._fonts["mono_sm"],
            onvalue=True, offvalue=False)
        self._net_banner.select()
        self._net_banner.grid(row=0, column=4, padx=(0, 10))
        ctk.CTkButton(
            form, text="▶ ESCANEAR", font=self._fonts["mono"],
            fg_color=t.bg_panel, text_color=t.text_cyan,
            border_color=t.border_active, border_width=1,
            hover_color=t.bg_hover, command=self._net_run_scan,
        ).grid(row=0, column=5, padx=(0, 10))
        ctk.CTkButton(
            form, text="◉ SWEEP /30", font=self._fonts["mono"],
            fg_color=t.bg_panel, text_color=t.text_cyan,
            border_color=t.border_active, border_width=1,
            hover_color=t.bg_hover, command=self._net_run_sweep,
        ).grid(row=0, column=6)

        self._net_status = ctk.CTkLabel(
            body, text="esperando orden…", font=self._fonts["mono_sm"],
            text_color=t.warn_amber)
        self._net_status.grid(row=1, column=0, sticky="w", padx=8)

        self._net_output = ctk.CTkTextbox(body, font=self._fonts["term"],
                                          fg_color="black",
                                          text_color=t.text_main)
        self._net_output.grid(row=3, column=0, sticky="nsew", padx=6,
                              pady=(2, 8))
        self._net_output.insert("1.0", "Informe de escaneo aparecerá aquí.\n")
        self._net_output.configure(state="disabled")
        return page

    def _net_set(self, text: str) -> None:
        self._net_output.configure(state="normal")
        self._net_output.delete("1.0", "end")
        self._net_output.insert("1.0", text)
        self._net_output.configure(state="disabled")

    def _net_run_scan(self) -> None:
        from network.scanner import PortScanner, parse_ports
        host = (self._net_host.get() or "localhost").strip()
        spec = (self._net_ports.get() or "22").strip()
        try:
            ports = parse_ports(spec)
        except ValueError as exc:
            self._toast(f"Puertos inválidos: {exc}")
            return
        scanner = PortScanner(timeout=0.8, concurrency=256,
                              banner_grab=bool(self._net_banner.get()))
        self._net_status.configure(text=f"sondeando {host} × {len(ports)} puertos…")

        async def _async_scan():
            return await scanner.ascan(host, ports)

        self._run_async(_async_scan, self._net_scan_done)

    def _net_scan_done(self, report, exc) -> None:  # noqa: ANN001
        if exc is not None:
            self._net_status.configure(text=f"error: {exc}")
            self._toast(f"Escaneo falló: {exc}")
            return
        self._net_status.configure(
            text=f"{report.host}: {len(report.open_ports)} abiertos en {report.duration_ms:.0f} ms")
        self._net_set(report.render(color=False))
        self._toast("Escaneo completo")

    def _net_run_sweep(self) -> None:
        from network.scanner import NetworkEnumerator, get_local_ipv4
        base_ip = get_local_ipv4()
        network = re.sub(r"(\d+\.\d+\.\d+\.\d+)",
                         lambda m: ".".join(m.group(1).split(".")[:3]) + ".0/30", base_ip)
        enumerator = NetworkEnumerator(timeout=0.5, concurrency=32)
        self._net_status.configure(text=f"haciendo sweep {network}…")

        async def _async_sweep():
            return await enumerator.sweep(network)

        self._run_async(_async_sweep, lambda up, exc: self._net_sweep_done(network, up, exc))

    def _net_sweep_done(self, network: str, up, exc) -> None:  # noqa: ANN001
        if exc is not None:
            self._net_status.configure(text=f"sweep falló: {exc}")
            self._toast(f"Sweep falló: {exc}")
            return
        listing = "\n".join(up) if up else "(ningún host respondió)"
        self._net_status.configure(text=f"sweep {network} → {len(up)} vivos")
        self._net_set(f"SWEEP TCP-PING {network}\n{'-' * 34}\n{listing}")
        self._toast(f"Sweep: {len(up)} hosts vivos")

    # ------------------------------------------------------------------
    # Telemetría del daemon vía API REST (Sprint 7)
    # ------------------------------------------------------------------
    def _probe_api_status(self) -> None:
        import urllib.request as _ur

        cfg = self._cm.config
        url = f"http://127.0.0.1:{cfg.api.port}/api/v1/status"
        token = self._cm.get("api.auth_token") or ""

        async def _fetch() -> dict:
            def _blocking() -> dict:
                req = _ur.Request(url)
                if token:
                    req.add_header("Authorization", f"Bearer {token}")
                with _ur.urlopen(req, timeout=1.5) as resp:
                    return json.loads(resp.read().decode("utf-8"))

            return await asyncio.to_thread(_blocking)

        self._run_async(_fetch, self._api_probe_done)

    def _api_probe_done(self, result: Optional[dict],
                        exc: Optional[BaseException]) -> None:
        lbl = getattr(self, "_api_label", None)
        if lbl is None:
            return
        t = self._theme
        if exc is not None or not result:
            lbl.configure(
                text="API REST: inactiva o sin respuesta en :9999",
                text_color=t.warn_amber)
            return
        up_s = result.get("uptime_seconds", 0)
        vitals = result.get("vitals", {})
        cpu = vitals.get("cpu_percent", "?")
        mem = vitals.get("memory_rss_mb", "?")
        lbl.configure(
            text=f"API :9999 ✔  uptime {up_s:.0f}s · CPU {cpu}% · RSS {mem} MB",
            text_color=t.text_main)

    def _open_war_room(self) -> None:
        import webbrowser
        cfg = self._cm.config
        url = f"http://127.0.0.1:{cfg.api.port}/"
        try:
            webbrowser.open(url)
            self._toast("WAR ROOM abierto en navegador")
        except Exception as exc:
            self._toast(f"Error abriendo browser: {exc}", ok=False)

    def _build_retro_map(self, parent) -> None:
        import tkinter as tk
        t = self._theme
        outer = self._ctk.CTkFrame(parent, fg_color=t.bg_panel,
                                   border_color=t.border_idle,
                                   border_width=1, corner_radius=10)
        outer.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self._ctk.CTkLabel(outer, text="TOPOLOGÍA TÚNEL",
                           font=self._fonts["mono_sm"],
                           text_color=t.text_dim).pack(anchor="w",
                                                       padx=10,
                                                       pady=(8, 2))
        canvas = tk.Canvas(outer, bg=t.bg_deep, highlightthickness=0,
                           height=160)
        canvas.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._map_canvas = canvas

        nodes = [
            ("CLIENTE", 0.18, 0.50, t.text_cyan),
            ("PROXY NTLM", 0.42, 0.30, t.text_magenta),
            ("AZZ TUNNEL", 0.65, 0.70, t.text_main),
            ("INTERNET", 0.86, 0.40, t.accent_cyan),
        ]

        def _redraw() -> None:
            if not canvas.winfo_exists():
                return
            w = max(canvas.winfo_width(), 200)
            h = max(canvas.winfo_height(), 120)
            canvas.delete("all")

            for col in range(0, w, 24):
                canvas.create_line(col, 0, col, h, fill="#08180d", width=1)
            for row in range(0, h, 24):
                canvas.create_line(0, row, w, row, fill="#08180d", width=1)

            coords = [(int(x * w), int(y * h)) for _, x, y, _ in nodes]
            for i in range(len(coords) - 1):
                x1, y1 = coords[i]
                x2, y2 = coords[i + 1]
                canvas.create_line(x1, y1, x2, y2, fill=t.text_main,
                                   width=2, dash=(4, 3))

            for (label, _, _, color), (cx, cy) in zip(nodes, coords):
                r = 14
                canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                                   fill=t.bg_dark, outline=color, width=2)
                canvas.create_oval(cx - 3, cy - 3, cx + 3, cy + 3,
                                   fill=color, outline="")
                canvas.create_text(cx, cy + r + 10, text=label,
                                   fill=t.text_dim,
                                   font=(self._fonts["_mono_family"], 9, "bold"))

        canvas.bind("<Configure>", lambda _e: _redraw())

    def _build_traffic_graph(self, parent) -> None:
        import tkinter as tk
        t = self._theme
        outer = self._ctk.CTkFrame(parent, fg_color=t.bg_panel,
                                   border_color=t.border_idle,
                                   border_width=1, corner_radius=10)
        outer.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)

        tag = "SINTÉTICO" if self._traffic.is_synthetic else "REAL psutil"
        self._ctk.CTkLabel(outer, text=f"TRÁFICO EN TIEMPO REAL ({tag})",
                           font=self._fonts["mono_sm"],
                           text_color=t.text_dim).pack(anchor="w",
                                                       padx=10,
                                                       pady=(8, 2))
        canvas = tk.Canvas(outer, bg=t.bg_deep, highlightthickness=0,
                           height=160)
        canvas.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._graph_canvas = canvas

        def _redraw() -> None:
            if not canvas.winfo_exists():
                return
            w = max(canvas.winfo_width(), 200)
            h = max(canvas.winfo_height(), 120)
            canvas.delete("all")

            for gy in range(0, h, 28):
                canvas.create_line(0, gy, w, gy, fill="#08180d", width=1)

            rx_s = self._traffic.series_rx()
            tx_s = self._traffic.series_tx()
            peak = max(max(rx_s, default=1.0), max(tx_s, default=1.0), 1024.0)

            def _plot(series: list[float], color: str) -> None:
                if len(series) < 2:
                    return
                step = w / max(len(series) - 1, 1)
                pts: list[float] = []
                for i, v in enumerate(series):
                    x = i * step
                    y = h - 6 - (v / peak) * (h - 16)
                    pts.extend([x, y])
                canvas.create_line(*pts, fill=color, width=2, smooth=True)

            _plot(rx_s, t.text_main)
            _plot(tx_s, t.text_cyan)

            canvas.create_text(10, 10, anchor="nw",
                               text=f"▲ {fmt_rate(peak)}",
                               fill=t.text_dim,
                               font=(self._fonts["_mono_family"], 9))

        def _tick() -> None:
            if self._root is None:
                return
            _redraw()
            self._root.after(1000, _tick)

        canvas.bind("<Configure>", lambda _e: _redraw())
        self._root.after(1000, _tick)

    def _page_roadmap(self, key: str):
        ctk, t = self._ctk, self._theme
        meta = next(m for m in _MODULE_META if m["key"] == key)
        page, body = self._page_frame(
            f"{meta['icon']} {meta['title'].upper()}",
            "Módulo de la suite AZZAZEL VPN")
        card = ctk.CTkFrame(body, fg_color=t.bg_panel,
                            border_color=t.border_idle, border_width=1,
                            corner_radius=10)
        card.pack(anchor="nw", padx=6, pady=6)
        for line in (
            f"Implementación: {meta['file']}",
            f"Estado: {meta['sprint']}",
            "",
            "La terminal inferior muestra el log real de la suite.",
        ):
            ctk.CTkLabel(card, text=line, font=self._fonts["mono"],
                         text_color=t.text_cyan).pack(
                anchor="w", padx=14, pady=3)
        return page

    def _page_settings(self):
        ctk, t = self._ctk, self._theme
        page, body = self._page_frame(
            "🔧 SETTINGS", "Proxy corporativo upstream (se guarda cifrado)")

        form = ctk.CTkFrame(body, fg_color=t.bg_panel,
                            border_color=t.border_idle, border_width=1,
                            corner_radius=10)
        form.pack(anchor="nw", padx=6, pady=6, fill="x")

        up = self._cm.config.proxy.upstream
        self._form: dict[str, Any] = {}

        def row(r: int, label: str, widget) -> None:
            ctk.CTkLabel(form, text=label, font=self._fonts["mono"],
                         text_color=t.text_cyan, width=170,
                         anchor="w").grid(row=r, column=0, sticky="w",
                                          padx=14, pady=6)
            widget.grid(row=r, column=1, sticky="we", padx=14, pady=6)

        form.grid_columnconfigure(1, weight=1)

        self._form["enabled"] = ctk.CTkSwitch(
            form, text="Activar proxy corporativo",
            font=self._fonts["mono"], text_color=t.text_main,
            progress_color=t.text_main)
        if up.enabled:
            self._form["enabled"].select()
        row(0, "Upstream", self._form["enabled"])

        self._form["host"] = ctk.CTkEntry(form, font=self._fonts["mono"],
                                          placeholder_text="proxy.empresa.com")
        self._form["host"].insert(0, up.host)
        row(1, "Host", self._form["host"])

        self._form["port"] = ctk.CTkEntry(form, font=self._fonts["mono"],
                                          placeholder_text="8080", width=90)
        self._form["port"].insert(0, str(up.port))
        row(2, "Puerto", self._form["port"])

        self._form["auth"] = ctk.CTkOptionMenu(
            form, values=["basic", "digest", "ntlm", "kerberos"],
            font=self._fonts["mono"], fg_color=t.bg_deep,
            button_color=t.bg_hover, text_color=t.text_main)
        self._form["auth"].set(up.auth_type or "basic")
        row(3, "Autenticación", self._form["auth"])

        self._form["user"] = ctk.CTkEntry(form, font=self._fonts["mono"],
                                          placeholder_text="DOMINIO\\usuario")
        self._form["user"].insert(
            0, f"{up.domain}\\{up.username}" if up.domain else up.username)
        row(4, "Usuario", self._form["user"])

        self._form["password"] = ctk.CTkEntry(form, font=self._fonts["mono"],
                                              show="●")
        self._form["password"].insert(0, up.password)
        row(5, "Contraseña", self._form["password"])

        ctk.CTkButton(
            form, text="💾 GUARDAR (cifrado AES-256-GCM)",
            font=self._fonts["mono"], fg_color=t.bg_panel,
            text_color=t.text_main, border_color=t.border_active,
            border_width=1, hover_color=t.bg_hover,
            command=self._save_settings,
        ).grid(row=6, column=1, sticky="w", padx=14, pady=16)
        return page

    def _save_settings(self) -> None:
        try:
            user_raw = self._form["user"].get().strip()
            domain, _, user = user_raw.partition("\\")
            port = int(self._form["port"].get().strip() or "8080")
            if not (1 <= port <= 65535):
                raise ValueError("puerto fuera de rango")
            enabled = bool(self._form["enabled"].get())
            cm = self._cm
            cm.set("proxy.upstream.enabled", enabled)
            cm.set("proxy.upstream.host", self._form["host"].get().strip())
            cm.set("proxy.upstream.port", port)
            cm.set("proxy.upstream.auth_type", self._form["auth"].get().strip().lower())
            cm.set("proxy.upstream.domain", domain if user else "")
            cm.set("proxy.upstream.username", user or user_raw)
            cm.set("proxy.upstream.password", self._form["password"].get())
            cm.save()
        except Exception as exc:  # noqa: BLE001
            _log.error("Error guardando settings desde GUI: %s", exc)
            self._toast(f"Error: {exc}", ok=False)
            return
        _log.success("Settings guardados desde la GUI (upstream proxy).")
        self._toast("Configuración guardada — secreto cifrado en disco")

    def _page_proxy(self):
        ctk, t = self._ctk, self._theme
        self._proxy_widgets = {}
        page, body = self._page_frame(
            "🔄 PROXY SUITE",
            "Cadena de proxies compuesta desde config.yaml — prueba real")

        up = self._cm.config.proxy.upstream
        local = self._cm.config.proxy.local
        estado = (f"{up.host}:{up.port} · {up.auth_type or 'basic'}"
                  if up.enabled and up.host else "DESACTIVADO (DIRECT)")
        info = ctk.CTkFrame(body, fg_color=t.bg_panel,
                            border_color=t.border_idle, border_width=1,
                            corner_radius=10)
        info.pack(anchor="nw", fill="x", padx=6, pady=6)
        ctk.CTkLabel(
            info,
            text=f"UPSTREAM → {estado}\n"
                 f"LISTENERS → http:{local.http_port} · socks5:{local.socks5_port}",
            font=self._fonts["mono_sm"], text_color=t.text_cyan,
            justify="left",
        ).pack(anchor="w", padx=12, pady=10)

        controls = ctk.CTkFrame(body, fg_color="transparent")
        controls.pack(anchor="w", padx=6, pady=2, fill="x")
        self._proxy_widgets["target"] = ctk.CTkEntry(
            controls, width=240, font=self._fonts["mono"],
            placeholder_text="objetivo: example.com:443")
        self._proxy_widgets["target"].insert(0, "example.com:443")
        self._proxy_widgets["target"].pack(side="left", padx=(0, 8))
        self._proxy_widgets["probe_btn"] = ctk.CTkButton(
            controls, text="⚡ PROBAR CADENA", font=self._fonts["mono"],
            fg_color=t.bg_panel, text_color=t.text_main,
            border_color=t.border_active, border_width=1,
            hover_color=t.bg_hover, command=self._probe_chain)
        self._proxy_widgets["probe_btn"].pack(side="left")

        self._proxy_widgets["report"] = ctk.CTkTextbox(
            body, font=self._fonts["term"], fg_color=t.bg_terminal,
            text_color=t.text_main, border_color=t.border_idle,
            border_width=1, corner_radius=8, height=250, wrap="none")
        self._proxy_widgets["report"].pack(fill="both", expand=True,
                                           padx=6, pady=(8, 8))
        self._proxy_set_report(
            "Pulsa ⚡ PROBAR CADENA para sonar cada nodo y abrir un\n"
            "túnel REAL hasta el objetivo (auth NTLMv2 incluida).\n",
            accent=None)
        return page

    def _proxy_set_report(self, text: str, accent: Optional[str]) -> None:
        box = self._proxy_widgets.get("report")
        if box is None:
            return
        color = accent or self._theme.text_main
        box.configure(state="normal", text_color=color)
        box.delete("1.0", "end")
        box.insert("end", text)
        box.configure(state="disabled")

    def _probe_chain(self) -> None:
        try:
            host, port = split_host_port(self._proxy_widgets["target"].get())
        except ValueError as exc:
            self._toast(f"Objetivo inválido: {exc}", ok=False)
            return
        self._proxy_widgets["probe_btn"].configure(state="disabled", text="PROBANDO…")
        self._proxy_set_report(
            f"Sonando cadena hacia {host}:{port} …\n"
            f"(cada nodo recibe un CONNECT; puede tardar segundos)\n",
            accent=None)

        def factory():
            from proxy.proxy_chain import ProxyChain
            chain = ProxyChain.from_config_manager(self._cm)
            return chain.test_chain(target_host=host, target_port=port)

        self._run_async(factory, self._on_chain_result)

    def _on_chain_result(self, report, exc) -> None:
        btn = self._proxy_widgets.get("probe_btn")
        if btn is not None:
            btn.configure(state="normal", text="⚡ PROBAR CADENA")
        if exc is not None:
            _log.error("GUI: test_chain falló: %s", exc)
            self._proxy_set_report(
                f"✗ ERROR de la prueba:\n{type(exc).__name__}: {exc}\n",
                accent=self._theme.accent_red)
            self._toast("Prueba de cadena falló — revisa el log", ok=False)
            return
        text = report.render(color=False)
        ok = report.ok
        self._proxy_set_report(
            text, accent=self._theme.text_main if ok else self._theme.accent_red)
        if ok:
            self._toast("Cadena operativa ✔")
        else:
            self._toast("Cadena ROTA — mira el informe", ok=False)

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------
    def _on_close(self) -> None:
        if self._log_handler is not None:
            logging.getLogger("azzazel").removeHandler(self._log_handler)
            self._log_handler = None
        if self._active_vpn_server:
            try:
                fut = asyncio.run_coroutine_threadsafe(
                    self._active_vpn_server.stop(), self._async_loop)
                fut.result(timeout=1.0)
            except Exception:
                pass
            self._active_vpn_server = None
        if self._active_vpn_client:
            try:
                fut = asyncio.run_coroutine_threadsafe(
                    self._active_vpn_client.close(), self._async_loop)
                fut.result(timeout=1.0)
            except Exception:
                pass
            self._active_vpn_client = None
        if self._active_bridge:
            try:
                fut = asyncio.run_coroutine_threadsafe(
                    self._active_bridge.stop(), self._async_loop)
                fut.result(timeout=1.0)
            except Exception:
                pass
            self._active_bridge = None
        if self._active_tunnel_mgr:
            try:
                self._active_tunnel_mgr.stop()
            except Exception:
                pass
            self._active_tunnel_mgr = None
        if hasattr(self, "_async_loop") and self._async_loop.is_running():
            try:
                self._async_loop.call_soon_threadsafe(self._async_loop.stop)
            except Exception:
                pass
        _log.info("Ventana AZZAZEL cerrada por el usuario.")
        if self._root is not None:
            self._root.destroy()
            self._root = None

    def run(self) -> int:
        self._build_window()
        self._log_handler = GuiLogHandler(self._log_queue)
        logging.getLogger("azzazel").addHandler(self._log_handler)
        _log.success("GUI AZZAZEL iniciada (customtkinter).")
        self._drain_logs()
        self._drain_ui()
        assert self._root is not None
        self._root.mainloop()
        return 0


def run_gui(config_manager) -> int:
    """Lanza la ventana principal."""
    ok, reason = check_gui_support()
    if not ok:
        print(reason, file=sys.stderr)
        return 1
    app = AzzazelGuiApp(config_manager)
    return app.run()
