#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AZZAZEL VPN — ui/gui/theme.py
=============================

Tema visual oscuro de la interfaz gráfica (ventana de programa).

Es un módulo de **datos puros** (sin imports de tkinter), de modo que
puede importarse en cualquier entorno — incluso headless/CI — y la
lógica de selección de fuentes es testeable de forma aislada.

Paleta oficial AZZAZEL (documento de diseño)::

    bg_deep        #0a0a0a   fondo principal (negro profundo)
    bg_dark        #111111   fondo secundario (sidebar, status bar)
    bg_panel       #1a1a2e   paneles/tarjetas (azul oscuro)
    text_main      #00ff41   verde Matrix
    text_cyan      #0abdc6   cyan neón
    text_magenta   #ea00d9   magenta neón
    accent_red     #ff003c   rojo neón (alertas)
    warn_amber     #ffb700   ámbar (warnings)
    border_active  #00ff41   bordes activos
    border_idle    #333333   bordes inactivos
    bg_terminal    #050505   terminal integrada
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

__all__ = [
    "AZZAZEL_THEME",
    "GuiTheme",
    "MONO_FONT_STACK",
    "TITLE_FONT_STACK",
    "resolve_font",
]

# Pilas de fuentes en orden de preferencia según el documento de diseño.
MONO_FONT_STACK: tuple[str, ...] = (
    "Cascadia Code",      # Windows Terminal moderno
    "JetBrains Mono",
    "Fira Code",
    "Consolas",           # Windows clásico
    "DejaVu Sans Mono",   # Linux
    "Liberation Mono",
    "Courier New",        # último recurso universal
)

TITLE_FONT_STACK: tuple[str, ...] = (
    "Share Tech Mono",    # especificado para títulos
    *MONO_FONT_STACK,
)


def resolve_font(preferred: Sequence[str], available: Sequence[str]) -> str:
    """Elige la primera fuente de ``preferred`` instalada en el sistema.

    Args:
        preferred: Pila de familias en orden de preferencia.
        available: Familias que reporta ``tkinter.font.families()``.

    Returns:
        La primera coincidencia, o ``"Courier New"`` como red de
        seguridad (presente en prácticamente todo tkinter).
    """
    available_set = {fam.lower() for fam in available}
    for family in preferred:
        if family.lower() in available_set:
            return family
    return "Courier New"


@dataclass(frozen=True)
class GuiTheme:
    """Tema oscuro AZZAZEL para la GUI (colores hex + fuentes)."""

    # Fondos
    bg_deep: str = "#0a0a0a"
    bg_dark: str = "#111111"
    bg_panel: str = "#1a1a2e"
    bg_terminal: str = "#050505"
    bg_hover: str = "#16213e"

    # Texto / acentos
    text_main: str = "#00ff41"
    text_cyan: str = "#0abdc6"
    text_magenta: str = "#ea00d9"
    text_dim: str = "#7a8a7a"
    text_inverse: str = "#0a0a0a"
    accent_red: str = "#ff003c"
    warn_amber: str = "#ffb700"

    # Alias convenientes para UI / Canvas
    accent_cyan: str = "#0abdc6"
    accent_magenta: str = "#ea00d9"
    accent_green: str = "#00ff41"
    accent_amber: str = "#ffb700"
    text_green: str = "#00ff41"
    text_amber: str = "#ffb700"
    text_red: str = "#ff003c"

    # Bordes
    border_active: str = "#00ff41"
    border_idle: str = "#333333"

    # Fuentes (resueltas en app.py contra el sistema real)
    font_mono_stack: tuple[str, ...] = field(default=MONO_FONT_STACK)
    font_title_stack: tuple[str, ...] = field(default=TITLE_FONT_STACK)

    # Métricas de la ventana
    window_width: int = 1280
    window_height: int = 800
    sidebar_width: int = 74
    terminal_height: int = 168
    statusbar_height: int = 26


AZZAZEL_THEME: GuiTheme = GuiTheme()
