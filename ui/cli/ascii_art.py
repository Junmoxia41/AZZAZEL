#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AZZAZEL VPN — ui/cli/ascii_art.py
=================================

Motor visual de la interfaz de terminal: banner AZZAZEL con gradiente
neón, lluvia Matrix, efectos de texto (typing / decrypt / glitch /
pulso), marcos decorativos y barras de progreso cyberpunk.

Diseño defensivo del módulo:

- **Sin TTY → degradación elegante**: toda animación detecta si la salida
  es un terminal interactivo; si no (pipes, CI, ``nohup``, servicio de
  Windows), imprime la versión estática y no emite códigos de cursor.
- **Desactivable**: ``AZZAZEL_NO_ANIM=1`` silencia las animaciones; el
  parámetro ``enabled`` de cada función permite que ``config.yaml``
  (``ui.animations: false``) haga lo mismo.
- **Siempre cancelable**: la lluvia Matrix acepta un
  :class:`threading.Event` externo, y ``KeyboardInterrupt`` restaura el
  cursor y limpia la pantalla antes de propagarse.
- **Temas**: ``matrix`` (verde/cyan/magenta), ``cyber`` (cyan/magenta) y
  ``blood`` (rojo/ámbar), según ``ui.theme`` de la configuración.

Uso rápido::

    from ui.cli.ascii_art import print_banner, matrix_rain, decrypt_text

    print_banner()                        # banner con gradiente neón
    matrix_rain(duration=2.5)             # splash Matrix (solo si hay TTY)
    decrypt_text("ACCESO CONCEDIDO")      # texto que se "descifra"

Independiente y auto-testeable::

    python ui/cli/ascii_art.py            # demo de todos los efectos
"""

from __future__ import annotations

import os
import random
import re
import shutil
import sys
import threading
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional, Sequence, TextIO

# Permite ejecutar este archivo directamente como script (demo standalone).
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.logger import AnsiPalette, get_logger

__all__ = [
    "THEMES",
    "Theme",
    "get_theme",
    "set_theme",
    "AZZAZEL_BANNER",
    "TAGLINE_BOX",
    "VERSION_LINE",
    "strip_ansi",
    "visible_len",
    "center_text",
    "clear_screen",
    "hidden_cursor",
    "get_banner_lines",
    "print_banner",
    "matrix_rain",
    "type_text",
    "type_lines",
    "decrypt_text",
    "glitch_text",
    "pulse_banner",
    "box",
    "print_box",
    "cyber_progress_bar",
]

# ---------------------------------------------------------------------------
# Logging perezoso (no fuerza la configuración global al importar)
# ---------------------------------------------------------------------------
_log = None


def _logger():
    """Devuelve el logger del módulo, inicializándolo bajo demanda."""
    global _log
    if _log is None:
        _log = get_logger("ui.ascii_art")
    return _log


# ---------------------------------------------------------------------------
# Temas visuales
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Theme:
    """Paleta de un tema visual de la CLI.

    Attributes:
        name: Identificador ("matrix" | "cyber" | "blood").
        primary: ANSI del texto principal.
        secondary: ANSI del texto secundario / bordes.
        tertiary: ANSI de resaltados.
        alert: ANSI de alertas/acentos.
        grad_start: RGB inicial del gradiente del banner.
        grad_end: RGB final del gradiente del banner.
    """

    name: str
    primary: str
    secondary: str
    tertiary: str
    alert: str
    grad_start: tuple[int, int, int]
    grad_end: tuple[int, int, int]
    reset: str = field(default=AnsiPalette.RESET)


THEMES: dict[str, Theme] = {
    "matrix": Theme(
        name="matrix",
        primary=AnsiPalette.MATRIX_GREEN,
        secondary=AnsiPalette.NEON_CYAN,
        tertiary=AnsiPalette.NEON_MAGENTA,
        alert=AnsiPalette.NEON_RED,
        grad_start=(0, 255, 65),
        grad_end=(10, 189, 198),
    ),
    "cyber": Theme(
        name="cyber",
        primary=AnsiPalette.NEON_CYAN,
        secondary=AnsiPalette.NEON_MAGENTA,
        tertiary=AnsiPalette.WHITE,
        alert=AnsiPalette.AMBER,
        grad_start=(10, 189, 198),
        grad_end=(234, 0, 217),
    ),
    "blood": Theme(
        name="blood",
        primary=AnsiPalette.NEON_RED,
        secondary=AnsiPalette.AMBER,
        tertiary=AnsiPalette.WHITE,
        alert=AnsiPalette.AMBER,
        grad_start=(255, 0, 60),
        grad_end=(255, 183, 0),
    ),
}

_current_theme: Theme = THEMES["matrix"]


def set_theme(name: str) -> Theme:
    """Activa un tema visual por nombre.

    Args:
        name: "matrix", "cyber" o "blood" (insensible a mayúsculas).

    Returns:
        El :class:`Theme` activado.

    Raises:
        ValueError: Si el nombre no existe en :data:`THEMES`.
    """
    global _current_theme
    key = name.strip().lower()
    if key not in THEMES:
        valid = ", ".join(sorted(THEMES))
        raise ValueError(f"Tema desconocido: {name!r}. Válidos: {valid}")
    _current_theme = THEMES[key]
    _logger().info("Tema visual cambiado a '%s'.", key)
    return _current_theme


def get_theme() -> Theme:
    """Devuelve el tema visual activo."""
    return _current_theme


# ---------------------------------------------------------------------------
# Utilidades ANSI (anchos visibles, seguridad Unicode)
# ---------------------------------------------------------------------------
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    """Elimina todas las secuencias de escape ANSI de ``text``."""
    return _ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    """Ancho visible en CELDAS de terminal (ignora códigos ANSI).

    Cuenta 2 celdas para glifos anchos (emojis, CJK) según
    ``unicodedata.east_asian_width`` y 1 para el resto, igual que las
    terminales reales: así los marcos con emojis quedan rectangulares.
    """
    plain = strip_ansi(text)
    return sum(
        2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        for ch in plain
    )


def center_text(text: str, width: int, fill: str = " ") -> str:
    """Centra ``text`` en ``width`` columnas, respetando códigos ANSI.

    Args:
        text: Cadena (posiblemente coloreada).
        width: Ancho visible total deseado.
        fill: Carácter de relleno (un solo carácter; por defecto espacio).

    Returns:
        Cadena centrada; si no cabe, se devuelve sin truncar.
    """
    extra = width - visible_len(text)
    if extra <= 0:
        return text
    left = extra // 2
    return f"{fill * left}{text}{fill * (extra - left)}"


def _write(stream: TextIO, text: str) -> None:
    """Escribe en ``stream`` con tolerancia a codificaciones limitadas.

    Si el terminal no puede representar un carácter (p. ej. consola
    heredada de Windows en cp1252), lo sustituye en lugar de romper.
    """
    try:
        stream.write(text)
        stream.flush()
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "utf-8"
        stream.write(text.encode(encoding, errors="replace").decode(encoding))
        stream.flush()


def _use_color(stream: TextIO) -> bool:
    """Decide si la salida admite color (mismo criterio que core.logger)."""
    if os.environ.get("AZZAZEL_FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _animations_ok(stream: TextIO, enabled: bool, force: bool) -> bool:
    """Decide si procede ejecutar una animación en este stream."""
    if force:
        return True
    if not enabled or os.environ.get("AZZAZEL_NO_ANIM"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


@contextmanager
def hidden_cursor(stream: TextIO = sys.stdout) -> Iterator[None]:
    """Oculta el cursor durante el bloque y lo restaura siempre al salir."""
    _write(stream, "\033[?25l")
    try:
        yield
    finally:
        _write(stream, "\033[?25h")


def clear_screen(stream: TextIO = sys.stdout) -> None:
    """Limpia la pantalla (o emite un salto amplio si no hay TTY)."""
    if hasattr(stream, "isatty") and stream.isatty():
        _write(stream, "\033[2J\033[H")
    else:
        _write(stream, "\n")


# ---------------------------------------------------------------------------
# Banner AZZAZEL
# ---------------------------------------------------------------------------
VERSION_LINE: str = "AZZAZEL VPN v1.0 — Advanced Network Warfare Suite"

AZZAZEL_BANNER: str = r"""
    ▄▄▄      ▒███████▒▒███████▒▄▄▄      ▒███████▒▓█████  ██▓
   ▒████▄    ▒ ▒ ▒ ▄▀░▒ ▒ ▒ ▄▀▒████▄    ▒ ▒ ▒ ▄▀░▓█   ▀ ▓██▒
   ▒██  ▀█▄  ░ ▒ ▄▀▒░ ░ ▒ ▄▀▒░▒██  ▀█▄  ░ ▒ ▄▀▒░ ▒███   ▒██░
   ░██▄▄▄▄██   ▄▀▒   ░  ▄▀▒   ░██▄▄▄▄██   ▄▀▒   ░▒▓█  ▄ ░██░
    ▓█   ▓██▒▒███████▒ ▒███████▒ ▓█   ▓██▒▒███████▒░▒████▒░██░
    ▒▒   ▓▒█░░▒▒ ▓░▒░▒ ░▒▒ ▓░▒░▒▒▒   ▓▒█░░▒▒ ▓░▒░▒░░ ▒░ ░░▓
     ▒   ▒▒ ░░░▒ ▒ ░ ▒ ░░▒ ▒ ░ ▒▒   ▒▒ ░░░▒ ▒ ░ ▒ ░ ░  ░ ▒░
     ░   ▒   ░ ░ ░ ░ ░ ░ ░ ░ ░ ░░   ▒   ░ ░ ░ ░ ░   ░    ░
         ░  ░  ░ ░       ░ ░         ░  ░  ░ ░       ░  ░ ░
"""

TAGLINE_BOX: str = r"""
    ╔══════════════════════════════════════════════════════╗
    ║  AZZAZEL VPN v1.0 — Advanced Network Warfare Suite  ║
    ║  [■] Encrypted  [■] Anonymous  [■] Unstoppable      ║
    ╚══════════════════════════════════════════════════════╝
"""


def _gradient_ansi(t: float, start: tuple[int, int, int],
                   end: tuple[int, int, int]) -> str:
    """Interpolación RGB lineal → código ANSI true-color.

    Args:
        t: Posición en el gradiente (0.0 = start, 1.0 = end).
        start: RGB inicial.
        end: RGB final.
    """
    r = round(start[0] + (end[0] - start[0]) * t)
    g = round(start[1] + (end[1] - start[1]) * t)
    b = round(start[2] + (end[2] - start[2]) * t)
    return f"\033[38;2;{r};{g};{b}m"


def get_banner_lines(gradient: bool = True, boost: str = "") -> list[str]:
    """Genera las líneas del banner coloreadas con gradiente del tema.

    Args:
        gradient: Aplica gradiente primary→secondary línea a línea; si es
            ``False``, todo el arte usa el color primary plano.
        boost: Código ANSI adicional (p. ej. ``AnsiPalette.BOLD`` para el
            efecto de pulso neón).

    Returns:
        Lista de líneas con códigos ANSI incluidos.
    """
    theme = get_theme()
    lines = AZZAZEL_BANNER.strip("\n").splitlines()
    total = max(1, len(lines) - 1)
    rendered: list[str] = []
    for i, line in enumerate(lines):
        if gradient:
            color = _gradient_ansi(i / total, theme.grad_start, theme.grad_end)
        else:
            color = theme.primary
        rendered.append(f"{color}{boost}{line}{AnsiPalette.RESET}")
    return rendered


def print_banner(
    *,
    tagline: bool = True,
    gradient: bool = True,
    stream: TextIO = sys.stdout,
) -> None:
    """Imprime el banner AZZAZEL (con caja de tagline opcional).

    Si el terminal es más estrecho que el arte, imprime una versión
    compacta enmarcada en su lugar.
    """
    art_lines = AZZAZEL_BANNER.strip("\n").splitlines()
    art_width = max(len(line) for line in art_lines)
    term_width = shutil.get_terminal_size(fallback=(80, 24)).columns

    if not _use_color(stream):
        _write(stream, strip_ansi(AZZAZEL_BANNER))
        if tagline:
            _write(stream, TAGLINE_BOX + "\n")
        return

    if term_width < art_width + 2:
        _logger().debug(
            "Terminal estrecho (%d cols); usando banner compacto.", term_width
        )
        print_box(
            [VERSION_LINE, "[■] Encrypted  [■] Anonymous  [■] Unstoppable"],
            style="double",
            align="center",
            stream=stream,
        )
        return

    for line in get_banner_lines(gradient=gradient):
        _write(stream, line + "\n")
    if tagline:
        theme = get_theme()
        for tl_line in TAGLINE_BOX.strip("\n").splitlines():
            _write(stream, f"{theme.secondary}{tl_line}{AnsiPalette.RESET}\n")
    _write(stream, "\n")


def pulse_banner(
    frames: int = 9,
    interval: float = 0.12,
    stream: TextIO = sys.stdout,
    enabled: bool = True,
    force: bool = False,
) -> None:
    """Efecto neón pulsante sobre el banner: normal → brillante → tenue.

    Solo actúa en terminales interactivos (o con ``force=True``).
    """
    if not _animations_ok(stream, enabled, force):
        print_banner(stream=stream)
        return

    lines_normal = get_banner_lines(boost="")
    lines_bright = get_banner_lines(boost=AnsiPalette.BOLD)
    lines_dim = get_banner_lines(boost=AnsiPalette.DIM)
    states = (lines_normal, lines_bright, lines_normal, lines_dim)
    height = len(lines_normal)

    with hidden_cursor(stream):
        first = True
        for frame in range(frames):
            state = states[frame % len(states)]
            if not first:
                _write(stream, f"\033[{height}A")  # sube al inicio del arte
            _write(stream, "\n".join(state) + "\n")
            time.sleep(interval)
            first = False
    _write(stream, "\n")


# ---------------------------------------------------------------------------
# Animación: lluvia Matrix
# ---------------------------------------------------------------------------
_MATRIX_GLYPHS = (
    "アイウエオカキクケコサシスセソタチツテトナニヌネノ"
    "0123456789ABCDEFXYZ$#*+=<>░▒▓"
)


def matrix_rain(
    duration: float = 3.0,
    *,
    fps: int = 18,
    stop: Optional[threading.Event] = None,
    stream: TextIO = sys.stdout,
    enabled: bool = True,
    force: bool = False,
) -> None:
    """Lluvia de caracteres estilo Matrix (splash screen de arranque).

    Args:
        duration: Segundos totales de la animación.
        fps: Fotogramas por segundo objetivo.
        stop: Event externo para abortar la animación (p. ej. el motor
            principal cancela el splash cuando termina de cargar).
        stream: Salida (stdout por defecto).
        enabled: Permite desactivarla desde configuración.
        force: Fuerza la animación aunque no haya TTY (testing).
    """
    if not _animations_ok(stream, enabled, force):
        _logger().debug("Lluvia Matrix omitida (sin TTY o desactivada).")
        return

    width, height = shutil.get_terminal_size(fallback=(80, 24))
    width = max(10, min(width, 200))
    height = max(5, height)
    theme = get_theme()
    bright = theme.primary
    dim = AnsiPalette.DIM

    # Estado por columna: posición de la cabeza (negativo = esperando).
    heads = [random.randint(-height, 0) for _ in range(width)]
    trails = [random.randint(4, 10) for _ in range(width)]

    frame_time = 1.0 / max(1, fps)
    start = time.monotonic()
    _logger().debug("Lluvia Matrix: %.1fs @ %dfps (%dx%d).",
                    duration, fps, width, height)

    with hidden_cursor(stream):
        _write(stream, "\033[2J")
        try:
            while time.monotonic() - start < duration:
                if stop is not None and stop.is_set():
                    break
                buffer: list[str] = []
                for col in range(width):
                    heads[col] += 1
                    head = heads[col]
                    if head - trails[col] > height:
                        heads[col] = random.randint(-height // 2, 0)
                        trails[col] = random.randint(4, 10)
                        continue
                    if 1 <= head <= height:
                        char = random.choice(_MATRIX_GLYPHS)
                        buffer.append(
                            f"\033[{head};{col + 1}H{bright}{char}"
                        )
                    tail_pos = head - trails[col]
                    if 1 <= tail_pos <= height:
                        char = random.choice(_MATRIX_GLYPHS)
                        buffer.append(f"\033[{tail_pos};{col + 1}H{dim}{char}")
                    erase = head - trails[col] - 1
                    if 1 <= erase <= height:
                        buffer.append(f"\033[{erase};{col + 1}H ")
                if buffer:
                    _write(stream, "".join(buffer))
                time.sleep(frame_time)
        except KeyboardInterrupt:
            _logger().info("Splash Matrix interrumpido por el usuario.")
        finally:
            _write(stream, f"{AnsiPalette.RESET}\033[2J\033[H")


# ---------------------------------------------------------------------------
# Efectos de texto: typing, decrypt, glitch
# ---------------------------------------------------------------------------
_SCRAMBLE_GLYPHS = "!<>-_\\/[]{}—=+*^?#"
_GLITCH_GLYPHS = "█▓▒░@#%&$§¤†‡"


def type_text(
    text: str,
    *,
    cps: int = 80,
    color: Optional[str] = None,
    end: str = "\n",
    jitter: float = 0.35,
    stream: TextIO = sys.stdout,
    enabled: bool = True,
    force: bool = False,
) -> None:
    """Imprime ``text`` carácter a carácter (efecto máquina de escribir).

    Args:
        text: Texto a imprimir.
        cps: Caracteres por segundo objetivo.
        color: ANSI opcional para colorear todo el texto.
        end: Terminador final (como en ``print``).
        jitter: Variación aleatoria (0-1) del ritmo; 0 = ritmo mecánico.
        stream: Salida.
        enabled: Permite desactivar la animación desde configuración.
        force: Fuerza la animación sin TTY (testing).
    """
    colored = f"{color}{text}{AnsiPalette.RESET}" if color else text
    if not _animations_ok(stream, enabled, force):
        _write(stream, colored + end)
        return

    interval = 1.0 / max(1, cps)
    if color:
        _write(stream, color)
    for char in text:
        _write(stream, char)
        delay = interval
        if jitter:
            delay *= 1.0 + random.uniform(-jitter, jitter)
        time.sleep(max(0.0, delay))
    if color:
        _write(stream, AnsiPalette.RESET)
    _write(stream, end)


def type_lines(
    lines: Sequence[str],
    *,
    cps: int = 80,
    line_pause: float = 0.15,
    color: Optional[str] = None,
    stream: TextIO = sys.stdout,
    enabled: bool = True,
    force: bool = False,
) -> None:
    """Aplica :func:`type_text` a una secuencia de líneas."""
    for line in lines:
        type_text(
            line, cps=cps, color=color, stream=stream,
            enabled=enabled, force=force,
        )
        if _animations_ok(stream, enabled, force) and line_pause:
            time.sleep(line_pause)


def decrypt_text(
    text: str,
    *,
    duration: float = 0.9,
    color: Optional[str] = None,
    stream: TextIO = sys.stdout,
    enabled: bool = True,
    force: bool = False,
) -> None:
    """Efecto "descifrado": caracteres aleatorios que se resuelven.

    Cada carácter se fija de izquierda a derecha tras un umbral
    aleatorio, mientras el resto sigue rotando por glifos basura.
    """
    if not _animations_ok(stream, enabled, force):
        _write(stream, f"{color or ''}{text}"
                       f"{AnsiPalette.RESET if color else ''}\n")
        return

    steps = max(4, min(40, int(duration * 30)))
    thresholds = [random.randint(0, steps - 1) for _ in text]
    frame_time = duration / steps

    with hidden_cursor(stream):
        for step in range(steps + 1):
            frame_chars: list[str] = []
            for i, char in enumerate(text):
                if char == " " or step > thresholds[i]:
                    frame_chars.append(char)
                else:
                    frame_chars.append(random.choice(_SCRAMBLE_GLYPHS))
            frame = "".join(frame_chars)
            _write(
                stream,
                f"\r{color or ''}{frame}"
                f"{AnsiPalette.RESET if color else ''}",
            )
            time.sleep(frame_time)
    _write(stream, "\n")


def glitch_text(
    text: str,
    *,
    duration: float = 0.6,
    intensity: float = 0.25,
    color: Optional[str] = None,
    stream: TextIO = sys.stdout,
    enabled: bool = True,
    force: bool = False,
) -> None:
    """Efecto glitch: el texto parpadea con glifos corruptos y se fija.

    Args:
        intensity: Fracción de caracteres corruptos por fotograma (0-1).
    """
    if not _animations_ok(stream, enabled, force):
        _write(stream, f"{color or ''}{text}"
                       f"{AnsiPalette.RESET if color else ''}\n")
        return

    frames = max(3, int(duration * 20))
    intensity = max(0.0, min(1.0, intensity))
    alert = color or get_theme().alert

    with hidden_cursor(stream):
        for frame_idx in range(frames):
            corrupted: list[str] = []
            for char in text:
                if char != " " and random.random() < intensity:
                    corrupted.append(random.choice(_GLITCH_GLYPHS))
                else:
                    corrupted.append(char)
            _write(
                stream,
                f"\r{alert}{''.join(corrupted)}{AnsiPalette.RESET}",
            )
            time.sleep(duration / frames)
    _write(stream, f"\r{color or ''}{text}"
                   f"{AnsiPalette.RESET if color else ''}\n")


# ---------------------------------------------------------------------------
# Marcos y barras de progreso
# ---------------------------------------------------------------------------
_BOX_STYLES: dict[str, tuple[str, str, str, str, str, str]] = {
    #        tl    h    tr    v    bl    br
    "single": ("┌", "─", "┐", "│", "└", "┘"),
    "double": ("╔", "═", "╗", "║", "╚", "╝"),
    "round": ("╭", "─", "╮", "│", "╰", "╯"),
    "heavy": ("┏", "━", "┓", "┃", "┗", "┛"),
}


def box(
    lines: str | Sequence[str],
    *,
    width: Optional[int] = None,
    style: str = "double",
    padding: int = 1,
    pad_v: int = 0,
    title: Optional[str] = None,
    align: str = "left",
    border_color: Optional[str] = None,
    text_color: Optional[str] = None,
) -> str:
    """Construye un marco decorativo alrededor de ``lines``.

    Args:
        lines: Texto (``str`` multi-línea) o secuencia de líneas. Se
            admiten códigos ANSI dentro del contenido.
        width: Ancho interior mínimo (sin contar bordes). ``None`` =
            ajustar al contenido. Si el contenido o el título no caben,
            el marco crece automáticamente para mantener la geometría.
        style: "single", "double", "round" o "heavy".
        padding: Espacios laterales entre borde y contenido.
        pad_v: Líneas vacías por encima/debajo del contenido.
        title: Título incrustado en el borde superior.
        align: "left", "center" o "right".
        border_color: ANSI del marco (por defecto, secondary del tema).
            El valor especial ``"none"`` desactiva TODOS los códigos
            ANSI del marco (útil para destinos sin terminal, p. ej. la
            GUI o ficheros).
        text_color: ANSI del contenido.

    Returns:
        El marco completo como cadena multi-línea (sin newline final).

    Raises:
        ValueError: Estilo desconocido o alineación inválida.
    """
    if style not in _BOX_STYLES:
        valid = ", ".join(sorted(_BOX_STYLES))
        raise ValueError(f"Estilo de marco desconocido: {style!r} ({valid})")
    if align not in ("left", "center", "right"):
        raise ValueError(f"Alineación inválida: {align!r}")

    tl, hz, tr, vt, bl, br = _BOX_STYLES[style]
    if isinstance(lines, str):
        lines = lines.splitlines() or [""]
    lines = list(lines)

    padding = max(0, padding)
    pad_v = max(0, pad_v)
    title_text = f" {title} " if title else ""

    # Ancho interior (entre bordes) que garantiza que todo cabe:
    # la línea más larga + padding, o el título + 1 relleno a cada lado.
    longest = max((visible_len(line) for line in lines), default=1)
    min_width = max(longest + 2 * padding, visible_len(title_text) + 2, 1)
    inner_width = max(min_width, width or 0)
    field_width = inner_width - 2 * padding

    if border_color == "none":
        border, reset = "", ""
    else:
        border = (border_color if border_color is not None
                  else get_theme().secondary)
        reset = AnsiPalette.RESET

    def border_line(fill: str) -> str:
        return f"{border}{fill}{reset}"

    def align_line(line: str) -> str:
        gap = field_width - visible_len(line)
        if gap <= 0:
            return line  # no truncar contenido del usuario
        if align == "center":
            left = gap // 2
            return f"{' ' * left}{line}{' ' * (gap - left)}"
        if align == "right":
            return f"{' ' * gap}{line}"
        return f"{line}{' ' * gap}"

    def content_row(line: str) -> str:
        side = " " * padding
        body = align_line(line)
        if text_color:
            body = f"{text_color}{body}{reset}"
        return border_line(f"{vt}{side}") + body + border_line(f"{side}{vt}")

    # Borde superior (con título opcional incrustado)
    if title_text:
        rest = inner_width - visible_len(title_text) - 1
        top = f"{tl}{hz}{title_text}{hz * rest}{tr}"
    else:
        top = f"{tl}{hz * inner_width}{tr}"

    rows: list[str] = [border_line(top)]
    empty = border_line(f"{vt}{' ' * inner_width}{vt}")
    rows.extend([empty] * pad_v)
    rows.extend(content_row(line) for line in lines)
    rows.extend([empty] * pad_v)
    rows.append(border_line(f"{bl}{hz * inner_width}{br}"))
    return "\n".join(rows)


def print_box(
    lines: str | Sequence[str],
    *,
    stream: TextIO = sys.stdout,
    **kwargs,
) -> None:
    """Imprime el resultado de :func:`box` (mismos argumentos)."""
    _write(stream, box(lines, **kwargs) + "\n")


def cyber_progress_bar(
    percent: float,
    *,
    width: int = 30,
    complete: str = "█",
    empty: str = "░",
    color: Optional[str] = None,
) -> str:
    """Barra de progreso estilo cyberpunk: ``[██████░░░░░░]  48.0%``.

    Args:
        percent: Progreso entre 0.0 y 1.0 (se acota).
        width: Ancho de la barra en caracteres.
        complete: Glifo de la parte completada.
        empty: Glifo de la parte vacía.
        color: ANSI opcional (por defecto, primary del tema).
    """
    percent = max(0.0, min(1.0, percent))
    width = max(2, width)
    filled = round(width * percent)
    bar = f"{complete * filled}{empty * (width - filled)}"
    base = f"[{bar}] {percent * 100:5.1f}%"
    if color is None and not os.environ.get("NO_COLOR"):
        color = get_theme().primary
    return f"{color}{base}{AnsiPalette.RESET}" if color else base


# ---------------------------------------------------------------------------
# Demo standalone
# ---------------------------------------------------------------------------
def _demo() -> None:
    """Recorre todos los efectos del módulo (auto-test visual)."""
    set_theme("matrix")
    clear_screen()
    print_banner()

    theme = get_theme()
    type_text("[*] Inicializando módulos del núcleo AZZAZEL...",
              cps=120, color=theme.secondary)
    type_text("[*] Verificando cadena de proxies (3 nodos)...",
              cps=120, color=theme.secondary)
    decrypt_text("[✓] CANAL CIFRADO ESTABLECIDO — AES-256-GCM",
                 color=theme.primary)
    glitch_text("[!] INTRUSO DETECTADO EN EL PUERTO 31337",
                color=theme.alert)

    print()
    print_box(
        [
            f"{theme.primary}[1]{AnsiPalette.RESET} VPN Manager   "
            f"{theme.primary}[2]{AnsiPalette.RESET} Proxy Suite   "
            f"{theme.primary}[3]{AnsiPalette.RESET} Tunnels",
            f"{theme.primary}[4]{AnsiPalette.RESET} Net Tools     "
            f"{theme.primary}[5]{AnsiPalette.RESET} Firewall      "
            f"{theme.primary}[0]{AnsiPalette.RESET} Exit",
        ],
        title="AZZAZEL MENU",
        align="center",
        width=52,
    )

    print()
    for step in (0.0, 0.35, 0.7, 1.0):
        print("  " + cyber_progress_bar(step, width=40))

    print()
    _logger().info("Demo de ascii_art finalizada.")
    matrix_rain(duration=2.0)  # solo se ve en un TTY real


if __name__ == "__main__":
    _demo()
