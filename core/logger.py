#!/usr/bin/env python3
"""
AZZAZEL VPN — core/logger.py
============================

Sistema de logging personalizado con estética de terminal hacker.

Proporciona salida dual (consola coloreada + archivo rotativo en texto
plano), un nivel personalizado ``SUCCESS``, iconos por nivel con
fallback ASCII y ganchos globales para excepciones no controladas.

Este módulo es autocontenido: no depende de ningún otro componente de
AZZAZEL, por lo que puede probarse de forma independiente::

    python core/logger.py          # demo con todos los niveles

Uso desde cualquier módulo del proyecto::

    from core.logger import get_logger

    log = get_logger("bridge")
    log.info("Servidor del puente iniciado en 0.0.0.0:9999")
    log.success("Cliente autenticado: pixel-7 (100.64.0.8)")
    log.warning("Heartbeat perdido (intento 2/10)")
    log.error("Fallo en el proxy upstream", exc_info=True)

La configuración global se realiza una sola vez al arrancar::

    from core.logger import LoggerConfig, setup_logger

    setup_logger(LoggerConfig(level="DEBUG", log_file="logs/azzazel.log"))

Formato de salida (consola)::

    [21:03:45] [✓] [bridge            ] Cliente autenticado

Formato de salida (archivo)::

    2026-09-07 21:03:45 | SUCCESS  | azzazel.bridge | Cliente autenticado

Compatibilidad: Windows y Linux (Python 3.10+). En Windows usa
``colorama`` si está instalada para habilitar ANSI en terminales
antiguas; el módulo funciona igualmente sin ella.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import TracebackType
from typing import Optional, TextIO

__all__ = [
    "APP_NAME",
    "SUCCESS_LEVEL",
    "LoggerConfig",
    "setup_logger",
    "get_logger",
    "install_global_exception_hook",
]

# ---------------------------------------------------------------------------
# Compatibilidad de ANSI en Windows (colorama es una dependencia opcional)
# ---------------------------------------------------------------------------
try:
    from colorama import init as _colorama_init

    _colorama_init(strip=False)
    _COLORAMA_AVAILABLE: bool = True
except ImportError:  # pragma: no cover - entorno mínimo sin colorama
    _COLORAMA_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constantes del módulo
# ---------------------------------------------------------------------------
APP_NAME: str = "azzazel"

#: Nivel personalizado entre INFO (20) y WARNING (30).
SUCCESS_LEVEL: int = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

DEFAULT_LOG_FILE: Path = Path("logs") / "azzazel.log"
DEFAULT_LEVEL: str = "INFO"
DEFAULT_MAX_SIZE_MB: int = 100
DEFAULT_ROTATION: int = 5

CONSOLE_DATE_FORMAT: str = "%H:%M:%S"
FILE_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
FILE_LOG_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)-28s | %(message)s"

_NAME_COLUMN_WIDTH: int = 18


class AnsiPalette:
    """Códigos ANSI true-color del tema visual AZZAZEL."""

    MATRIX_GREEN: str = "\033[38;2;0;255;65m"    # #00ff41 (texto principal)
    NEON_CYAN: str = "\033[38;2;10;189;198m"     # #0abdc6 (texto secundario)
    NEON_MAGENTA: str = "\033[38;2;234;0;217m"   # #ea00d9 (texto terciario)
    NEON_RED: str = "\033[38;2;255;0;60m"        # #ff003c (acentos/errores)
    AMBER: str = "\033[38;2;255;183;0m"          # #ffb700 (warnings)
    DARK_GRAY: str = "\033[38;2;85;85;85m"       # bordes inactivos
    WHITE: str = "\033[38;2;230;230;230m"
    BOLD: str = "\033[1m"
    DIM: str = "\033[2m"
    RESET: str = "\033[0m"


# Color asociado a cada nivel de log (los niveles intermedios heredan el
# estilo del nivel definido inmediatamente inferior).
_LEVEL_COLORS: dict[int, str] = {
    logging.DEBUG: AnsiPalette.DARK_GRAY,
    logging.INFO: AnsiPalette.NEON_CYAN,
    SUCCESS_LEVEL: AnsiPalette.MATRIX_GREEN,
    logging.WARNING: AnsiPalette.AMBER,
    logging.ERROR: AnsiPalette.NEON_RED,
    logging.CRITICAL: AnsiPalette.NEON_RED + AnsiPalette.BOLD,
}

# Iconos por nivel: set UTF-8 (terminales modernas) y set ASCII (fallback).
_UNICODE_ICONS: dict[int, str] = {
    logging.DEBUG: "·",
    logging.INFO: "»",
    SUCCESS_LEVEL: "✓",
    logging.WARNING: "⚠",
    logging.ERROR: "✗",
    logging.CRITICAL: "☠",
}

_ASCII_ICONS: dict[int, str] = {
    logging.DEBUG: ".",
    logging.INFO: "i",
    SUCCESS_LEVEL: "+",
    logging.WARNING: "!",
    logging.ERROR: "x",
    logging.CRITICAL: "#",
}


def _resolve_style(table: dict[int, str], levelno: int) -> str:
    """Resuelve el estilo de un nivel arbitrario.

    Args:
        table: Diccionario ``{nivel: estilo}`` con los niveles definidos.
        levelno: Nivel numérico del registro (puede ser personalizado).

    Returns:
        El estilo del nivel exacto, o el del nivel definido inmediatamente
        inferior, o el del nivel más bajo si ninguno es inferior.
    """
    style = table.get(levelno)
    if style is not None:
        return style
    for defined in sorted(table, reverse=True):
        if defined <= levelno:
            return table[defined]
    return table[min(table)]


def _supports_color(stream: TextIO) -> bool:
    """Detecta si el terminal acepta códigos de color ANSI.

    Respeta la variable de entorno estándar ``NO_COLOR`` y permite forzar
    color con ``AZZAZEL_FORCE_COLOR=1``.
    """
    if os.environ.get("AZZAZEL_FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR"):
        return False
    if _COLORAMA_AVAILABLE:
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def _supports_unicode(stream: TextIO) -> bool:
    """Detecta si la codificación del terminal admite iconos UTF-8."""
    encoding = getattr(stream, "encoding", "") or ""
    return "utf" in encoding.lower()


class HackerConsoleFormatter(logging.Formatter):
    """Formatter ANSI para consola: ``[hora] [icono] [módulo] mensaje``.

    Las líneas usan la paleta AZZAZEL: timestamp en gris oscuro, nombre
    del módulo en cyan neón, icono y mensaje en el color del nivel.
    """

    def __init__(self, use_color: bool = True, use_unicode: bool = True) -> None:
        """Inicializa el formatter.

        Args:
            use_color: Emite códigos ANSI de color.
            use_unicode: Usa iconos UTF-8 (``✓``, ``✗``...) en lugar de ASCII.
        """
        super().__init__(datefmt=CONSOLE_DATE_FORMAT)
        self.use_color = use_color
        self.use_unicode = use_unicode

    def format(self, record: logging.LogRecord) -> str:
        """Formatea un registro como línea de terminal hacker.

        Args:
            record: Registro de logging a formatear.

        Returns:
            Línea lista para imprimir (con traza adjunta si hubo excepción).
        """
        icon_table = _UNICODE_ICONS if self.use_unicode else _ASCII_ICONS
        icon = _resolve_style(icon_table, record.levelno)
        timestamp = self.formatTime(record, self.datefmt)

        module = record.name
        if module.startswith(APP_NAME + "."):
            module = module[len(APP_NAME) + 1:]

        message = record.getMessage()

        if self.use_color:
            color = _resolve_style(_LEVEL_COLORS, record.levelno)
            p = AnsiPalette
            line = (
                f"{p.DARK_GRAY}[{timestamp}]{p.RESET} "
                f"{color}[{icon}]{p.RESET} "
                f"{p.NEON_CYAN}[{module:<{_NAME_COLUMN_WIDTH}}]{p.RESET} "
                f"{color}{message}{p.RESET}"
            )
        else:
            line = (
                f"[{timestamp}] [{icon}] "
                f"[{module:<{_NAME_COLUMN_WIDTH}}] {message}"
            )

        if record.exc_info:
            line = f"{line}\n{self.formatException(record.exc_info)}"
        if record.stack_info:
            line = f"{line}\n{self.formatStack(record.stack_info)}"
        return line


@dataclass
class LoggerConfig:
    """Parámetros del sistema de logging.

    Mapea la sección ``logging`` de ``config.yaml`` (será cargada por
    ``core.config_manager`` en el paso 4).

    Attributes:
        level: Nivel mínimo ("DEBUG", "INFO", "SUCCESS", "WARNING", ...).
        log_file: Ruta del archivo de log rotativo.
        max_size_mb: Tamaño máximo del archivo antes de rotar.
        rotation: Número de archivos históricos a conservar.
        console_output: Activa la salida por consola.
        file_output: Activa la salida a archivo.
        use_color: Fuerza/desactiva color; ``None`` autodetecta el terminal.
        use_unicode: Fuerza/desactiva iconos UTF-8; ``None`` autodetecta.
    """

    level: str = DEFAULT_LEVEL
    log_file: str | Path = DEFAULT_LOG_FILE
    max_size_mb: int = DEFAULT_MAX_SIZE_MB
    rotation: int = DEFAULT_ROTATION
    console_output: bool = True
    file_output: bool = True
    use_color: Optional[bool] = None
    use_unicode: Optional[bool] = None


def _log_success(self: logging.Logger, msg: object, *args: object,
                 **kwargs: object) -> None:
    """Registra un mensaje con el nivel personalizado SUCCESS.

    Acepta los mismos argumentos que :meth:`logging.Logger.info`,
    incluidos ``exc_info``, ``extra`` y formato con ``%``.
    """
    if self.isEnabledFor(SUCCESS_LEVEL):
        self._log(SUCCESS_LEVEL, msg, args, **kwargs)


# Se inyecta en la clase base para que esté disponible en todos los loggers.
logging.Logger.success = _log_success  # type: ignore[attr-defined]


def parse_level(level: str | int) -> int:
    """Convierte un nombre de nivel (o entero) a su valor numérico.

    Args:
        level: Nombre ("DEBUG", "INFO", "SUCCESS"...) o entero.

    Returns:
        Valor numérico del nivel. Ante un nombre desconocido, ``INFO``.
    """
    if isinstance(level, int):
        return level
    resolved = logging.getLevelName(level.strip().upper())
    return resolved if isinstance(resolved, int) else logging.INFO


def _build_console_handler(config: LoggerConfig) -> logging.Handler:
    """Construye el handler de consola con el formatter hacker."""
    stream: TextIO = sys.stdout
    use_color = config.use_color
    if use_color is None:
        use_color = _supports_color(stream)
    use_unicode = config.use_unicode
    if use_unicode is None:
        use_unicode = _supports_unicode(stream)

    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        HackerConsoleFormatter(use_color=use_color, use_unicode=use_unicode)
    )
    handler.setLevel(logging.NOTSET)  # el filtrado lo hace el logger raíz
    return handler


def _build_file_handler(config: LoggerConfig) -> Optional[logging.Handler]:
    """Construye el handler de archivo rotativo (texto plano, sin ANSI).

    Devuelve ``None`` si el directorio o el archivo no pueden crearse
    (p. ej. por permisos); en ese caso el sistema sigue con solo consola.
    """
    try:
        log_path = Path(config.log_file).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(
            log_path,
            maxBytes=max(1, config.max_size_mb) * 1024 * 1024,
            backupCount=max(1, config.rotation),
            encoding="utf-8",
            errors="replace",
        )
        handler.setFormatter(
            logging.Formatter(FILE_LOG_FORMAT, datefmt=FILE_DATE_FORMAT)
        )
        handler.setLevel(logging.NOTSET)
        return handler
    except OSError as exc:
        print(
            f"[{APP_NAME}-logger] AVISO: no se pudo crear el archivo de log "
            f"'{config.log_file}': {exc}. Se continúa solo con consola.",
            file=sys.stderr,
        )
        return None


_configured: bool = False
_setup_lock = threading.Lock()


def setup_logger(config: Optional[LoggerConfig] = None,
                 force: bool = False) -> logging.Logger:
    """Inicializa el logger raíz ``azzazel`` con consola + archivo.

    La función es idempotente: llamadas posteriores devuelven el logger
    ya configurado sin duplicar handlers, salvo ``force=True``, que
    reemplaza la configuración (útil tras recargar ``config.yaml``).

    Args:
        config: Parámetros de logging; con ``None`` se usan los valores
            por defecto (INFO, ``logs/azzazel.log``, 100 MB x 5).
        force: Si es ``True``, reemplaza los handlers existentes.

    Returns:
        El logger raíz del proyecto, ya configurado.
    """
    global _configured
    config = config or LoggerConfig()
    root_logger = logging.getLogger(APP_NAME)

    with _setup_lock:
        if _configured and not force:
            return root_logger

        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
            handler.close()

        root_logger.setLevel(parse_level(config.level))
        root_logger.propagate = False  # evita duplicados vía logging.root

        if config.console_output:
            root_logger.addHandler(_build_console_handler(config))
        if config.file_output:
            file_handler = _build_file_handler(config)
            if file_handler is not None:
                root_logger.addHandler(file_handler)

        _configured = True

    return root_logger


def get_logger(name: str = "") -> logging.Logger:
    """Devuelve un logger hijo de ``azzazel`` listo para usar.

    Args:
        name: Nombre jerárquico del componente (p. ej. ``"vpn.server"``
            produce el logger ``azzazel.vpn.server``). Si ya lleva el
            prefijo de la aplicación no se duplica. Cadena vacía devuelve
            el logger raíz del proyecto.

    Returns:
        Logger que hereda los handlers y el nivel configurados en
        :func:`setup_logger`.
    """
    if not _configured:
        setup_logger()
    if not name or name == APP_NAME:
        return logging.getLogger(APP_NAME)
    if name.startswith(APP_NAME + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{APP_NAME}.{name}")


def install_global_exception_hook() -> None:
    """Registra como CRITICAL toda excepción no controlada.

    Instala ganchos en :data:`sys.excepthook` y
    :data:`threading.excepthook` de modo que las excepciones que matan al
    proceso (o a un hilo) queden en el log antes de morir. Esencial para
    depurar el modo ``--daemon``. ``KeyboardInterrupt`` mantiene su
    comportamiento normal para no interferir con Ctrl+C.
    """

    def _sys_hook(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_traceback: Optional[TracebackType],
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        get_logger("fatal").critical(
            "Excepción no controlada.",
            exc_info=(exc_type, exc_value, exc_traceback),
        )

    def _thread_hook(args: threading.ExceptHookArgs) -> None:
        thread_name = args.thread.name if args.thread else "?"
        get_logger("fatal").critical(
            "Excepción no controlada en el hilo '%s'.",
            thread_name,
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        )

    sys.excepthook = _sys_hook
    if hasattr(threading, "excepthook"):  # Python >= 3.8
        threading.excepthook = _thread_hook


def _demo() -> None:
    """Emite mensajes de todos los niveles para probar el módulo."""
    setup_logger(LoggerConfig(level="DEBUG", log_file=DEFAULT_LOG_FILE))
    log = get_logger("demo")

    log.debug("Inicializando subsistema de diagnóstico...")
    log.info("Cargando módulos del núcleo de AZZAZEL...")
    log.success("Proxy chain verificada (3/3 nodos operativos)")
    log.warning("Latencia alta en el nodo #2 (312 ms)")
    log.error("No se pudo abrir el socket UDP en el puerto 5353")
    log.critical("SIMULACRO: fallo catastrófico del túnel principal")

    try:
        _ = 1 / 0
    except ZeroDivisionError:
        log.exception("Ejemplo de traza capturada con log.exception")

    get_logger("").info(
        "Los mensajes anteriores también quedaron en %s", DEFAULT_LOG_FILE
    )


if __name__ == "__main__":
    _demo()
