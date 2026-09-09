"""
AZZAZEL tests/test_logger.py — Batería de pruebas de Logger.
"""
from pathlib import Path
import logging
from core.logger import setup_logger, get_logger, LoggerConfig, HackerConsoleFormatter


def test_logger_setup_and_levels(temp_dir: Path):
    log_file = temp_dir / "azzazel.log"
    cfg = LoggerConfig(
        log_file=log_file,
        level="DEBUG",
    )
    root_logger = setup_logger(config=cfg, force=True)
    logger = get_logger("test.audit")

    try:
        logger.debug("Debug message test")
        logger.info("Info message test")
        logger.warning("Warning message test")
        logger.error("Error message test")

        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "Debug message test" in content
        assert "Info message test" in content
        assert "Warning message test" in content
        assert "Error message test" in content
    finally:
        # Cierra el FileHandler antes de que la fixture `temp_dir` borre el
        # directorio temporal: en Windows no se puede eliminar un archivo
        # mientras sigue abierto por otro handle (a diferencia de Linux),
        # así que sin este cierre explícito el teardown falla con
        # PermissionError [WinError 32] solo en ese sistema operativo.
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
            handler.close()


def test_formatter_rendering():
    formatter = HackerConsoleFormatter(use_color=False)
    record = logging.LogRecord(
        name="vpn.tunnel",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Handshake completado: %s",
        args=("session_01",),
        exc_info=None,
    )
    formatted = formatter.format(record)
    assert "vpn.tunnel" in formatted
    assert "Handshake completado: session_01" in formatted
