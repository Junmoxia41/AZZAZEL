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
    setup_logger(config=cfg, force=True)
    logger = get_logger("test.audit")

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
