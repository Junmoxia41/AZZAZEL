"""
Pruebas exhaustivas para ui/cli/doctor.py (SystemDoctor).
"""
from __future__ import annotations

import sys
from unittest.mock import patch

from ui.cli.doctor import SystemDoctor, DiagnosticCheck


def test_system_doctor_all_checks():
    doc = SystemDoctor()
    results = doc.run_all()

    assert len(results) >= 6
    report_plain = doc.render_report(color=False)
    report_color = doc.render_report(color=True)

    assert "DIAGNÓSTICO DEL SISTEMA" in report_plain
    assert "ENTORNO" in report_plain
    assert "CRIPTOGRAFÍA" in report_plain
    assert "Resumen:" in report_plain
    assert "DIAGNÓSTICO DEL SISTEMA" in report_color


def test_doctor_python_version_check():
    doc = SystemDoctor()
    check = doc.check_python_version()
    assert check.passed is True
    assert "Python 3." in check.message

    with patch.object(sys, "version_info", (3, 8, 0)):
        check_fail = doc.check_python_version()
        assert check_fail.passed is False
        assert check_fail.remediation is not None


def test_doctor_crypto_primitives_check():
    doc = SystemDoctor()
    check = doc.check_crypto_primitives()
    assert check.passed is True
    assert "operan correctamente" in check.message


def test_doctor_port_availability_check():
    doc = SystemDoctor()
    # Test checking a known ephemeral bind
    is_free = doc.check_port_availability(0, "tcp")
    assert is_free is True
