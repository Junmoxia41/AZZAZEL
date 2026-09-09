"""
Pruebas unitarias para install_deps.py (DependencyAnalyzer, PipInstaller).
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from install_deps import (
    DependencyAnalyzer,
    DependencyCategory,
    DependencyItem,
    DependencyStatus,
    PipInstaller,
    sync_requirements_file,
)


def test_dependency_analyzer_scan_codebase():
    project_root = Path(__file__).resolve().parents[1]
    analyzer = DependencyAnalyzer(project_root)

    code_imports = analyzer.scan_codebase_imports()
    assert isinstance(code_imports, dict)
    assert "cryptography" in code_imports or "yaml" in code_imports or "customtkinter" in code_imports


def test_dependency_analyzer_parse_requirements():
    project_root = Path(__file__).resolve().parents[1]
    analyzer = DependencyAnalyzer(project_root)

    reqs = analyzer.parse_requirements_file()
    assert isinstance(reqs, dict)
    assert "cryptography" in reqs
    assert "pyyaml" in reqs


def test_dependency_analyzer_inspect_all():
    project_root = Path(__file__).resolve().parents[1]
    analyzer = DependencyAnalyzer(project_root)

    items = analyzer.inspect_dependencies(include_dev=True)
    assert len(items) >= 5

    crypto_item = next((it for it in items if it.pypi_name.lower() == "cryptography"), None)
    assert crypto_item is not None
    assert crypto_item.status == DependencyStatus.INSTALLED
    assert crypto_item.installed_version is not None


def test_pip_installer_empty_list():
    ok, msg = PipInstaller.install([])
    assert ok is True
    assert "Nada que instalar" in msg


def test_sync_requirements_file(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("cryptography>=41.0\n", encoding="utf-8")

    fake_item = DependencyItem(
        pypi_name="fake-package",
        import_name="fake_package",
        required_spec=">=1.0.0",
        declared_in_requirements=False,
    )

    updated = sync_requirements_file(req_file, [fake_item])
    assert updated is True

    new_content = req_file.read_text(encoding="utf-8")
    assert "fake-package>=1.0.0" in new_content
