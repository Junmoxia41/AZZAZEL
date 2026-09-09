#!/usr/bin/env python3
"""
AZZAZEL scripts/release_clean.py — Higiene y limpieza de artefactos temporales para release.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

ARTIFACT_DIRS = {
    "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    ".coverage", "htmlcov", "build", "dist", "*.egg-info",
}

ARTIFACT_PATTERNS = {
    "*.pyc", "*.pyo", "*.pyd", "*.bak", "*.tmp", "*.swp",
}


def clean_repository(root: Path, dry_run: bool = False) -> int:
    removed_count = 0
    print(f"🧹 Limpiando artefactos de release en {root} (dry_run={dry_run})...")

    # 1. Eliminar directorios de artefactos
    for dirpath, dirnames, _ in os.walk(root):
        for d in list(dirnames):
            if d in ARTIFACT_DIRS or d.endswith(".egg-info"):
                target = Path(dirpath) / d
                rel = target.relative_to(root)
                print(f"  [DIR] Eliminando: {rel}")
                if not dry_run:
                    shutil.rmtree(target, ignore_errors=True)
                removed_count += 1
                dirnames.remove(d)

    # 2. Eliminar archivos temporales
    for pattern in ARTIFACT_PATTERNS:
        for fpath in root.rglob(pattern):
            rel = fpath.relative_to(root)
            print(f"  [FILE] Eliminando: {rel}")
            if not dry_run:
                try:
                    fpath.unlink()
                except Exception:
                    pass
            removed_count += 1

    print(f"✨ Limpieza completada: {removed_count} artefactos tratados.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Limpieza de artefactos pre-release")
    parser.add_argument("--dry-run", action="store_true", help="Muestra qué se eliminaría sin borrar")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    return clean_repository(root, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
