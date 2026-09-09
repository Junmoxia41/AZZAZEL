#!/usr/bin/env python3
"""
AZZAZEL scripts/secret_scan.py — Escáner estático de secretos y tokens en el repositorio.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# Patrones sospechosos de claves privadas, tokens y credenciales hardcodeadas
SECRET_PATTERNS = [
    (r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----", "Clave privada PEM"),
    (r"(?i)aws_access_key_id\s*=\s*['\"][A-Z0-9]{20}['\"]", "AWS Access Key"),
    (r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", "AWS Secret Key"),
    (r"ghp_[A-Za-z0-9_]{36,}", "GitHub Personal Access Token"),
    (r"glpat-[A-Za-z0-9\-_]{20,}", "GitLab Personal Access Token"),
    (r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", "Bearer Token no parametrizado"),
    (r"(?i)(?:password|passwd|secret|api_key)\s*=\s*['\"][^'\"]{8,}['\"]", "Posible contraseña/secreto en claro"),
]

IGNORED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache",
    ".mypy_cache", "build", "dist", "node_modules",
}

IGNORED_FILES = {
    "secret_scan.py", "PROJECT_INVENTORY.md", "AUDIT_BASELINE.md", "README.md",
}

IGNORED_EXTENSIONS = {
    ".pyc", ".png", ".jpg", ".ico", ".bin", ".md",
}


def scan_repo(root: Path) -> list[tuple[Path, int, str, str]]:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            if fname in IGNORED_FILES:
                continue
            fpath = Path(dirpath) / fname
            if fpath.suffix in IGNORED_EXTENSIONS:
                continue
            if "tests" in fpath.parts or "test" in fname:
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                sline = line.strip()
                if sline.startswith("#") or sline.startswith('"""') or sline.startswith("'''") or sline.startswith("*") or sline.startswith("//"):
                    continue
                if any(kw in sline.lower() for kw in ("placeholder", "dummy", "demo", "example", "prompt", "print", "test", "bearer token")):
                    continue
                for pattern, desc in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        findings.append((fpath, lineno, desc, line.strip()[:80]))
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    print(f"🔍 Escaneando repositorio {root} en busca de secretos hardcodeados...")
    findings = scan_repo(root)

    if not findings:
        print("✅ No se detectaron secretos hardcodeados ni credenciales en claro.")
        return 0

    print(f"⚠️ Se encontraron {len(findings)} posibles secretos:")
    for path, lineno, desc, snippet in findings:
        rel = path.relative_to(root)
        print(f"  ➜ {rel}:{lineno} [{desc}] -> {snippet}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
