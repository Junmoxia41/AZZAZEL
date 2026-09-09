# -*- mode: python ; coding: utf-8 -*-
"""
AZZAZEL — especificación de PyInstaller para generar el .exe de Windows.

Uso (debe ejecutarse EN Windows, PyInstaller no hace cross-compile):

    pip install -r requirements.txt
    pip install pyinstaller
    cd web_pwa && npm install && npm run build && cd ..
    pyinstaller packaging/azzazel.spec --noconfirm

El resultado queda en dist/AZZAZEL/AZZAZEL.exe (modo carpeta, arranque
rápido) y se empaqueta además como .zip listo para distribuir por el
workflow de GitHub Actions (ver .github/workflows/release-windows.yml).
"""

import sys
from pathlib import Path

block_cipher = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_PWA = PROJECT_ROOT / "web_pwa" / "dist"

if not DIST_PWA.exists():
    raise SystemExit(
        "No se encontró web_pwa/dist. Compila la PWA antes de empaquetar:\n"
        "  cd web_pwa && npm install && npm run build"
    )

# Incluye el build completo de la PWA (HTML/CSS/JS) dentro del .exe para que
# la ventana de escritorio (ui/webapp/desktop_window.py) pueda abrirlo sin
# depender de una instalación aparte.
datas = [
    (str(DIST_PWA), "web_pwa/dist"),
    (str(PROJECT_ROOT / "config.yaml"), "."),
]

hidden_imports = [
    "webview",
    "webview.platforms.winforms",
    "webview.platforms.edgechromium",
    "clr_loader",
    "pythonnet",
    "customtkinter",
    "PIL",
    "psutil",
    "paramiko",
    "yaml",
    "cryptography",
    "colorama",
]

a = Analysis(
    [str(PROJECT_ROOT / "azzazel.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter.test", "test", "tests"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AZZAZEL",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # ventana GUI, sin consola negra detrás
    icon=str(PROJECT_ROOT / "packaging" / "azzazel.ico")
    if (PROJECT_ROOT / "packaging" / "azzazel.ico").exists()
    else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="AZZAZEL",
)
