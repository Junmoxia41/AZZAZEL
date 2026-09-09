@echo off
REM ===========================================================================
REM AZZAZEL — build local del .exe de Windows.
REM Ejecutar este script DENTRO de una PC/VM Windows (PyInstaller no puede
REM generar un .exe de Windows desde Linux/macOS).
REM
REM Requisitos previos:
REM   - Python 3.10+ instalado y en PATH (python --version)
REM   - Node.js 18+ instalado y en PATH (node --version)
REM
REM Uso:
REM   cd packaging
REM   build_windows.bat
REM ===========================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0\.."

echo [1/5] Instalando dependencias Python...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller
if errorlevel 1 goto :error

echo [2/5] Instalando dependencias de la PWA (npm)...
pushd web_pwa
call npm install
if errorlevel 1 goto :error_popd

echo [3/5] Compilando la PWA (vite build)...
call npm run build
if errorlevel 1 goto :error_popd
popd

echo [4/5] Generando el ejecutable con PyInstaller...
pyinstaller packaging\azzazel.spec --noconfirm --clean
if errorlevel 1 goto :error

echo [5/5] Empaquetando ZIP de distribucion...
powershell -NoProfile -Command "Compress-Archive -Path 'dist\AZZAZEL\*' -DestinationPath 'dist\AZZAZEL-windows.zip' -Force"

echo.
echo ============================================================
echo   Listo: dist\AZZAZEL\AZZAZEL.exe
echo   ZIP de distribucion: dist\AZZAZEL-windows.zip
echo ============================================================
exit /b 0

:error_popd
popd
:error
echo.
echo [X] El build fallo. Revisa el mensaje de error de arriba.
exit /b 1
