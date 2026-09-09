#!/usr/bin/env python3
"""
AZZAZEL VPN — reverse_tunnel.py
===============================
Establece un túnel inverso público a través de un proxy corporativo
(configurable por el usuario, sin datos precargados) hacia el Mobile Bridge local (:8765) con:

- 📁 Explorador de Archivos Remoto (Tu Google Drive Privado en la PC del trabajo).
- 📥 Gestor de Descargas Remotas (Pega un enlace en tu móvil y tu PC lo descarga a toda velocidad).
- 💻 Panel de Estado del PC (CPU, RAM, Espacio en Disco).
- 🌐 Navegador Web Proxy a través de Squid corporativo.
- 📱 Soporte de proxy HTTP/HTTPS para apps.

Uso:
    python reverse_tunnel.py
    python reverse_tunnel.py -u tu_usuario -p tu_contraseña --proxy-host proxy.tuempresa.com --proxy-port 3128
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import mimetypes
import os
import re
import shutil
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Callable, Optional

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config_manager import ConfigManager, is_encrypted_token
from core.logger import AnsiPalette, setup_logger


def _forward_pipe(source_sock: Any, dest_sock: Any) -> None:
    """Reenvía tráfico bidireccional entre dos sockets/canales."""
    def _pump(r: Any, w: Any) -> None:
        try:
            while True:
                data = r.recv(8192)
                if not data:
                    break
                w.sendall(data)
        except Exception:
            pass
        finally:
            try:
                if hasattr(w, "shutdown"):
                    w.shutdown(socket.SHUT_WR)
                elif hasattr(w, "close"):
                    w.close()
            except Exception:
                pass

    t1 = threading.Thread(target=_pump, args=(source_sock, dest_sock), daemon=True)
    t2 = threading.Thread(target=_pump, args=(dest_sock, source_sock), daemon=True)
    t1.start()
    t2.start()


# ---------------------------------------------------------------------------
# Portal Web Móvil y Explorador de Archivos (Puerto 8765)
# ---------------------------------------------------------------------------
def _get_system_vitals() -> dict[str, Any]:
    """Obtiene métricas rápidas de la PC (RAM, Disco, CPU aproximado)."""
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory()
        disk = shutil.disk_usage(Path.home())
        return {
            "cpu_percent": f"{cpu}%",
            "ram_used_gb": f"{ram.used / (1024**3):.1f} GB / {ram.total / (1024**3):.1f} GB ({ram.percent}%)",
            "disk_free_gb": f"{disk.free / (1024**3):.1f} GB libres de {disk.total / (1024**3):.1f} GB",
        }
    except Exception:
        disk = shutil.disk_usage(Path.home())
        return {
            "cpu_percent": "N/A",
            "ram_used_gb": "N/A",
            "disk_free_gb": f"{disk.free / (1024**3):.1f} GB libres de {disk.total / (1024**3):.1f} GB",
        }


def _render_file_explorer_html(current_dir: Path, public_url: str, user: str) -> str:
    """Renderiza el explorador de archivos con interfaz moderna para móvil."""
    home = Path.home()
    if not current_dir.exists() or not current_dir.is_dir():
        current_dir = home

    items = []
    try:
        entries = sorted(list(current_dir.iterdir()), key=lambda p: (not p.is_dir(), p.name.lower()))
        for entry in entries:
            if entry.name.startswith((".", "$")):
                continue
            is_dir = entry.is_dir()
            size_str = ""
            icon = "📁" if is_dir else "📄"
            if not is_dir:
                try:
                    sz = entry.stat().st_size
                    if sz > 1024 * 1024:
                        size_str = f"{sz / (1024 * 1024):.1f} MB"
                    else:
                        size_str = f"{sz / 1024:.1f} KB"
                except Exception:
                    size_str = "0 KB"

                ext = entry.suffix.lower()
                if ext in (".jpg", ".jpeg", ".png", ".webp", ".gif"):
                    icon = "🖼️"
                elif ext in (".mp4", ".mkv", ".avi", ".mov"):
                    icon = "🎬"
                elif ext in (".mp3", ".wav", ".flac"):
                    icon = "🎵"
                elif ext in (".zip", ".rar", ".7z", ".tar", ".gz"):
                    icon = "📦"
                elif ext in (".pdf", ".docx", ".xlsx", ".txt"):
                    icon = "📑"
                elif ext in (".py", ".js", ".html", ".css", ".json"):
                    icon = "💻"

            items.append({
                "name": entry.name,
                "is_dir": is_dir,
                "size": size_str,
                "icon": icon,
                "path": str(entry.resolve()),
            })
    except Exception as exc:
        items = [{"name": f"Error leyendo carpeta: {exc}", "is_dir": False, "size": "", "icon": "⚠", "path": ""}]

    parent_path = str(current_dir.parent.resolve()) if current_dir.parent != current_dir else ""

    # Atajos comunes
    shortcuts = [
        {"name": "🏠 Inicio", "path": str(home)},
        {"name": "📥 Descargas", "path": str(home / "Downloads")},
        {"name": "📄 Documentos", "path": str(home / "Documents")},
        {"name": "🖥️ Escritorio", "path": str(home / "Desktop")},
    ]
    if os.name == "nt":
        shortcuts.append({"name": "💿 Disco C:\\", "path": "C:\\"})

    vitals = _get_system_vitals()

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>AZZAZEL — Nube Privada & Control Remoto</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --card: rgba(16, 26, 44, 0.9);
            --border: #0abdc6;
            --text: #e2e8f0;
            --accent-green: #00ff41;
            --accent-cyan: #0abdc6;
            --accent-magenta: #ea00d9;
            --amber: #ffb700;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: radial-gradient(circle at top, #111e38 0%, #080c14 100%);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 12px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 14px;
        }}
        .header {{
            background: var(--card);
            border: 1px solid var(--accent-cyan);
            border-radius: 12px;
            padding: 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 0 15px rgba(10, 189, 198, 0.2);
        }}
        .logo {{ font-size: 18px; font-weight: bold; color: var(--accent-green); }}
        .badge {{
            background: rgba(0, 255, 65, 0.15);
            color: var(--accent-green);
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: bold;
        }}
        .tabs {{
            display: flex;
            gap: 6px;
            overflow-x: auto;
        }}
        .tab {{
            flex: 1;
            padding: 10px;
            text-align: center;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(10, 189, 198, 0.3);
            border-radius: 8px;
            color: var(--text);
            text-decoration: none;
            font-size: 12px;
            font-weight: bold;
            white-space: nowrap;
        }}
        .tab.active {{
            background: var(--accent-cyan);
            color: #000;
            border-color: var(--accent-cyan);
        }}
        .card {{
            background: var(--card);
            border: 1px solid rgba(10, 189, 198, 0.3);
            border-radius: 12px;
            padding: 14px;
        }}
        .shortcuts {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-bottom: 12px;
        }}
        .sc-btn {{
            background: rgba(10, 189, 198, 0.15);
            border: 1px solid var(--accent-cyan);
            color: #fff;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 11px;
            text-decoration: none;
        }}
        .breadcrumb {{
            background: rgba(0,0,0,0.4);
            padding: 8px 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 12px;
            color: var(--accent-cyan);
            word-break: break-all;
            margin-bottom: 12px;
        }}
        .file-list {{
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .file-row {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 12px;
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 8px;
            text-decoration: none;
            color: var(--text);
            transition: all 0.2s;
        }}
        .file-row:active {{ background: rgba(10, 189, 198, 0.2); }}
        .file-info {{ display: flex; align-items: center; gap: 10px; overflow: hidden; }}
        .file-name {{ font-size: 13px; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .file-size {{ font-size: 11px; color: #8fa0b8; margin-left: 8px; flex-shrink: 0; }}
        .input-text {{
            width: 100%;
            padding: 10px;
            background: rgba(0,0,0,0.4);
            border: 1px solid var(--accent-cyan);
            border-radius: 8px;
            color: #fff;
            font-size: 13px;
            margin-bottom: 10px;
            outline: none;
        }}
        .btn {{
            display: block;
            width: 100%;
            padding: 10px;
            background: linear-gradient(135deg, #0abdc6, #008b94);
            color: #000;
            font-weight: bold;
            text-align: center;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            text-decoration: none;
        }}
        .vitals-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
        }}
        .vital-box {{
            background: rgba(0,0,0,0.3);
            padding: 10px;
            border-radius: 8px;
            border-left: 3px solid var(--accent-cyan);
        }}
        .vital-title {{ font-size: 11px; color: #8fa0b8; text-transform: uppercase; }}
        .vital-val {{ font-size: 13px; font-weight: bold; color: #fff; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="logo">⚡ AZZAZEL CLOUD</div>
                <div style="font-size:11px;color:#8fa0b8;">PC Remota ({user})</div>
            </div>
            <span class="badge">● ONLINE</span>
        </div>

        <div class="tabs">
            <a href="/files" class="tab active">📁 Archivos de la PC</a>
            <a href="/downloader" class="tab">📥 Descargar a la PC</a>
            <a href="/pcinfo" class="tab">💻 Estado PC</a>
            <a href="/" class="tab">🌐 Web Proxy</a>
        </div>

        <div class="card">
            <div class="shortcuts">
                {''.join(f'<a href="/files?dir={urllib.parse.quote(sc["path"])}" class="sc-btn">{sc["name"]}</a>' for sc in shortcuts)}
            </div>

            <div class="breadcrumb">
                📍 {current_dir}
            </div>

            <!-- Subir archivo desde móvil -->
            <form action="/upload" method="POST" enctype="multipart/form-data" style="margin-bottom:12px;background:rgba(0,255,65,0.05);padding:10px;border-radius:8px;border:1px dashed var(--accent-green);">
                <input type="hidden" name="target_dir" value="{current_dir}">
                <div style="font-size:12px;font-weight:bold;color:var(--accent-green);margin-bottom:6px;">⬆ Subir archivo del móvil a esta carpeta:</div>
                <input type="file" name="file" style="font-size:12px;margin-bottom:8px;color:#fff;" required>
                <button type="submit" class="btn" style="background:var(--accent-green);color:#000;">Subir a la PC</button>
            </form>

            <div class="file-list">
                {f'<a href="/files?dir={urllib.parse.quote(parent_path)}" class="file-row" style="color:var(--amber);font-weight:bold;"><div class="file-info"><span>📂</span><span>.. (Subir carpeta)</span></div></a>' if parent_path else ''}
                {''.join(
                    f'<a href="/files?dir={urllib.parse.quote(it["path"])}" class="file-row"><div class="file-info"><span>{it["icon"]}</span><span class="file-name">{it["name"]}</span></div></a>'
                    if it["is_dir"] else
                    f'<a href="/download?file={urllib.parse.quote(it["path"])}" class="file-row"><div class="file-info"><span>{it["icon"]}</span><span class="file-name">{it["name"]}</span></div><span class="file-size">{it["size"]} ⬇</span></a>'
                    for it in items
                )}
            </div>
        </div>

        <div class="card">
            <div style="font-size:12px;color:#8fa0b8;text-align:center;">
                💾 Espacio Disco C: <b>{vitals['disk_free_gb']}</b>
            </div>
        </div>
    </div>
</body>
</html>"""


def _render_downloader_html(msg: str = "") -> str:
    """Renderiza el gestor de descargas remotas."""
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AZZAZEL — Descargas Remotas</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --card: rgba(16, 26, 44, 0.9);
            --border: #0abdc6;
            --text: #e2e8f0;
            --accent-green: #00ff41;
            --accent-cyan: #0abdc6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: radial-gradient(circle at top, #111e38 0%, #080c14 100%);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 12px;
            min-height: 100vh;
        }}
        .container {{ max-width: 600px; margin: 0 auto; display: flex; flex-direction: column; gap: 14px; }}
        .header {{
            background: var(--card);
            border: 1px solid var(--accent-cyan);
            border-radius: 12px;
            padding: 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .tabs {{ display: flex; gap: 6px; }}
        .tab {{
            flex: 1; padding: 10px; text-align: center;
            background: rgba(255,255,255,0.05); border: 1px solid rgba(10, 189, 198, 0.3);
            border-radius: 8px; color: var(--text); text-decoration: none; font-size: 12px; font-weight: bold;
        }}
        .tab.active {{ background: var(--accent-cyan); color: #000; }}
        .card {{ background: var(--card); border: 1px solid rgba(10, 189, 198, 0.3); border-radius: 12px; padding: 16px; }}
        .input-text {{
            width: 100%; padding: 12px; background: rgba(0,0,0,0.4);
            border: 1px solid var(--accent-cyan); border-radius: 8px; color: #fff; font-size: 13px; margin-bottom: 12px; outline: none;
        }}
        .btn {{
            display: block; width: 100%; padding: 12px;
            background: linear-gradient(135deg, #0abdc6, #008b94);
            color: #000; font-weight: bold; text-align: center; border: none; border-radius: 8px; cursor: pointer; font-size: 14px;
        }}
        .msg-box {{
            background: rgba(0,255,65,0.15); border: 1px solid var(--accent-green);
            color: var(--accent-green); padding: 10px; border-radius: 8px; font-size: 12px; margin-bottom: 12px; text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div style="font-size:18px;font-weight:bold;color:var(--accent-green);">📥 DESCARGAS EN TU PC</div>
            <span style="color:var(--accent-green);font-size:12px;font-weight:bold;">● ACTIVO</span>
        </div>

        <div class="tabs">
            <a href="/files" class="tab">📁 Archivos PC</a>
            <a href="/downloader" class="tab active">📥 Descargar a PC</a>
            <a href="/pcinfo" class="tab">💻 Estado PC</a>
            <a href="/" class="tab">🌐 Web Proxy</a>
        </div>

        <div class="card">
            {f'<div class="msg-box">{msg}</div>' if msg else ''}
            <div style="font-size:14px;font-weight:bold;color:var(--accent-cyan);margin-bottom:8px;">Poner a descargar en tu PC del trabajo:</div>
            <p style="font-size:12px;color:#8fa0b8;margin-bottom:14px;line-height:1.5;">
                Pega cualquier enlace directo (vídeo, película, ISO, programa, archivo zip). La PC de tu oficina lo descargará a toda velocidad usando el internet de la empresa y lo guardará en tu carpeta <b>Descargas</b>.
            </p>
            <form action="/remote_download" method="POST">
                <input type="text" name="url" class="input-text" placeholder="https://ejemplo.com/archivo.zip" required>
                <button type="submit" class="btn">🚀 Iniciar Descarga en la PC</button>
            </form>
        </div>
    </div>
</body>
</html>"""


def _render_pcinfo_html() -> str:
    """Renderiza la página de métricas de la PC."""
    v = _get_system_vitals()
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AZZAZEL — Estado PC</title>
    <style>
        :root {{ --bg: #0b0f19; --card: rgba(16, 26, 44, 0.9); --text: #e2e8f0; --accent-cyan: #0abdc6; --accent-green: #00ff41; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ background: radial-gradient(circle at top, #111e38 0%, #080c14 100%); color: var(--text); font-family: sans-serif; padding: 12px; }}
        .container {{ max-width: 600px; margin: 0 auto; display: flex; flex-direction: column; gap: 14px; }}
        .header {{ background: var(--card); border: 1px solid var(--accent-cyan); border-radius: 12px; padding: 14px; display: flex; justify-content: space-between; }}
        .tabs {{ display: flex; gap: 6px; }}
        .tab {{ flex: 1; padding: 10px; text-align: center; background: rgba(255,255,255,0.05); border: 1px solid rgba(10,189,198,0.3); border-radius: 8px; color: var(--text); text-decoration: none; font-size: 12px; font-weight: bold; }}
        .tab.active {{ background: var(--accent-cyan); color: #000; }}
        .card {{ background: var(--card); border: 1px solid rgba(10,189,198,0.3); border-radius: 12px; padding: 16px; }}
        .vital-box {{ background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; border-left: 3px solid var(--accent-cyan); margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div style="font-size:18px;font-weight:bold;color:var(--accent-green);">💻 ESTADO DE TU PC</div>
            <span style="color:var(--accent-green);font-size:12px;font-weight:bold;">● EN LÍNEA</span>
        </div>
        <div class="tabs">
            <a href="/files" class="tab">📁 Archivos PC</a>
            <a href="/downloader" class="tab">📥 Descargar a PC</a>
            <a href="/pcinfo" class="tab active">💻 Estado PC</a>
            <a href="/" class="tab">🌐 Web Proxy</a>
        </div>
        <div class="card">
            <div class="vital-box">
                <div style="font-size:11px;color:#8fa0b8;">DISCO DURO</div>
                <div style="font-size:14px;font-weight:bold;color:#fff;margin-top:4px;">{v['disk_free_gb']}</div>
            </div>
            <div class="vital-box">
                <div style="font-size:11px;color:#8fa0b8;">MEMORIA RAM</div>
                <div style="font-size:14px;font-weight:bold;color:#fff;margin-top:4px;">{v['ram_used_gb']}</div>
            </div>
            <div class="vital-box">
                <div style="font-size:11px;color:#8fa0b8;">USO DE CPU</div>
                <div style="font-size:14px;font-weight:bold;color:#fff;margin-top:4px;">{v['cpu_percent']}</div>
            </div>
        </div>
    </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Servidor HTTP / Bridge
# ---------------------------------------------------------------------------
class EmbeddedBridgeServer:
    """Servidor HTTP y Proxy CONNECT que escucha en 127.0.0.1:8765."""

    def __init__(
        self,
        bind_host: str = "127.0.0.1",
        bind_port: int = 8765,
        proxy_host: str = "",
        proxy_port: int = 0,
        username: str = "",
        password: str = "",
    ) -> None:
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self.public_url = "https://a.pinggy.io"
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def set_public_url(self, url: str) -> None:
        self.public_url = url

    def start(self) -> bool:
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.bind_host, self.bind_port))
            self._server_sock.listen(50)
            self._running = True
            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()
            return True
        except OSError:
            return False

    def _accept_loop(self) -> None:
        while self._running and self._server_sock:
            try:
                client_sock, _ = self._server_sock.accept()
                threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True).start()
            except Exception:
                break

    def _handle_client(self, client_sock: socket.socket) -> None:
        try:
            client_sock.settimeout(15.0)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client_sock.recv(1024)
                if not chunk:
                    break
                head += chunk

            if not head:
                client_sock.close()
                return

            header_bytes, _, rest_body = head.partition(b"\r\n\r\n")
            lines = header_bytes.split(b"\r\n")
            req_line = lines[0].decode("ascii", errors="ignore")
            parts = req_line.split(" ")
            if len(parts) < 2:
                client_sock.close()
                return

            method, path = parts[0].upper(), parts[1]

            # Parse headers
            headers = {}
            for l in lines[1:]:
                k, _, v = l.decode("ascii", errors="ignore").partition(":")
                headers[k.strip().lower()] = v.strip()

            content_len = int(headers.get("content-length", 0))
            body = bytearray(rest_body)
            while len(body) < content_len:
                more = client_sock.recv(min(8192, content_len - len(body)))
                if not more:
                    break
                body.extend(more)

            # --- CASO 0: Healthcheck Ping (/status) ---
            if path == "/status":
                resp_json = json.dumps({
                    "status": "online",
                    "user": self.username,
                    "proxy": f"{self.proxy_host}:{self.proxy_port}",
                    "public_url": self.public_url,
                    "timestamp": time.time(),
                }).encode("utf-8")
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Access-Control-Allow-Origin: *\r\n"
                    b"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                    b"Content-Length: " + str(len(resp_json)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n" + resp_json
                )
                client_sock.sendall(resp)
                client_sock.close()
                return

            # --- CASO 1: HTTP CONNECT (Proxy Apps) ---
            if method == "CONNECT":
                self._handle_connect(client_sock, path)
                return

            # --- CASO 2: Explorador de Archivos (/files) ---
            if path.startswith("/files"):
                target_dir = Path.home()
                if "?dir=" in path:
                    raw_dir = urllib.parse.unquote(path.split("?dir=", 1)[1].split("&", 1)[0])
                    target_dir = Path(raw_dir)
                html = _render_file_explorer_html(target_dir, self.public_url, self.username)
                self._send_html(client_sock, html)
                return

            # --- CASO 3: Descarga Directa de Archivo (/download?file=...) ---
            if path.startswith("/download?file="):
                raw_file = urllib.parse.unquote(path.split("?file=", 1)[1].split("&", 1)[0])
                file_p = Path(raw_file)
                self._stream_file(client_sock, file_p)
                return

            # --- CASO 4: Subida de Archivos desde el Móvil (/upload) ---
            if path == "/upload" and method == "POST":
                self._handle_upload(client_sock, headers, bytes(body))
                return

            # --- CASO 5: Gestor de Descargas Remotas (/downloader) ---
            if path == "/downloader":
                html = _render_downloader_html()
                self._send_html(client_sock, html)
                return

            # --- CASO 6: Acción de Descarga Remota (/remote_download) ---
            if path == "/remote_download" and method == "POST":
                url_to_dl = ""
                try:
                    form_str = body.decode("utf-8", errors="ignore")
                    params = urllib.parse.parse_qs(form_str)
                    url_to_dl = params.get("url", [""])[0]
                except Exception:
                    pass

                if url_to_dl:
                    threading.Thread(target=self._background_download, args=(url_to_dl,), daemon=True).start()
                    msg = f"🚀 ¡Descarga iniciada en tu PC para: {url_to_dl[:45]}...! Se guardará en tu carpeta Descargas."
                else:
                    msg = "⚠ Enlace no válido."

                html = _render_downloader_html(msg)
                self._send_html(client_sock, html)
                return

            # --- CASO 7: Estado PC (/pcinfo) ---
            if path == "/pcinfo":
                html = _render_pcinfo_html()
                self._send_html(client_sock, html)
                return

            # --- CASO 8: Web Proxy (/browse?url=...) ---
            if path.startswith("/browse"):
                target_url = "https://www.google.com"
                if "?url=" in path:
                    target_url = urllib.parse.unquote(path.split("?url=", 1)[1])
                elif "&url=" in path:
                    target_url = urllib.parse.unquote(path.split("&url=", 1)[1])
                if not target_url.startswith(("http://", "https://")):
                    target_url = "https://" + target_url
                self._handle_web_browse(client_sock, target_url)
                return

            # --- CASO 9: Portal Web Principal (GET /) ---
            target_dir = Path.home()
            html = _render_file_explorer_html(target_dir, self.public_url, self.username)
            self._send_html(client_sock, html)
        except Exception:
            try:
                client_sock.close()
            except Exception:
                pass

    def _send_html(self, client_sock: socket.socket, html_str: str) -> None:
        body = html_str.encode("utf-8")
        resp = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Access-Control-Allow-Origin: *\r\n"
            f"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii") + body
        client_sock.sendall(resp)
        client_sock.close()

    def _stream_file(self, client_sock: socket.socket, file_path: Path) -> None:
        """Envía un archivo al navegador móvil para descarga o vista previa."""
        try:
            if not file_path.exists() or not file_path.is_file():
                self._send_html(client_sock, "<h3>Archivo no encontrado</h3>")
                return

            ctype, _ = mimetypes.guess_type(str(file_path))
            if not ctype:
                ctype = "application/octet-stream"

            size = file_path.stat().st_size
            filename_clean = urllib.parse.quote(file_path.name)
            headers = [
                "HTTP/1.1 200 OK",
                f"Content-Type: {ctype}",
                f"Content-Length: {size}",
                f"Content-Disposition: attachment; filename*=UTF-8''{filename_clean}",
                "Access-Control-Allow-Origin: *",
                "Connection: close",
                "\r\n",
            ]
            client_sock.sendall("\r\n".join(headers).encode("ascii"))

            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    client_sock.sendall(chunk)
        except Exception:
            pass
        finally:
            client_sock.close()

    def _handle_upload(self, client_sock: socket.socket, headers: dict[str, str], body: bytes) -> None:
        """Procesa la subida de un archivo desde el móvil a la PC."""
        target_dir = Path.home() / "Downloads"
        try:
            ctype = headers.get("content-type", "")
            msg = BytesParser().parsebytes(f"Content-Type: {ctype}\r\n\r\n".encode() + body)
            for part in msg.walk():
                fn = part.get_filename()
                if fn:
                    save_path = target_dir / fn
                    save_path.write_bytes(part.get_payload(decode=True) or b"")
                    break
        except Exception:
            pass

        html = _render_file_explorer_html(target_dir, self.public_url, self.username)
        self._send_html(client_sock, html)

    def _background_download(self, url: str) -> None:
        """Descarga un archivo en segundo plano usando Squid de la empresa."""
        try:
            p = urllib.parse.urlparse(url)
            fn = Path(p.path).name or f"download_{int(time.time())}.bin"
            save_dest = Path.home() / "Downloads" / fn

            proxy_url = f"http://{self.username}:{self.password}@{self.proxy_host}:{self.proxy_port}"
            proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

            with opener.open(req, timeout=30.0) as resp, open(save_dest, "wb") as out_f:
                while chunk := resp.read(65536):
                    out_f.write(chunk)
        except Exception:
            pass

    def _handle_connect(self, client_sock: socket.socket, target: str) -> None:
        try:
            thost, _, tport = target.partition(":")
            port_num = int(tport) if tport else 443
            up_sock = SynchronousProxyTunnel.connect(
                proxy_host=self.proxy_host,
                proxy_port=self.proxy_port,
                target_host=thost,
                target_port=port_num,
                username=self.username,
                password=self.password,
                use_tls=False,
            )
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            _forward_pipe(client_sock, up_sock)
        except Exception:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client_sock.close()

    def _handle_web_browse(self, client_sock: socket.socket, target_url: str) -> None:
        try:
            p = urllib.parse.urlparse(target_url)
            scheme = p.scheme.lower() or "https"
            host = p.hostname or "www.google.com"
            port = p.port or (443 if scheme == "https" else 80)
            req_path = p.path if p.path else "/"
            if p.query:
                req_path += "?" + p.query

            if scheme == "https":
                sock = SynchronousProxyTunnel.connect(
                    proxy_host=self.proxy_host,
                    proxy_port=self.proxy_port,
                    target_host=host,
                    target_port=port,
                    username=self.username,
                    password=self.password,
                    use_tls=False,
                )
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s_tls = ctx.wrap_socket(sock, server_hostname=host)

                http_get = (
                    f"GET {req_path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: Mozilla/5.0 (Linux; Android 10; Mobile)\r\n"
                    f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    f"Accept-Encoding: identity\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                s_tls.sendall(http_get)

                raw_resp = bytearray()
                while True:
                    chunk = s_tls.recv(8192)
                    if not chunk:
                        break
                    raw_resp.extend(chunk)
                s_tls.close()
                raw_bytes = bytes(raw_resp)
            else:
                sock = socket.create_connection((self.proxy_host, self.proxy_port), timeout=12.0)
                auth_b64 = base64.b64encode(f"{self.username}:{self.password}".encode("latin1")).decode("ascii")
                http_get = (
                    f"GET {target_url} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n"
                    f"User-Agent: Mozilla/5.0 (Linux; Android 10; Mobile)\r\n"
                    f"Accept-Encoding: identity\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                sock.sendall(http_get)

                raw_resp = bytearray()
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    raw_resp.extend(chunk)
                sock.close()
                raw_bytes = bytes(raw_resp)

            if raw_bytes:
                h_part, sep, body_part = raw_bytes.partition(b"\r\n\r\n")
                top_bar = f"""
                <div style="position:sticky;top:0;left:0;right:0;background:#0d1117;color:#00ff41;padding:8px 12px;display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid #0abdc6;font-family:sans-serif;font-size:12px;z-index:9999999;">
                    <div>⚡ <b>AZZAZEL PROXY</b> ({self.username})</div>
                    <div>
                        <a href="/files" style="color:#0abdc6;text-decoration:none;font-weight:bold;margin-right:12px;">📁 Archivos</a>
                        <a href="/" style="color:#ffb700;text-decoration:none;font-weight:bold;">🏠 Inicio</a>
                    </div>
                </div>
                """.encode("utf-8")

                if b"<body" in body_part.lower():
                    body_part = re.sub(b"(<body[^>]*>)", b"\\1" + top_bar, body_part, count=1, flags=re.IGNORECASE)
                else:
                    body_part = top_bar + body_part

                client_sock.sendall(h_part + sep + body_part)
            else:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Conector Síncrono a Proxy Upstream
# ---------------------------------------------------------------------------
class SynchronousProxyTunnel:
    """Abre túneles HTTP CONNECT síncronos sobre sockets bloqueantes con soporte SSL/TLS."""

    @staticmethod
    def connect(
        proxy_host: str,
        proxy_port: int,
        target_host: str,
        target_port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 15.0,
        use_tls: bool = True,
    ) -> socket.socket:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        sock.settimeout(timeout)

        headers = [
            f"CONNECT {target_host}:{target_port} HTTP/1.1",
            f"Host: {target_host}:{target_port}",
        ]

        if username and password:
            token = base64.b64encode(f"{username}:{password}".encode("latin1")).decode("ascii")
            headers.append(f"Proxy-Authorization: Basic {token}")

        headers.append("Proxy-Connection: keep-alive")
        headers.append("User-Agent: AZZAZEL/1.0")

        req = "\r\n".join(headers) + "\r\n\r\n"
        sock.sendall(req.encode("ascii"))

        buf = bytearray()
        while not buf.endswith(b"\r\n\r\n"):
            b = sock.recv(1)
            if not b:
                sock.close()
                raise ConnectionError("El proxy corporativo cerró la conexión inesperadamente.")
            buf.extend(b)

        first_line = bytes(buf).split(b"\r\n")[0].decode("ascii", errors="ignore")
        parts = first_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            sock.close()
            raise ConnectionError(f"Respuesta no válida del proxy: {first_line}")

        status = int(parts[1])
        if status == 407:
            sock.close()
            raise PermissionError(f"Credenciales rechazadas por el proxy {proxy_host}:{proxy_port} (HTTP 407).")
        elif not (200 <= status < 300):
            sock.close()
            raise ConnectionError(f"Proxy rechazó CONNECT: {first_line}")

        if use_tls or target_port == 443:
            ctx = ssl.create_default_context()
            try:
                sock = ctx.wrap_socket(sock, server_hostname=target_host)
            except ssl.SSLError:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=target_host)

        sock.settimeout(None)
        return sock


# ---------------------------------------------------------------------------
# Gestor Principal del Túnel Inverso
# ---------------------------------------------------------------------------
class ReverseTunnelBridge:
    def __init__(
        self,
        config_path: Optional[Path] = None,
        server: str = "a.pinggy.io",
        server_port: int = 443,
        user: Optional[str] = None,
        password: Optional[str] = None,
        proxy_host: Optional[str] = None,
        proxy_port: Optional[int] = None,
        bridge_port: Optional[int] = None,
    ) -> None:
        self.cm = ConfigManager(config_path or (PROJECT_ROOT / "config.yaml"))
        self.cm.load_or_create()
        self.server = server
        self.server_port = server_port

        up = self.cm.config.proxy.upstream
        self.proxy_host = proxy_host or up.host or ""
        self.proxy_port = proxy_port or up.port or 0
        self.user = user or up.username or ""

        raw_pw = password or up.password or ""
        if is_encrypted_token(raw_pw):
            raw_pw = ""
        self.password = raw_pw

        self.local_port = bridge_port or getattr(self.cm.config.bridge, "port", 8765) or 8765
        self.embedded_server: Optional[EmbeddedBridgeServer] = None
        self.supabase_sync: Optional["SupabaseSyncManager"] = None

    def _ensure_supabase_session(self) -> None:
        """Inicia sesión en Supabase Auth con la MISMA cuenta que usa la PWA.

        Esta sesión es la que permite publicar el túnel y leer/guardar el
        proxy corporativo del usuario; nunca se usan credenciales quemadas.
        """
        from core.supabase_sync import SupabaseSyncManager, SupabaseAuthError

        self.supabase_sync = SupabaseSyncManager()
        print(f"\n{AnsiPalette.NEON_CYAN}Inicia sesión con tu cuenta AZZAZEL (la misma de la app web):{AnsiPalette.RESET}")
        for _ in range(3):
            email = input(f"{AnsiPalette.NEON_CYAN}Correo: {AnsiPalette.RESET}").strip()
            try:
                sb_password = getpass.getpass(f"{AnsiPalette.NEON_CYAN}Contraseña: {AnsiPalette.RESET}")
            except Exception:
                sb_password = input(f"{AnsiPalette.NEON_CYAN}Contraseña: {AnsiPalette.RESET}")
            try:
                self.supabase_sync.sign_in(email, sb_password)
                print(f"{AnsiPalette.MATRIX_GREEN}✔ Sesión iniciada como {email}{AnsiPalette.RESET}")
                return
            except SupabaseAuthError as exc:
                print(f"{AnsiPalette.NEON_RED}[✖] {exc}{AnsiPalette.RESET}")
        raise RuntimeError("No fue posible iniciar sesión en Supabase tras varios intentos.")

    def _ensure_credentials(self) -> None:
        # El proxy corporativo se guarda SIEMPRE en Supabase, por usuario —
        # nunca en config.yaml local ni con valores por defecto en el código.
        remote_proxy = None
        if self.supabase_sync and self.supabase_sync.is_authenticated:
            remote_proxy = self.supabase_sync.fetch_proxy_config()
            if remote_proxy:
                self.proxy_host = self.proxy_host or remote_proxy.get("proxy_host") or ""
                self.proxy_port = self.proxy_port or remote_proxy.get("proxy_port") or 0
                self.user = self.user or remote_proxy.get("proxy_username") or ""
                self.password = self.password or remote_proxy.get("proxy_password") or ""

        if not self.proxy_host:
            self.proxy_host = input(f"{AnsiPalette.NEON_CYAN}Host del proxy corporativo (ej. proxy.tuempresa.com): {AnsiPalette.RESET}").strip()
        if not self.proxy_port:
            raw_port = input(f"{AnsiPalette.NEON_CYAN}Puerto del proxy (ej. 3128): {AnsiPalette.RESET}").strip()
            self.proxy_port = int(raw_port) if raw_port.isdigit() else 3128
        if not self.user:
            self.user = input(f"{AnsiPalette.NEON_CYAN}Usuario del proxy corporativo: {AnsiPalette.RESET}").strip()
        if not self.password:
            try:
                self.password = getpass.getpass(f"{AnsiPalette.NEON_CYAN}Contraseña del proxy para [{self.user}]: {AnsiPalette.RESET}")
            except Exception:
                self.password = input(f"{AnsiPalette.NEON_CYAN}Contraseña: {AnsiPalette.RESET}")

        # Guardar en Supabase para la próxima vez (cifrado en tránsito TLS,
        # protegido en reposo por RLS: solo el dueño puede leerlo).
        if self.supabase_sync and self.supabase_sync.is_authenticated and not remote_proxy:
            self.supabase_sync.save_proxy_config(
                self.proxy_host, self.proxy_port, self.user, self.password
            )

    def run_with_session(
        self,
        access_token: str,
        user_id: str,
        email: Optional[str] = None,
        on_url_found: Optional[Callable[[str], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Variante no interactiva para embeberse en la GUI (WebView).

        Recibe una sesión de Supabase YA iniciada por el usuario en el
        formulario web (mismo login que la PWA) en vez de pedir credenciales
        por terminal. El proxy corporativo se resuelve exclusivamente desde
        Supabase (``proxy_configs``) o desde los argumentos explícitos; si
        falta algo, se lanza :class:`RuntimeError` en vez de bloquear
        esperando ``input()``.
        """
        from core.supabase_sync import SupabaseSyncManager

        self.supabase_sync = SupabaseSyncManager()
        self.supabase_sync.use_session(access_token, user_id, email)

        remote_proxy = self.supabase_sync.fetch_proxy_config()
        if remote_proxy:
            self.proxy_host = self.proxy_host or remote_proxy.get("proxy_host") or ""
            self.proxy_port = self.proxy_port or remote_proxy.get("proxy_port") or 0
            self.user = self.user or remote_proxy.get("proxy_username") or ""
            self.password = self.password or remote_proxy.get("proxy_password") or ""

        if not (self.proxy_host and self.proxy_port and self.user and self.password):
            error = (
                "Falta configurar el proxy corporativo (host, puerto, usuario y "
                "contraseña) en Ajustes antes de iniciar el túnel."
            )
            if on_error:
                on_error(error)
                return
            raise RuntimeError(error)

        self._run_tunnel(on_url_found=on_url_found, on_error=on_error)

    def run(self) -> None:
        self._ensure_supabase_session()
        self._ensure_credentials()
        self._run_tunnel()

    def _run_tunnel(
        self,
        on_url_found: Optional[Callable[[str], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.embedded_server = EmbeddedBridgeServer(
            bind_host="127.0.0.1",
            bind_port=self.local_port,
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            username=self.user,
            password=self.password,
        )
        started = self.embedded_server.start()
        if started:
            print(f"{AnsiPalette.MATRIX_GREEN} [0/3] 🌐 Nube Privada y Servidor de Archivos iniciado en 127.0.0.1:{self.local_port}{AnsiPalette.RESET}")

        print(f"\n{AnsiPalette.NEON_CYAN} [1/3] 🔌 Conectando al proxy corporativo {self.proxy_host}:{self.proxy_port} (Usuario: {self.user})...{AnsiPalette.RESET}")

        try:
            tunneled_sock = SynchronousProxyTunnel.connect(
                proxy_host=self.proxy_host,
                proxy_port=self.proxy_port,
                target_host=self.server,
                target_port=self.server_port,
                username=self.user,
                password=self.password,
                use_tls=(self.server_port == 443),
            )
        except Exception as exc:
            msg = f"Error conectando con el proxy ({self.proxy_host}:{self.proxy_port}): {exc}"
            print(f"\n{AnsiPalette.NEON_RED}[✖] {msg}{AnsiPalette.RESET}")
            if on_error:
                on_error(msg)
            return

        print(f"{AnsiPalette.MATRIX_GREEN} [2/3] ✔ Autenticación Squid exitosa. Canal seguro TLS/CONNECT abierto hacia {self.server}:{self.server_port}{AnsiPalette.RESET}")
        print(f"{AnsiPalette.NEON_CYAN} [3/3] 🚀 Generando enlace público seguro para tu móvil...{AnsiPalette.RESET}")

        try:
            import paramiko
        except ImportError:
            msg = "Falta Paramiko. Ejecuta 'python install_deps.py -y' primero."
            print(f"{AnsiPalette.NEON_RED}[✖] {msg}{AnsiPalette.RESET}")
            if on_error:
                on_error(msg)
            return

        try:
            transport = paramiko.Transport(tunneled_sock)
            transport.set_keepalive(15)
            transport.start_client()

            ephemeral_key = paramiko.RSAKey.generate(2048)
            transport.auth_publickey("pinggy", ephemeral_key)

            channel = transport.open_session()
            channel.get_pty()
            channel.invoke_shell()

            transport.request_port_forward("", 0, handler=self._handle_incoming_connection)

            time.sleep(2.5)
            banner = b""
            while channel.recv_ready():
                banner += channel.recv(4096)

            banner_text = banner.decode("utf-8", errors="ignore")
            found_urls = set(re.findall(r"https?://[a-zA-Z0-9_\-\.]+\.(?:pinggy\.net|pinggy-free\.link)", banner_text))

            if found_urls:
                first_url = sorted(list(found_urls))[0]
                if self.embedded_server:
                    self.embedded_server.set_public_url(first_url)
                if self.supabase_sync and self.supabase_sync.is_authenticated:
                    try:
                        self.supabase_sync.publish_tunnel(first_url)
                        self.supabase_sync.start_heartbeat()
                    except Exception:
                        pass
                if on_url_found:
                    on_url_found(first_url)

            pwa_url = "https://azzazel-vpn.vercel.app"
            if found_urls:
                pwa_url += f"/?tunnel={sorted(list(found_urls))[0]}"

            print(f"\n{AnsiPalette.MATRIX_GREEN}======================================================================{AnsiPalette.RESET}")
            print(f"{AnsiPalette.NEON_CYAN}🌟 ¡NUBE PRIVADA Y CONTROL REMOTO ACTIVADO!{AnsiPalette.RESET}")
            print(f"{AnsiPalette.WHITE}📱 Tu PWA Móvil:          {AnsiPalette.BOLD}{pwa_url}{AnsiPalette.RESET}")
            for u in sorted(found_urls):
                print(f"{AnsiPalette.WHITE}👉 Enlace Directo:        {AnsiPalette.BOLD}{u}{AnsiPalette.RESET}")
            print(f"{AnsiPalette.WHITE}👉 Bridge Local:          {AnsiPalette.BOLD}127.0.0.1:{self.local_port}{AnsiPalette.RESET}")
            print(f"{AnsiPalette.MATRIX_GREEN}======================================================================{AnsiPalette.RESET}")
            print(f"\n{AnsiPalette.AMBER}📱 Abre la PWA en tu teléfono ({pwa_url}) para:{AnsiPalette.RESET}")
            print(f"   • 📁 Explorar Este Equipo (Disco C:, Descargas, Documentos).")
            print(f"   • ⬆ Subir fotos y archivos desde tu móvil directamente al PC.")
            print(f"   • 📥 Poner a descargar archivos en la PC con la fibra de la empresa.")
            print(f"   • 💻 Ver el estado de RAM, CPU y disco duro de tu PC en tiempo real.\n")
            print(f"{AnsiPalette.DARK_GRAY}Presiona Ctrl+C para finalizar.{AnsiPalette.RESET}")

            while transport.is_active():
                time.sleep(1.0)
        except Exception as exc:
            print(f"{AnsiPalette.AMBER}[i] Estado del túnel: {exc}{AnsiPalette.RESET}")
        finally:
            if self.embedded_server:
                self.embedded_server.stop()
            try:
                transport.close()
            except Exception:
                pass

    def _handle_incoming_connection(self, channel: Any, origin: tuple[str, int], server: tuple[str, int]) -> None:
        try:
            local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_sock.connect(("127.0.0.1", self.local_port))
            _forward_pipe(channel, local_sock)
        except Exception as exc:
            channel.close()


def main() -> int:
    setup_logger()
    parser = argparse.ArgumentParser(description="Nube Privada y Túnel Inverso AZZAZEL")
    parser.add_argument("--server", type=str, default="a.pinggy.io", help="Servidor de túnel público (default: a.pinggy.io)")
    parser.add_argument("--server-port", type=int, default=443, help="Puerto del servidor público (default: 443)")
    parser.add_argument("--user", "-u", type=str, default=None, help="Usuario del proxy corporativo")
    parser.add_argument("--password", "-p", "--pass", type=str, default=None, help="Contraseña del proxy corporativo")
    parser.add_argument("--proxy-host", type=str, default=None, help="Host del proxy corporativo (p. ej. proxy.tuempresa.com)")
    parser.add_argument("--proxy-port", type=int, default=None, help="Puerto del proxy corporativo (ej. 3128)")
    parser.add_argument("--bridge-port", type=int, default=None, help="Puerto local del Bridge (default: 8765)")
    args = parser.parse_args()

    bridge = ReverseTunnelBridge(
        server=args.server,
        server_port=args.server_port,
        user=args.user,
        password=args.password,
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        bridge_port=args.bridge_port,
    )
    try:
        bridge.run()
    except KeyboardInterrupt:
        print("\n[»] Túnel inverso detenido por el usuario.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
