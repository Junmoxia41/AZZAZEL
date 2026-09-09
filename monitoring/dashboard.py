"""
AZZAZEL monitoring/dashboard.py — consola web embebida (Sprint 7).

Genera la página HTML/CSS/JS **completamente inline** (sin CDN, sin
fuentes externas: la consola funciona en air-gapped) servida por
:class:`monitoring.api_server.ApiServer` en ``/``:

- Tarjetas de estado (modo, uptime, sondas vitales) que se refrescan por
  *polling* contra ``/api/v1/status``.
- Stream **SSE** ``/api/v1/events`` → sparkline de actividad en canvas.
- Tabla de métricas (counters/gauges) contra ``/api/v1/metrics``.
- Cola de logs contra ``/api/v1/logs``.
- Toasts glitch estilo AZZAZEL (paleta matrix/cyber).

Uso::

    from monitoring.dashboard import dashboard_html
    html = dashboard_html(app_version="1.0.0")
"""
from __future__ import annotations

from typing import Optional

__all__ = ["dashboard_html"]

THEME = {
    "bg": "#011a0e",          # fondo matriz muy oscuro
    "panel": "#032313",
    "border": "#0abdc6",
    "fg": "#00ff41",
    "accent": "#ea00d9",
    "warn": "#ffb700",
    "danger": "#ff003c",
    "muted": "#0a6f47",
}


def dashboard_html(app_version: str = "1.0.0",
                   api_prefix: str = "/api/v1",
                   poll_ms: int = 4000) -> str:
    """HTML completo de la consola WAR ROOM (autocontenido).

    Args:
        app_version: Versión mostrada en la cabecera.
        api_prefix: Ruta base de los endpoints.
        poll_ms: Periodo de refresco por polling en milisegundos.

    Returns:
        Documento HTML válido, todo inline (CSS + JS incluidos).
    """
    c = THEME
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>AZZAZEL WAR ROOM</title>
<style>
* {{ box-sizing: border-box; }}
body {{ background: {c['bg']}; color: {c['fg']}; font-family: 'Courier New',
  monospace; margin: 0; padding: 0; }}
header {{ border-bottom: 2px solid {c['border']}; padding: 10px 20px;
  display: flex; justify-content: space-between; align-items: center; }}
h1 {{ margin: 0; font-size: 22px; letter-spacing: 4px;
  text-shadow: 0 0 8px {c['fg']}; }}
.badge {{ color: {c['warn']}; font-size: 12px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit,
  minmax(300px, 1fr)); gap: 12px; padding: 14px; }}
.card {{ background: {c['panel']}; border: 1px solid {c['border']};
  border-radius: 4px; padding: 10px; box-shadow: 0 0 6px
  rgba(10,189,198,.25); }}
.card h2 {{ margin: 0 0 8px 0; font-size: 13px; color: {c['border']};
  letter-spacing: 2px; border-bottom: 1px dashed {c['muted']};
  padding-bottom: 5px; }}
.kv {{ font-size: 13px; line-height: 1.5; white-space: pre-wrap; }}
canvas {{ width: 100%; height: 90px; background: #000; border: 1px solid
  {c['muted']}; }}
table {{ width: 100%; font-size: 12px; border-collapse: collapse; }}
td, th {{ text-align: left; padding: 2px 4px; border-bottom: 1px dotted
  {c['muted']}; }}
th {{ color: {c['accent']}; }}
#logs {{ max-height: 220px; overflow-y: auto; font-size: 11px;
  white-space: pre-wrap; }}
.toast {{ position: fixed; right: 16px; bottom: 16px; padding: 10px
  14px; border: 1px solid {c['accent']}; color: {c['accent']};
  background: #150013; animation: glitch .25s infinite alternate; }}
@keyframes glitch {{ from {{ transform: translateX(-2px) skewX(-3deg); }}
  to {{ transform: translateX(2px) skewX(3deg); }} }}
.ok {{ color: {c['fg']}; }} .bad {{ color: {c['danger']}; }}
</style>
</head>
<body>
<header>
  <h1>▓ AZZAZEL WAR ROOM</h1>
  <span class="badge">v{app_version} · consola http en vivo · sin CDN</span>
</header>
<div class="grid">
  <div class="card"><h2>◇ ESTADO</h2><div id="status" class="kv">
    cargando…</div></div>
  <div class="card"><h2>◇ ACTIVIDAD (SSE)</h2>
    <canvas id="spark" width="320" height="90"></canvas>
    <div id="sse-line" class="kv">esperando latidos…</div></div>
  <div class="card"><h2>◇ MÉTRICAS</h2>
    <table id="metrics"><tr><th>métrica</th><th>valor</th></tr></table>
  </div>
  <div class="card"><h2>◇ LOGS TAIL</h2><div id="logs"
    class="kv">…</div></div>
</div>
<div id="toast" class="toast" style="display:none"></div>
<script>
const API = "{api_prefix}";
const urlParams = new URLSearchParams(window.location.search);
let TOKEN = urlParams.get('token') || sessionStorage.getItem('azz_token') || "";

function toast(msg) {{ const t = document.getElementById('toast');
  t.textContent = msg; t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 2200); }}

async function getJson(path) {{
  const headers = {{}};
  if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
  const sep = path.includes('?') ? '&' : '?';
  const url = API + path + (TOKEN ? sep + 'token=' + encodeURIComponent(TOKEN) : '');
  const r = await fetch(url, {{ headers }});
  if (r.status === 401) {{
    const promptToken = prompt('API protegida por token. Introduzca el Bearer Auth Token:');
    if (promptToken) {{
      sessionStorage.setItem('azz_token', promptToken);
      TOKEN = promptToken;
      return getJson(path);
    }}
    throw new Error('401 Unauthorized');
  }}
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return await r.json();
}}

async function refresh() {{
  try {{
    const st = await getJson('/status');
    document.getElementById('status').innerHTML =
      'app: ' + st.app + ' (' + st.ok + ')\\nup: ' +
      st.uptime_human + ' (' + st.uptime_s + 's)\\n' +
      'vitals:\\n  ' + JSON.stringify(st.vitals, null, 2)
        .replace(/\\n/g, '\\n  ');
  }} catch (e) {{ toast('status KO: ' + e.message); }}
  try {{
    const m = await getJson('/metrics');
    const rows = Object.entries(m.counters)
      .concat(Object.entries(m.gauges))
      .map(([k, v]) => `<tr><td>${{k}}</td><td>${{v}}</td></tr>`)
      .join('');
    document.getElementById('metrics').innerHTML =
      '<tr><th>métrica</th><th>valor</th></tr>' + rows;
  }} catch (e) {{ toast('metrics KO: ' + e.message); }}
  try {{
    const lg = await getJson('/logs?n=20');
    document.getElementById('logs').textContent = lg.lines.join('\\n');
  }} catch (e) {{ toast('logs KO: ' + e.message); }}
}}

const sseUrl = API + '/events' + (TOKEN ? '?token=' + encodeURIComponent(TOKEN) : '');
const sse = new EventSource(sseUrl);
const ctx = document.getElementById('spark').getContext('2d');
let beats = [];
sse.addEventListener('vitals', ev => {{
  const d = JSON.parse(ev.data);
  beats.push(1); if (beats.length > 40) beats.shift();
  document.getElementById('sse-line').textContent =
    'latido #' + d.beat + ' · ' + d.uptime_s + 's · ' +
    Object.keys(d.vitals).length + ' sondas';
  ctx.clearRect(0, 0, 320, 90);
  ctx.fillStyle = '{c['fg']}';
  beats.forEach((v, i) => ctx.fillRect(i * 8, 80, 5, -42));
}});
sse.onerror = () => toast('SSE desconectado');
refresh(); setInterval(refresh, {poll_ms});
</script>
</body>
</html>"""


# =====================================================================
# Pruebas autónomas: python -m monitoring.dashboard
# =====================================================================
if __name__ == "__main__":
    import re

    print("╔══ monitoring/dashboard.py — demo: consola web autocontenida ══╗\n")

    html = dashboard_html(app_version="1.0.0")
    # A) autocontención estricta: NADA de recursos externos
    assert 'src="http' not in html and "href=\"http" not in html, \
        "CDNs prohibidos (air-gapped)"
    assert "@import" not in html and "fonts.googleapis" not in html
    print("  ✔ autocontenido: sin src/href externos, sin @import")
    # B) estructura & hooks de API (prefijo + rutas sueltas: JS concatena)
    for hook in ('"/api/v1"', "'/status'", "'/metrics'", "'/logs?n=20'",
                 "'/events'", "EventSource", "vitals"):
        assert hook in html, f"hook ausente: {hook}"
    print("  ✔ hooks API: status/metrics/logs/SSE/EventSource")
    # C) paleta AZZAZEL + glitch
    assert THEME["fg"] == "#00ff41" and html.count("#00ff41") >= 2
    assert "glitch" in html and "WAR ROOM" in html
    print("  ✔ estética: #00ff41 + toast glitch + cabecera WAR ROOM")
    # D) argumentos substituibles y estructura de documento
    html2 = dashboard_html(app_version="9.9.9", poll_ms=1000)
    assert "v9.9.9" in html2 and "1000" in html2
    assert html.strip().startswith("<!DOCTYPE html>")
    assert re.search(r"<script>.*</script>", html, re.S)
    print("  ✔ parametrizable: versión/poll inyectados correctamente")
    print("\n╔══ DEMO COMPLETA: Dashboard 4/4 baterías ✔ ══╗")
