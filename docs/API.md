# 🌐 AZZAZEL VPN — Especificación de API REST (API.md)

La API REST de **AZZAZEL VPN** proporciona telemetría, métricas en vivo, streaming de eventos en tiempo real (SSE) y control administrativo sobre los subsistemas.

---

## 1. Configuración de Red y Seguridad

- **Puerto por Defecto:** `9999` (TCP)
- **Host de Escucha Seguro:** `127.0.0.1` (o configurable para bind de red)
- **Autenticación:** Cabecera HTTP `Authorization: Bearer <auth_token>`
- **Rate Limiting:** Por IP cliente con ventana deslizante (default: 100 req/min)

---

## 2. Endpoints Disponibles

### `GET /health`
Comprobación de salud pública (no requiere autenticación).
- **Respuesta 200 OK:**
```json
{
  "ok": true,
  "alive": true,
  "uptime_s": 1245.8
}
```

---

### `GET /api/v1/status`
Estado detallado del sistema, subsistemas activos y parámetros de red.
- **Autenticación:** Requerida.
- **Respuesta 200 OK:**
```json
{
  "ok": true,
  "product": "AZZAZEL VPN",
  "version": "1.0.0",
  "mode": "client",
  "services": {
    "vpn": "RUNNING",
    "proxy": "STOPPED",
    "bridge": "RUNNING"
  },
  "vitals": {
    "cpu_percent": 3.4,
    "memory_mb": 42.1,
    "threads": 6
  }
}
```

---

### `GET /api/v1/metrics`
Métricas operativas del túnel y tráfico.
- **Parámetros de Query:** `?fmt=prom` para exportación en formato estándar de Prometheus.
- **Respuesta 200 OK (JSON):**
```json
{
  "ok": true,
  "counters": {
    "vpn_rx_bytes": 1048576,
    "vpn_tx_bytes": 5242880,
    "vpn_replays_dropped": 0
  },
  "gauges": {
    "active_sessions": 1,
    "rtt_ms": 12.4
  }
}
```

---

### `GET /api/v1/logs`
Recupera los últimos registros del buffer circular en memoria (`LogRing`).
- **Parámetros de Query:** `?n=50` (máximo 1000).
- **Respuesta 200 OK:**
```json
{
  "ok": true,
  "lines": [
    "[16:00:01] [INFO   ] [vpn.tunnel] Handshake completado con peer 198.51.100.2:51820",
    "[16:00:26] [DEBUG  ] [vpn.tunnel] Keepalive enviado (counter=10)"
  ]
}
```

---

### `GET /api/v1/events`
Streaming Server-Sent Events (SSE) para actualizaciones en vivo de telemetría y logs.
- **Content-Type:** `text/event-stream`
- **Formato:** `data: {"type": "heartbeat", "time": 1725800000, "metrics": {...}}\n\n`
