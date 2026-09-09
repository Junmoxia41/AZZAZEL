# ⚙️ AZZAZEL VPN — Guía de Configuración Integral (CONFIGURATION.md)

Este documento detalla todas las secciones, directivas, tipos de datos y opciones disponibles en `config.yaml` para el despliegue y afinamiento de **AZZAZEL VPN**.

---

## 1. Esquema General de `config.yaml`

```yaml
azzazel:
  version: "1.0.0"
  mode: "client"              # server | client | bridge | mesh
  log_level: "INFO"           # DEBUG | INFO | WARNING | ERROR | CRITICAL
  ui:
    theme: "matrix"           # matrix | cyber | stealth | dracula

vpn:
  enabled: true
  protocol: "AZZ1"            # AZZ1 (nativo) | WireGuard (backend opcional)
  server:
    listen_address: "0.0.0.0"
    listen_port: 51820
    max_clients: 10
    network: "10.66.66.0/24"
  client:
    server_address: "vpn.corp.net"
    server_port: 51820
    auto_reconnect: true
    kill_switch: true
    keepalive: 25
  keys:
    private_key: "!enc:AES256GCM:..." # Clave maestra PSK protegida

proxy:
  local:
    enabled: true
    http_port: 8080
    socks5_port: 1080
    bind_address: "127.0.0.1"
  upstream:
    enabled: false
    host: "proxy.enterprise.lan"
    port: 8080
    auth_type: "basic"        # none | basic | digest | ntlm
    username: "DOMAIN\\user"
    password: "!enc:AES256GCM:..."

bridge:
  enabled: false
  host: "0.0.0.0"
  port: 47671
  security:
    max_devices: 5
    allow_localhost: false    # Anti-SSRF (default false)
    pair_ttl: 120

firewall:
  kill_switch: true
  engine: "auto"              # auto | iptables | nftables | netsh
  exceptions:
    - "192.168.1.0/24"
    - "10.0.0.0/8"

api:
  enabled: true
  host: "127.0.0.1"
  port: 9999
  auth_token: "!enc:AES256GCM:..."
  rate_limit: 100
  cors_origins:
    - "http://localhost:3000"
    - "http://127.0.0.1:9999"
```

---

## 2. Detalle de Secciones y Directivas

### 2.1. Sección `azzazel`
- `mode`: Modo de operación principal (`server`, `client`, `bridge`).
- `log_level`: Nivel de detalle de registro en consola y archivo rotativo.
- `ui.theme`: Esquema de colores para el CLI ANSI y la GUI (`matrix`, `cyber`, `stealth`, `dracula`).

### 2.2. Sección `vpn`
- `protocol`: Protocolo de túnel. `AZZ1` es el protocolo de alto rendimiento con PFS y ofuscación de frames; no confundir con `WireGuard`.
- `vpn.server.network`: Subred virtual IPv4 asignada dinámicamente a clientes conectados.
- `vpn.client.kill_switch`: Aísla el adaptador de red en caso de corte del túnel impidiendo fugas fuera del túnel VPN.

### 2.3. Gestión de Secretos en Reposo
Los campos marcados con el prefijo `!enc:AES256GCM:` se almacenan cifrados en disco. La clave maestra se ubica en `data/.azzazel.key` con permisos `0600`.
Al modificar un secreto vía CLI:
```bash
python azzazel.py --setup
```
El motor criptográfico genera un Nonce único de 96 bits, cifra con `AES-256-GCM` y vincula el nombre del campo como AAD para impedir ataques de trasplante.
