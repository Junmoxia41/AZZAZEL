# ⚡ AZZAZEL VPN v1.0 — Enterprise Network Warfare Suite

**AZZAZEL VPN** es una suite integral y de alta seguridad de túneles VPN cifrados con Perfect Forward Secrecy (PFS), cadenas de proxies multi-hop (con soporte nativo para autenticación corporativa NTLMv2 / MD4 puro), puente PC↔Móvil para compartir internet a smartphones/tablets, gestor de túneles SSH con redirección local (-L), remota (-R) y dinámica SOCKS5 (-D), escáner de red concurrente, firewall con DSL declarativo y Kill-Switch anti-fugas integrado, y servidor de telemetría REST/Prometheus en tiempo real con consola Web interactiva ("War Room") e interfaz gráfica nativa CustomTkinter v3.1.

---

## 🏛️ Resumen de Módulos y Arquitectura

| Sprint | Módulo | Ruta | Descripción |
| :--- | :--- | :--- | :--- |
| **0** | **Logging Engine** | `core/logger.py` | Logger asíncrono no bloqueante con buffer circular, niveles cyberpunk y formato estructurado. |
| **1** | **Crypto Engine** | `core/crypto_engine.py` | Cifrado simétrico autenticado AES-256-GCM / ChaCha20-Poly1305, KDF Scrypt/HKDF y AAD contextual. |
| **1** | **Config Manager** | `core/config_manager.py` | Gestor de configuración YAML con validación tipada y cifrado transparente de secretos en disco. |
| **2** | **NTLMv2 Native** | `security/ntlm.py` | Autenticación corporativa NTLMv2 pura en Python con motor MD4 propio (RFC 1320), HMAC-MD5 y Type 1/2/3. |
| **2** | **Upstream Proxy** | `proxy/upstream_proxy.py` | Conector HTTP CONNECT con autenticación Basic, NTLMv2 y reglas inteligentes de Bypass/No-Proxy. |
| **2** | **Proxy Chaining** | `proxy/proxy_chain.py` | Cadena multi-hop de proxies encadenados con failover, métricas de latencia y sondeo interactivo. |
| **3** | **VPN Tunneling** | `vpn/tunnel_manager.py` | Protocolo nativo **AZZ1** con PFS efímero X25519 (ECDH) + HKDF-SHA256, Anti-Replay de 64 bits y Keepalive. |
| **4** | **Mobile Bridge** | `bridge/mobile_bridge.py` | Puente TCP PC↔Móvil con emparejamiento por PIN de 6 dígitos, whitelist concurrente con Lock y ACL anti-SSRF. |
| **5** | **Network Tools** | `network/scanner.py` | Escáner de puertos TCP asíncrono con control de concurrencia semafórica y sweep ping de subred /30. |
| **6** | **Cyberpunk GUI** | `ui/gui/app.py` | Interfaz gráfica interactiva v3.1 CustomTkinter con 8 pestañas operativas y backend async persistente. |
| **7** | **Firewall Manager**| `firewall/fw_manager.py` | DSL declarativo para reglas de firewall (`iptables` / `netsh`) y generador de Kill-Switch restrictivo. |
| **7** | **Remote Shell** | `remote/remote_shell.py` | Cliente SSH interactivo con soporte de perfiles seguros, políticas de host keys y multiplexación. |
| **7** | **SSH Port Forward**| `tunnel/ssh_tunnel.py` | Redirección de puertos local (-L), inversa (-R) y proxy dinámico SOCKS5 RFC 1928 (-D) sobre SSH. |
| **7** | **Metrics & API** | `monitoring/` | Exporter Prometheus estructurado, servidor SSE en streaming `/api/v1/events` y Dashboard web "WAR ROOM". |
| **8** | **Test Suite** | `tests/` & `run_tests.py` | Suite formal con 55 pruebas unitarias y de integración continua al 100% de éxito. |

---

## 🚀 Instalación y Requisitos

### Requisitos del Sistema
- Python 3.9 o superior (probado hasta Python 3.13)
- Sistema Operativo: Linux (Debian, Ubuntu, Fedora, Arch) o Windows (10/11/Server)

### Dependencias Principales
```bash
pip install pyyaml cryptography paramiko customtkinter
# Para desarrollo y testing:
pip install pytest pytest-asyncio anyio
```

---

## 💻 Modos de Uso

### 1. Lanzador Inteligente (CLI vs GUI)
```bash
# Lanzador interactivo (detecta entorno y pregunta modo en primer uso):
python azzazel.py

# Forzar interfaz de línea de comandos (Consola):
python azzazel.py --cli

# Forzar interfaz gráfica (Ventana CustomTkinter):
python azzazel.py --gui

# Comprobar estado de componentes:
python azzazel.py status
```

### 2. Ejecutar Servidor o Cliente VPN
```bash
# Iniciar Servidor VPN AZZ1 en puerto 51820:
python azzazel.py --mode server

# Iniciar Cliente VPN conectando a un endpoint remoto:
python azzazel.py --mode client --peer 51.254.120.4:51820

# Iniciar Puente PC↔Móvil:
python azzazel.py --mode bridge
```

### 3. Ejecutar Suite de Pruebas de CI/CD
```bash
python run_tests.py
# O directamente con pytest:
pytest tests/ -v
```

---

## 🔒 Auditoría de Seguridad y Defensas Técnicas

1. **Perfect Forward Secrecy (PFS)**: En cada handshake VPN, el cliente y el servidor generan un par efímero X25519 (ECDH). La clave simétrica de sesión se deriva mediante HKDF-SHA256 combinando la PSK compartida, nonces criptográficos de 16 bytes y el secreto efímero compartido. Si la PSK se viese comprometida en el futuro, el tráfico capturado previamente no puede descifrarse.
2. **Cifrado en Reposo con AAD**: Los secretos en el archivo `config.yaml` (`vpn.keys.psk`, `proxy.upstream.password`, etc.) se almacenan cifrados con AES-256-GCM, inyectando la ruta canónica del campo como Datos Autenticados Adicionales (AAD). Esto previene ataques de trasplante donde un atacante intercambia valores cifrados entre campos.
3. **Control Anti-Replay de 64 bits**: Los paquetes de datos cifrados incluyen un contador monótono verificado mediante una ventana deslizante de 64 bits. Paquetes fuera de ventana o duplicados son descartados silenciosamente sin responder, protegiendo contra ataques de retransmisión.
4. **Kill-Switch Integrado con Firewall**: Al detectarse una pérdida de enlace irrevocable (tras reintentos exponenciales agotados), el Kill-Switch aplica automáticamente el conjunto de reglas `vpn_only_rules` mediante `FirewallManager`, aislando todo el tráfico saliente y evitando fugas de DNS sin cifrar.
5. **Mitigación Anti-SSRF en Bridge PC↔Mobile**: El servidor de puente móvil valida todos los destinos de conexión en capa 7, bloqueando cualquier intento de pivotaje no autorizado hacia `127.0.0.1`, `localhost` o la pila de loopback.
6. **Autenticación en Streaming SSE y REST API**: Soporte dual de autenticación Bearer mediante cabecera HTTP estándar y parámetro seguro `?token=` para EventSource / SSE en navegadores, con redacción total de contraseñas (`***`) en `/api/v1/config`.

---

## 📄 Licencia
Este software se distribuye bajo los términos de la Licencia MIT.
