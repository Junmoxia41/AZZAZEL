# 📦 AZZAZEL VPN — Inventario Técnico de Archivos y Componentes

Este inventario clasifica y detalla todos los archivos, módulos, dependencias y artefactos que componen el repositorio de **AZZAZEL VPN v1.0**.

---

## 🏛️ Estructura y Módulos del Proyecto

| Ruta Relativa | Tamaño (Bytes) | Líneas | Módulo / Propósito |
| :--- | :--- | :--- | :--- |
| `azzazel.py` | 59,992 | 1,510 | Entry Point unificado CLI / Daemon / Dispatcher |
| `config.yaml` | 2,739 | 139 | Configuración declarativa base |
| `pyproject.toml` | 1,120 | 45 | Metadatos PEP 621 / Build configuration |
| `requirements.txt` | 2,188 | 50 | Requisitos y dependencias de entorno |
| `pytest.ini` | 125 | 6 | Configuración del runner pytest |
| `run_tests.py` | 2,239 | 48 | Runner visual de CI/CD |
| `README.md` | 5,575 | 71 | Documentación principal del sistema |
| `ARCHITECTURE.md` | 6,317 | 94 | Especificación de arquitectura y componentes |
| `SECURITY.md` | 2,671 | 32 | Políticas y modelos de mitigación criptográfica |
| `core/__init__.py` | 199 | 9 | Paquete Core |
| `core/version.py` | 450 | 15 | Origen canónico de versión (`1.0.0`) |
| `core/logger.py` | 20,504 | 480 | Logging asíncrono no bloqueante y buffer circular |
| `core/crypto_engine.py` | 25,012 | 580 | Cifrado simétrico AES-256-GCM, KDF y AAD |
| `core/config_manager.py` | 39,844 | 740 | Validación tipada de configuración y secretos en reposo |
| `security/__init__.py` | 199 | 9 | Paquete Security |
| `security/ntlm.py` | 27,812 | 665 | Motor NTLMv2 nativo con MD4 puro (RFC 1320) |
| `vpn/__init__.py` | 199 | 9 | Paquete VPN |
| `vpn/tunnel_manager.py` | 50,420 | 1,230 | Túnel cifrado AZZ1 con PFS X25519 y Kill-Switch |
| `proxy/__init__.py` | 199 | 9 | Paquete Proxy |
| `proxy/upstream_proxy.py` | 32,150 | 715 | Conector HTTP CONNECT corporativo y bypass |
| `proxy/proxy_chain.py` | 24,110 | 530 | Cadenas multi-hop con failover y medición RTT |
| `bridge/__init__.py` | 199 | 9 | Paquete Bridge |
| `bridge/mobile_bridge.py` | 40,075 | 930 | Servidor PC↔Móvil con PIN y ACL anti-SSRF |
| `network/__init__.py` | 199 | 9 | Paquete Network |
| `network/scanner.py` | 25,820 | 565 | Escáner TCP asíncrono y sweep de red /30 |
| `firewall/__init__.py` | 199 | 9 | Paquete Firewall |
| `firewall/fw_manager.py` | 22,410 | 515 | DSL de reglas y aislamiento de red |
| `monitoring/__init__.py` | 199 | 9 | Paquete Monitoring |
| `monitoring/metrics.py` | 11,250 | 255 | Métricas Prometheus y sondas vitales |
| `monitoring/api_server.py` | 20,890 | 465 | API REST / SSE con Bearer token |
| `monitoring/dashboard.py` | 12,450 | 215 | Consola Web "War Room" interactiva |
| `remote/__init__.py` | 199 | 9 | Paquete Remote |
| `remote/remote_shell.py` | 20,120 | 460 | Shell SSH interactivo con validación de host keys |
| `tunnel/__init__.py` | 199 | 9 | Paquete Tunnel |
| `tunnel/ssh_tunnel.py` | 35,420 | 820 | SSH Port Forwarding (-L, -R, -D SOCKS5) |
| `ui/__init__.py` | 199 | 9 | Paquete UI |
| `ui/cli/__init__.py` | 199 | 9 | Paquete CLI UI |
| `ui/cli/ascii_art.py` | 38,150 | 850 | Renderizador ASCII Art, Matrix rain y paletas |
| `ui/gui/__init__.py` | 199 | 9 | Paquete GUI UI |
| `ui/gui/theme.py` | 3,120 | 80 | Paleta hacker y temas visuales |
| `ui/gui/app.py` | 78,410 | 1,920 | Interfaz CustomTkinter v3.1 |
| `tests/conftest.py` | 2,120 | 60 | Fixtures de pruebas compartidas |
| `tests/test_audit_security.py` | 3,450 | 85 | Tests de seguridad y auditoría P0 |
| `tests/test_cli_and_gui.py` | 2,850 | 70 | Tests de CLI, GUI y validaciones |
| `tests/test_config_manager.py` | 2,150 | 55 | Tests de esquema de configuración |
| `tests/test_crypto_engine.py` | 2,650 | 65 | Tests de primitivas criptográficas |
| `tests/test_fw_manager.py` | 2,450 | 60 | Tests de firewall y Kill-Switch |
| `tests/test_logger.py` | 1,850 | 45 | Tests de logging estructurado |
| `tests/test_metrics_and_api.py` | 3,250 | 80 | Tests de telemetría y API REST |
| `tests/test_mobile_bridge.py` | 2,650 | 65 | Tests de Bridge y pairing |
| `tests/test_ntlm.py` | 2,350 | 60 | Tests de autenticación NTLMv2 y MD4 |
| `tests/test_proxy_chain.py` | 1,950 | 50 | Tests de cadenas de proxies |
| `tests/test_remote_shell.py` | 3,150 | 80 | Tests de cliente SSH |
| `tests/test_scanner.py` | 2,250 | 55 | Tests de escaneo de puertos |
| `tests/test_ssh_tunnel.py` | 3,850 | 95 | Tests de túneles SSH |
| `tests/test_tunnel_manager.py` | 2,950 | 75 | Tests de handshake y replay window |
| `tests/test_upstream_proxy.py` | 2,750 | 70 | Tests de HTTP CONNECT y 407 |
