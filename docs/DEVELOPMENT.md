# 🛠️ AZZAZEL VPN — Guía de Desarrollo y Arquitectura (DEVELOPMENT.md)

Directrices de ingeniería, convenciones de código y arquitectura de **AZZAZEL VPN**.

---

## 1. Convenciones y Estilo de Código

- **Python 3.10+ Moderno**: Uso exhaustivo de Type Hints (`X | None`, `list[str]`, `dict[str, Any]`), dataclasses y context managers asíncronos.
- **Linters Obligatorios**:
  - `ruff`: Formateo de código y análisis de sintaxis.
  - `mypy`: Verificación estática de tipos.
  - `bandit`: Escaneo estático de seguridad AST.
- **Manejo de Errores**: Prohibido el uso de `except: pass` sin logging o captura de excepción específica. Toda degradación o fallo criptográfico debe propagar `HandshakeError` o excepciones de dominio tipadas.

---

## 2. Estructura de Paquetes

```text
azzazel-vpn/
├── azzazel.py              # CLI / Entrypoint y despachador principal
├── core/                   # Criptografía, configuración, logging, registro de servicios
├── protocol/               # Protocolo AZZ1: version, constants, framing, crypto, replay, handshake
├── vpn/                    # Túnel UDP, VpnSession, KillSwitch y capa TUN
├── proxy/                  # Upstream Proxy (HTTP/SOCKS5/NTLMv2) y ProxyChain
├── bridge/                 # Mobile Bridge PC↔Móvil, Pairing y Anti-SSRF ACL
├── firewall/               # Declarative DSL Firewall Manager (iptables/netsh)
├── network/                # PortScanner concurrente y enumeración de red
├── tunnel/                 # SSH Tunneling Manager (L/R/D Port Forwarding)
├── monitoring/             # ApiServer REST, MetricsRegistry, LogRing y Dashboard
├── security/               # NTLMv2 puro, IdentityManager, RBAC y control de acceso
├── ui/                     # Terminal CLI interactivo (Rich/ANSI) y GUI CustomTkinter
├── docs/                   # Documentación técnica completa
├── tests/                  # Baterías de pruebas unitarias, de integración y fuzzing
└── scripts/                # Herramientas de higiene, escaneo y release
```
