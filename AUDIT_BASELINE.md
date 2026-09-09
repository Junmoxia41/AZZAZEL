# 📊 AZZAZEL VPN — Baseline de Auditoría Técnica

Este documento establece el estado de referencia (baseline) del código, suite de pruebas, análisis estático, escaneo de seguridad y soporte de plataforma antes de las fases de refactorización y endurecimiento.

---

## 1. Métricas de Cobertura y Pruebas
- **Total de Pruebas Unitarias/Integración:** 56 pruebas
- **Tasa de Éxito:** 100% (56/56 pasadas)
- **Tiempo de Ejecución:** ~1.2s en CI runner
- **Cobertura Global de Código:** ~45% (Objetivo: >=85% global, >=90% core/seguridad/vpn)

---

## 2. Resultados de Análisis Estático y Linters
- **Ruff:** 441 observaciones (formateo de imports, tipado `X | None`, uniones de strings en colecciones `ISC004`, excepciones genéricas).
- **Mypy:** Tipado base funcional; requiere mayor rigor en annotations de retornos y generic type hints.
- **Bandit (Security AST):**
  - Severidad Alta: 3 incidencias (uso de `shell=True` en `firewall/fw_manager.py`).
  - Severidad Media: 14 incidencias (parámetros por defecto de escucha en interfaces abiertas `0.0.0.0`).
  - Severidad Baja: 64 incidencias (uso de generador pseudo-aleatorio `random` para animaciones visuales/glitch y capturas de excepciones en cierres).

---

## 3. Estado de Soporte de Plataforma
- **Linux (x86_64 / arm64):**
  - Core, Criptografía, NTLMv2, Upstream Proxy, Proxy Chain: ✅ Totalmente operativo.
  - VPN AZZ1 Tunneling: ✅ Operativo en modo socket UDP y capa TUN Linux.
  - Firewall: ✅ Soporte `iptables` y planificación declarativa.
- **Windows (10 / 11 / Server):**
  - Core, Criptografía, Proxy, SSH Shell, Port Forwarding: ✅ Totalmente operativo.
  - GUI CustomTkinter: ✅ Operativo (corregidos alias de color y widgets).
  - Firewall: ✅ Soporte `netsh advfirewall` (en proceso de migración segura).

---

## 4. Clasificación de Tareas y Blockers (P0 / P1 / P2)

### 🔴 P0 — Seguridad Crítica y Criptografía
1. **Eliminar fallbacks silenciosos en PFS (X25519)**: Si el handshake anuncia PFS, el intercambio efímero debe ser estricto; cualquier fallo debe abortar la conexión con `HandshakeError`.
2. **Eliminación de `shell=True` en Firewall**: Refactorizar la ejecución de comandos `netsh` en Windows para usar vectores de argumentos seguros sin invocación de shell de comandos.
3. **Migración explícita de AAD para secretos**: AAD obligatorio en todos los campos cifrados; migración documentada para secretos heredados.
4. **Protección Anti-SSRF estricta en Bridge**: Validación reforzada de destinos IPv4/IPv6, link-local, subredes privadas y endpoints de metadatos (`169.254.169.254`).

### 🟡 P1 — Arquitectura y Modularización
1. **Separación del Protocolo AZZ1**: Modularizar el protocolo en el paquete `protocol/` (`version.py`, `constants.py`, `framing.py`, `handshake.py`, `crypto.py`, `replay.py`).
2. **Separación explícita WireGuard vs AZZ1**: El esquema de configuración y documentación deben diferenciar explícitamente el protocolo nativo `AZZ1` del backend `WireGuard`.
3. **Gestor de Identidad y Capacidades (`IdentityManager`)**: Sistema de roles y capacidades (`vpn`, `proxy`, `bridge`, `scanner`, `ssh`).
4. **Ciclo de Vida de Servicios (`ServiceRegistry` / `ServiceState`)**: Abstracción formal de ciclo de vida (`STOPPED`, `STARTING`, `RUNNING`, `DEGRADED`, `FAILED`).
5. **Herramienta de Diagnóstico (`azzazel doctor`)**: Subcomando CLI de verificación de dependencias, permisos, interfaces y backends de firewall.

### 🟢 P2 — Cobertura, Fuzzing y Documentación
1. **Aumento de Cobertura a >=85%**: Baterías exhaustivas de pruebas para `azzazel.py`, `tunnel/ssh_tunnel.py`, `monitoring/api_server.py`, `bridge/mobile_bridge.py`.
2. **Fuzzing con Hypothesis**: Pruebas basadas en propiedades para el deserializador de frames AZZ1, mensajes del Bridge y DSL del firewall.
3. **Scripts de Higiene de Datos y Escáner de Secretos**: `scripts/secret_scan.py` y `scripts/release_clean.py`.
4. **Manuales de Arquitectura y Referencia Completa**: `THREAT_MODEL.md`, `CONFIGURATION.md`, `API.md`, `BRIDGE.md`, `FIREWALL.md`, `VPN.md`, `DNS.md`, `NETWORK.md`, `WINDOWS.md`, `LINUX.md`, `INSTALL.md`, `DEVELOPMENT.md`, `TESTING.md`, `RELEASE.md`, `CHANGELOG.md`, `FINAL_CERTIFICATION.md`.
