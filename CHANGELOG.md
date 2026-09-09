# 📝 AZZAZEL VPN — Registro de Cambios (CHANGELOG.md)

Todos los cambios notables en este proyecto se documentan en este archivo según el formato [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y siguen [Semantic Versioning](https://semver.org/).

---

## [1.0.0] - 2026-09-08

### ✨ Añadido
- **Protocolo de Túnel AZZ1 Desacoplado**: Paquete modular `protocol/` con especificación formal (`docs/protocol/AZZ1.md`), framing binario AEAD (`framing.py`), ventana deslizante anti-replay de 128 bits (`replay.py`), handshake de 3 vías (`handshake.py`) e intercambio criptográfico X25519 con HKDF (`crypto.py`).
- **Comando de Diagnóstico `azzazel doctor`**: Suite integral de verificación de entorno, privilegios, primitivas criptográficas, TUN/TAP, puertos de red y dependencias en `ui/cli/doctor.py`.
- **Gestión de Identidades RBAC (`IdentityManager`)**: Soporte de roles (`ADMIN`, `OPERATOR`, `AUDITOR`, `SERVICE`), tokens revocables con hash SHA-256 en reposo y verificación en tiempo constante en `security/identity.py`.
- **Supervisión de Ciclo de Vida (`ServiceRegistry`)**: Registro centralizado y estados (`STOPPED`, `STARTING`, `RUNNING`, `DEGRADED`, `STOPPING`, `FAILED`) en `core/service_registry.py`.
- **Fuzzing y Pruebas Basadas en Propiedades**: Baterías de pruebas automáticas con `hypothesis` para el protocolo AZZ1.
- **Herramientas de Mantenimiento**: `scripts/secret_scan.py` para auditoría estática de secretos y `scripts/release_clean.py` para higiene de artefactos.
- **Documentación Técnica Completa**: 14 documentos exhaustivos en `docs/` cubriendo arquitectura, modelo de amenazas STRIDE, API REST, protocolos, firewall, red y guías de sistema operativo.

### 🔒 Seguridad y Endurecimiento
- **PFS Estricto**: Eliminación de fallbacks degradantes a PSK cuando se solicita intercambio X25519; rechazo explícito con `HandshakeError`.
- **AAD Forzoso en Secretos**: Autenticación de datos asociados obligatoria en el cifrador AES-256-GCM para prevenir ataques de trasplante.
- **Eliminación de `shell=True` en Firewall**: Refactorización de comandos de sistema en Windows (`netsh`) y Linux (`iptables`) a listas de argumentos directas para neutralizar inyecciones de comandos.
- **Mitigación Anti-SSRF en Mobile Bridge**: Bloqueo estricto de destinos loopback, subredes link-local y endpoints de metadatos de nube (`169.254.169.254`).
- **Permisos Restrictivos de Claves**: Detección automática y advertencia de seguridad para archivos `.key` con permisos superiores a `0600`.

### 🐛 Corregido
- Corregida discrepancia de versión única mediante la centralización en `core/version.py`.
- Corregidos errores de referencias en paletas ANSI de la consola CLI.
- Corregida persistencia y hashing de tokens en el registro de dispositivos móviles.
