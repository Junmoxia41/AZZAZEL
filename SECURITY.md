# 🛡️ AZZAZEL VPN — Política de Seguridad y Modelo de Amenazas

## 1. Modelo de Cifrado y Primitivas Criptográficas

| Función | Algoritmo / Primitiva | Detalle de Implementación |
| :--- | :--- | :--- |
| **Cifrado en Tránsito (VPN)** | AES-256-GCM / ChaCha20-Poly1305 | Tag de autenticación de 128 bits, nonce único por trama derivado con contador de 64 bits. |
| **Intercambio Efímero de Claves** | X25519 (ECDH) | Claves efímeras generadas por sesión; asegura **Perfect Forward Secrecy (PFS)**. |
| **Derivación de Claves (KDF)** | HKDF-SHA256 / Scrypt | Expansión y extracción criptográfica de alta entropía. |
| **Cifrado en Reposo (Config)** | AES-256-GCM con AAD | El secreto se cifra usando el dotted-path (`vpn.keys.psk`) como AAD para evitar translocación. |
| **Autenticación Corporativa** | NTLMv2 Nativo (RFC 2759) | MD4 puro (RFC 1320), HMAC-MD5 y generación aleatoria de client challenges. |
| **Comparación Segura** | `hmac.compare_digest` | Verificación en tiempo constante para mitigar ataques de temporización (timing attacks). |

---

## 2. Mitigaciones y Contramedidas Implementadas

### A. Ataques de Replay (Retransmisión de paquetes)
- Se implementa una **ventana deslizante de 64 bits** (`ReplayWindow`) en `vpn/tunnel_manager.py`.
- Cualquier frame que presente un contador inferior a la cota inferior de la ventana, o un contador ya visto dentro del mapa de bits, es descartado silenciosamente sin generar respuestas ICMP/UDP que delaten al host.

### B. Fugas de Tráfico y DNS (Kill-Switch)
- En caso de desconexión o desautenticación imprevista del túnel VPN, el `KillSwitch` invoca automáticamente al `FirewallManager` para inyectar reglas restrictivas (`vpn_only_rules`).
- Se bloquea todo el tráfico TCP/UDP saliente no dirigido explícitamente al endpoint del túnel, suprimiendo consultas DNS sin cifrar a servidores externos.

### C. Server-Side Request Forgery (SSRF) y Pivoting en Bridge
- El puente PC↔Móvil (`bridge/mobile_bridge.py`) analiza cada petición de apertura de túnel en capa 7.
- Bloquea por defecto cualquier intento de conexión hacia `127.0.0.1`, `localhost`, `::1` o subredes de loopback (`127.0.0.0/8`), evitando que dispositivos móviles comprometidos accedan a puertos locales de gestión interna en la máquina host.

### D. Ataques de Fuerza Bruta en Autenticación
- El emparejamiento móvil por PIN aplica una política de **cooldown exponencial por IP** tras 3 intentos fallidos y expira los intentos con un TTL estricto.
- El servidor API REST incluye un limitador de tasa de peticiones con ventana deslizante (`RateLimiter`) que retorna `HTTP 429 Too Many Requests`.
