# 🛡️ AZZAZEL VPN — Modelo de Amenazas (STRIDE Threat Model)

Este documento define el análisis de amenazas, vectores de ataque, suposiciones de seguridad y mitigaciones implementadas en la arquitectura de **AZZAZEL VPN**.

---

## 1. Alcance y Suposiciones de Seguridad

1. **Entorno de Red No Confiable**: Todo el tráfico que transita entre nodos (Internet, LAN corporativas, redes móviles) se asume interceptable, manipulable y susceptible de ataques de inyección y repetición por atacantes activos (adversario Dolev-Yao).
2. **Host Local Confiable**: La memoria y el sistema de archivos local del endpoint donde corre el software se consideran seguros frente a atacantes no privilegiados, salvo elevación de privilegios no autorizada.
3. **Secretos en Reposo**: Las claves y contraseñas persistidas en `config.yaml` deben estar protegidas mediante cifrado autenticado AES-256-GCM con derivación de clave local y permisos restrictivos (`0600`).

---

## 2. Análisis de Amenazas STRIDE

| Categoría STRIDE | Amenaza Identificada | Vector de Ataque | Mitigación Implementada | Estado |
| :--- | :--- | :--- | :--- | :---: |
| **Spoofing (Suplantación)** | Suplantación del Servidor VPN o Cliente | Inyección de paquetes UDP fraudulentos | Handshake mutuo con prueba HMAC-SHA256 y firma de sesión derivada mediante HKDF y PSK maestra. | ✅ Mitigado |
| **Spoofing** | Suplantación de Dispositivo Móvil en Bridge | Falsificación de ID de dispositivo o token | Emparejamiento interactivo por PIN con TTL de 120s y tokens de 32 bytes con hash SHA-256 y comparación en tiempo constante. | ✅ Mitigado |
| **Tampering (Manipulación)** | Modificación de cabeceras o payloads en tránsito | Alteración de `session_id`, contadores o paquetes IP | Cabeceras en claro (`AZZ1‖type‖session_id`) vinculadas obligatoriamente como AAD en el cifrador AES-256-GCM / ChaCha20-Poly1305. | ✅ Mitigado |
| **Repudiation (Repudio)** | Negación de eventos críticos o accesos | Modificación de historiales de auditoría | LogRing circular en memoria y registro rotativo local con marcas de tiempo Unix e identidades RBAC en streaming. | ✅ Mitigado |
| **Information Disclosure (Fuga de Info)** | Compromiso retrospectivo de claves maestras | Interceptación de tráfico grabado y análisis forense | Perfect Forward Secrecy (PFS) obligatorio vía Curva25519 (`X25519`) por cada sesión; las claves caducan y se destruyen en RAM tras desconexión. | ✅ Mitigado |
| **Information Disclosure** | Fuga de DNS fuera del túnel VPN | Consultas DNS dirigidas al router local | Enrutamiento forzado y reglas de firewall Kill-Switch que bloquean tráfico hacia puertos UDP/TCP 53 fuera de la interfaz virtual TUN. | ✅ Mitigado |
| **Denial of Service (DoS)** | Inundación de Handshakes o paquetes de control | Flood UDP masivo para agotar CPU/RAM | Rate limiter por IP independiente, poda de sesiones inactivas (`SESSION_IDLE_TIMEOUT`), rechazo en primera fase de datagramas sin magia válida. | ✅ Mitigado |
| **Elevation of Privilege** | SSRF / Pivoting no autorizado vía Mobile Bridge | Ataques dirigidos a `127.0.0.1` o `169.254.169.254` desde el móvil | ACL estricta de destinos con bloqueo de direcciones loopback, link-local, multicast y cloud metadata endpoints. | ✅ Mitigado |

---

## 3. Matriz de Superficies de Ataque y Contramedidas

```text
+-----------------------+-----------------------------+------------------------------------+
| Superficie de Ataque  | Vector Potencial            | Mecanismo de Defensa AZZAZEL       |
+-----------------------+-----------------------------+------------------------------------+
| Socket UDP VPN        | Flooding / Handshake replay | ReplayWindow (128 bits), RateLimit |
| API REST (Port 9999)  | Brute-force / CSRF          | Bearer Token, RateLimit, CORS      |
| Mobile Bridge (47671) | SSRF / Pivot LAN            | Dest ACL, Pin pairing TTL 120s     |
| Configuración (.yaml) | Extracción de claves disco  | AES-256-GCM + AAD de campo         |
| Subprocess / Firewall | Inyección de comandos       | Argument vectors (shell=False)     |
+-----------------------+-----------------------------+------------------------------------+
```
