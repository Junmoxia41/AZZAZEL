# 🛰️ AZZ1 Protocol Wire Specification (v1.0)

El protocolo **AZZ1** es el protocolo nativo de túnel VPN punto-a-punto y cliente-servidor de alta velocidad desarrollado para la suite **AZZAZEL VPN**. Opera sobre transporte UDP y está diseñado específicamente para ofuscación, evasión de inspección profunda de paquetes (DPI), baja latencia y resistencia criptográfica de grado militar.

---

## 1. Principios de Diseño y Diferenciación

1. **Protocolo Propio e Independiente**: AZZ1 **NO es WireGuard**, **NO es OpenVPN** ni **IPsec**. Es un protocolo de aplicación con framing binario propio, handshake autenticado de 3 vías con PFS y encapsulación de datagramas con cifrado autenticado.
2. **Perfect Forward Secrecy (PFS) Estricto**: Todo handshake utiliza intercambio de claves efímeras Diffie-Hellman sobre Curva25519 (`X25519`). La clave maestra precompartida (`PSK`) actúa como autenticador y sal en la función de derivación de claves (`HKDF-SHA256`), garantizando que la revelación de la PSK a posteriori no comprometa el tráfico pasado.
3. **Autenticación de Datos Asociados (AAD)**: La cabecera en claro (`FRAME_MAGIC`, `ftype`, `session_id`) forma parte obligatoria del AAD (Additional Authenticated Data) en el cifrador AEAD (`AES-256-GCM`), impidiendo la manipulación, inyección cruzada o suplantación de identificadores de sesión.
4. **Protección Anti-Replay con Ventana Deslizante**: Contador monótono de 64 bits transmitido dentro del cuerpo cifrado junto a una ventana de bits deslizante de 128 posiciones (RFC 6479) para mitigar repeticiones y desórdenes en redes no fiables.

---

## 2. Primitivas Criptográficas

| Función | Algoritmo / Primitiva | Propósito |
| :--- | :--- | :--- |
| **Intercambio Efímero** | `X25519 (ECDH Curve25519)` | Claves públicas de 32 bytes para Perfect Forward Secrecy |
| **Derivación de Sesión** | `HKDF-SHA256` (RFC 5869) | Salt = SHA-256(PSK), Info = `client_nonce \| server_nonce \| "AZZ-SESSION-v1"` |
| **Cifrado de Frames** | `AES-256-GCM` (o ChaCha20-Poly1305) | Cifrado autenticado de carga útil con Nonce aleatorio de 96 bits |
| **Prueba de Posesión** | `HMAC-SHA256` | Verificación mutua de clave durante el handshake |
| **Comparación Segura** | `hmac.compare_digest` | Mitigación total de ataques de canal lateral por temporización |

---

## 3. Formato del Paquete en Cable (Binary Wire Layout)

### 3.1. Datagrama de Datos Cifrado (Frame)
```text
+-----------------------+--------------------+--------------------------------+
|  FRAME_MAGIC (4 B)    |  FRAME_TYPE (1 B)  |       SESSION_ID (8 B)         |
|      "AZZ1"           |   0x01 = DATA      |    Identificador de Sesión     |
|                       |   0x02 = KEEPALIVE |         del Servidor           |
+-----------------------+--------------------+--------------------------------+
|<--------------------- CABECERA EN CLARO (AAD: 13 BYTES) ------------------->|

+-----------------------------------------------------------------------------+
|                          CARGA CIFRADA (AEAD BLOB)                          |
|  +--------------------+--------------------------------+-----------------+  |
|  |   NONCE (12 B)     |  CIPHERTEXT (Counter + Data)   |  GCM TAG (16 B) |  |
|  +--------------------+--------------------------------+-----------------+  |
+-----------------------------------------------------------------------------+
```

#### Detalle de Campos del Frame:
- **`FRAME_MAGIC` (4 bytes)**: Constante fija `b"AZZ1"` (`0x41 0x5A 0x5A 0x31`).
- **`FRAME_TYPE` (1 byte)**:
  - `0x01` (`FRAME_DATA`): Datagrama IP encapsulado.
  - `0x02` (`FRAME_KEEPALIVE`): Latido de mantenimiento de estado NAT / firewall.
- **`SESSION_ID` (8 bytes)**: Valor aleatorio único asignado por el servidor durante el handshake.
- **`NONCE` (12 bytes)**: Vector de inicialización aleatorio para el cifrador AES-GCM.
- **`CIPHERTEXT` (Variable)**:
  - **`Counter` (8 bytes)**: Entero de 64 bits little-endian (`<Q`) con el número de secuencia monótono.
  - **`Payload` (0..MTU bytes)**: Paquete IPv4/IPv6 completo (o vacío en caso de keepalive).
- **`GCM TAG` (16 bytes)**: Etiqueta de autenticación de integridad (Poly1305 / GHASH) sobre el ciphertext y el AAD.

---

### 3.2. Datagrama de Control (Handshake)
Los mensajes de control se transportan con el prefijo mágico de 7 bytes `b"AZZ-C1\n"` seguido de un objeto JSON codificado en UTF-8.

```text
+------------------------+----------------------------------------------------+
|  CONTROL_MAGIC (7 B)   |               JSON PAYLOAD (UTF-8)                 |
|      "AZZ-C1\n"        |  {"msg":"hello", "ver":1, "client_pub":"...", ...} |
+------------------------+----------------------------------------------------+
```

---

## 4. Secuencia de Handshake de 3 Vías (State Machine)

```text
       CLIENTE (C)                                       SERVIDOR (S)
            |                                                 |
            | ---------- MSG_HELLO -------------------------> |
            |  client_nonce (16B), client_pub (32B), ver=1    |
            |                                                 |  1. Genera server_nonce (16B), session_id (8B)
            |                                                 |  2. Genera server_priv / server_pub (X25519)
            |                                                 |  3. ecdh_secret = X25519(server_priv, client_pub)
            |                                                 |  4. session_key = HKDF(PSK, ecdh_secret, nonces)
            |                                                 |  5. server_proof = HMAC(session_key, nonces+sid)
            | <--------- MSG_CHALLENGE ---------------------- |
            |  server_nonce, session_id, server_pub,          |
            |  server_proof, assigned_ip                      |
            |                                                 |
 1. ecdh_secret = X25519(client_priv, server_pub)             |
 2. session_key = HKDF(PSK, ecdh_secret, nonces)             |
 3. Verifica server_proof (HMAC)                             |
 4. client_proof = HMAC(session_key, nonces+sid)              |
            |                                                 |
            | ---------- MSG_RESPONSE ----------------------> |
            |  client_proof                                   |
            |                                                 |  1. Verifica client_proof (HMAC)
            |                                                 |  2. Registra VpnSession activa
            |                                                 |
            | <================ TUNEL ESTABLECIDO ============> |
            |     Datagramas AZZ1 cifrados bidireccionales    |
```

---

## 5. Resiliencia de Red y Ciclo de Vida

- **Keepalive y Reenvío**: Si no hay tráfico de datos durante `KEEPALIVE_INTERVAL` (25s), el cliente emite automáticamente un frame `FRAME_KEEPALIVE`.
- **Inactividad y Poda de Sesiones**: El servidor inspecciona periódicamente `last_rx`. Si supera `SESSION_IDLE_TIMEOUT` (120s), la sesión se libera de memoria.
- **Reconexión Automática con Backoff Exponencial**: Si el cliente pierde conectividad o no recibe frames durante `keepalive * 2.5` segundos, entra en modo de reconexión con espera incremental (`1.0s` hasta `30.0s`).
