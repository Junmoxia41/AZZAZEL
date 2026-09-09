# 📐 AZZAZEL VPN — Documento de Arquitectura de Sistema

## 1. Visión General del Sistema
AZZAZEL VPN v1.0 está diseñado como un framework modular, resiliente y multiplataforma para operaciones avanzadas de red corporativa y privacidad en entornos hostiles.

```
+─────────────────────────────────────────────────────────────────────────────+
|                                 AZZAZEL VPN                                 |
+─────────────────────────────────────────────────────────────────────────────+
|  +--------------------+  +----------------------+  +---------------------+  |
|  |     CLI / TUI      |  | CustomTkinter GUI    |  |  Web Dashboard      |  |
|  | (Rich / Urwid TUI) |  |   (v3.1 Hacker UI)   |  |   (REST + SSE API)  |  |
|  +---------+----------+  +----------+-----------+  +----------+----------+  |
|            |                        |                         |             |
|  +---------v------------------------v-------------------------v----------+  |
|  |                   CORE INFRASTRUCTURE & SECURITY                     |  |
|  |   ConfigManager (YAML + AAD)   |   CryptoEngine (AES-GCM / X25519)   |  |
|  |   Async Logging Buffer         |   Prometheus Metrics & Vitals       |  |
|  +----------------------------------+------------------------------------+  |
|                                     |                                       |
|  +----------------------------------v------------------------------------+  |
|  |                    SUBSISTEMAS DE RED Y TÚNELES                       |  |
|  |  +-----------------+  +-------------------+  +---------------------+  |  |
|  |  | VPN Tunnel AZZ1 |  | Proxy Chain & NTLM|  | Mobile Bridge (PIN) |  |  |
|  |  |  (PFS + Replay) |  |   (Multi-hop)     |  |   (Anti-SSRF ACL)   |  |  |
|  |  +-----------------+  +-------------------+  +---------------------+  |  |
|  |  +-----------------+  +-------------------+  +---------------------+  |  |
|  |  | SSH Forwarding  |  | Firewall Manager  |  | Network Scanner     |  |  |
|  |  |   (-L / -R / -D)|  |  (Kill-Switch DSL)|  |   (TCP Probe/Sweep) |  |  |
|  |  +-----------------+  +-------------------+  +---------------------+  |  |
|  +-----------------------------------------------------------------------+  |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Protocolo de Túnel VPN AZZ1 (PFS Handshake)

```
       CLIENTE                                            SERVIDOR
          │                                                  │
          │ 1. HELLO [client_nonce, client_pub (X25519)]    │
          │─────────────────────────────────────────────────>│
          │                                                  │ (genera srv_priv/pub)
          │                                                  │ (deriva ecdh_secret)
          │                                                  │ (deriva session_key)
          │ 2. CHALLENGE [server_nonce, session_id, srv_pub] │
          │<─────────────────────────────────────────────────│
(deriva ecdh_secret)                                         │
(deriva session_key)                                         │
(calcula HMAC proof)                                         │
          │ 3. AUTH [proof = HMAC(session_key, n_c || n_s)]  │
          │─────────────────────────────────────────────────>│
          │                                                  │ (verifica HMAC proof)
          │                                                  │ (calcula confirm proof)
          │ 4. SESSION_OK [session_id, proof_confirm]        │
          │<─────────────────────────────────────────────────│
          │                                                  │
          │ ═════════ CANAL CIFRADO ESTABLECIDO ════════════ │
          │ DATA FRAME: [AZZ1][sid(8B)][counter(8B)][GCM]    │
          │<════════════════════════════════════════════════>│
```

---

## 3. Matriz de Componentes y Hilos de Ejecución

- **Main Thread**: Loop principal de UI (Tkinter `root.mainloop()` o CLI loop interactivo).
- **Async Worker Thread**: Bucle `asyncio` persistente para gestionar servidores UDP, listeners TCP del Bridge, sesiones del túnel y corrutinas de reconexión sin congelar la interfaz.
- **REST / SSE API Thread**: Servidor `ThreadingHTTPServer` con endpoints no bloqueantes y streaming en vivo para el dashboard web.
- **Background Tasks**: Pruners de sesiones inactivas, timeouts de heartbeat y recolección de métricas de telemetría.
