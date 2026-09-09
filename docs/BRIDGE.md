# 📱 AZZAZEL VPN — Protocolo Mobile Bridge (BRIDGE.md)

El módulo **Mobile Bridge** permite interconectar dispositivos móviles (Android / iOS) con la pasarela de salida AZZAZEL en el PC, permitiendo navegar y tunelizar tráfico de forma transparente a través de cadenas de proxies upstream o túneles VPN corporativos.

---

## 1. Arquitectura y Seguridad del Emparejamiento (Pairing)

Para evitar accesos no autorizados y escaneos hostiles en redes Wi-Fi locales, el Mobile Bridge implementa un mecanismo de emparejamiento interactivo asistido por PIN:

```text
       DISPOSITIVO MÓVIL                                   PC (AZZAZEL BRIDGE)
              |                                                     |
              | ------------ 1. SOLICITUD DE PAIRING -------------> |
              |  device_id="dev-01", name="Pixel 8"                 |
              |                                                     |  1. Muestra PIN de 6 dígitos en consola/UI
              |                                                     |  2. Genera temporizador TTL (120s)
              | <----------- 2. RETORNO DE ESTADO PENDING --------- |
              |                                                     |
  [Usuario ingresa PIN]                                             |
              | ------------ 3. VALIDACIÓN DE PIN ----------------> |
              |  pin="582914", device_id="dev-01"                   |
              |                                                     |  1. Verifica PIN en tiempo constante
              |                                                     |  2. Genera token de 32 bytes URL-Safe
              |                                                     |  3. Guarda hash SHA-256 en devices.json
              | <----------- 4. RESPUESTA TOKEN AUTORIZADO -------- |
              |  token="azz_br_..."                                 |
              |                                                     |
```

---

## 2. Prevención de Ataques y Mitigaciones SSRF

1. **Almacenamiento Seguro de Tokens**: El archivo `data/bridge_devices.json` únicamente contiene hashes `SHA-256` de los tokens generados. El robo físico del archivo no permite suplantar dispositivos autorizados.
2. **Defensas Anti-SSRF (Server-Side Request Forgery)**:
   - Toda solicitud de conexión `CONNECT` desde el móvil es inspeccionada por la capa ACL.
   - Direcciones prohibidas por defecto: `127.0.0.0/8`, `localhost`, `::1`, `0.0.0.0`, subredes Link-Local (`169.254.0.0/16`, `fe80::/10`), Direcciones Multicast y endpoints de metadatos en la nube (`169.254.169.254`, `metadata.google.internal`).
   - El acceso a `localhost` debe habilitarse explícitamente mediante la directiva `bridge.security.allow_localhost: true`.
3. **Control de Frecuencia y Bloqueo por Fuerza Bruta**:
   - Límite de 3 intentos fallidos de PIN por IP.
   - Bloqueo temporal exponencial (`cooldown: 30.0s`).
