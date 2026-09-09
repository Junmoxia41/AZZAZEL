# 🛡️ AZZAZEL VPN — Manual de Arquitectura VPN (VPN.md)

Este documento detalla el funcionamiento del túnel seguro de **AZZAZEL VPN**, la gestión de interfaces virtuales TUN, asignación de direccionamiento IP y gestión de congestión.

---

## 1. Topología y Modos de Despliegue

1. **Punto-a-Punto (P2P)**: Comunicación directa entre dos nodos AZZAZEL mediante UDP con claves simétricas precompartidas y PFS.
2. **Cliente-Servidor (Roadwarrior)**: El servidor AZZAZEL escucha en un socket UDP (puerto por defecto `51820`), asigna direcciones dentro del rango virtual `10.66.66.0/24` y enruta el tráfico entre los pares conectados o hacia Internet mediante NAT/Masquerading.
3. **Multi-Hop / Chained VPN**: Combinación de túnel VPN nativo AZZ1 con proxies intermedios o saltos SSH para anonimato reforzado.

---

## 2. Gestión de Interfaces TUN (`/dev/net/tun` vs `wintun`)

- **Linux**: Utiliza la interfaz universal TUN mediante `ioctl(fd, TUNSETIFF, struct ifreq)`. Requiere capacidad `CAP_NET_ADMIN` o ejecución con usuario root. El MTU por defecto es `1420` bytes para evitar fragmentación en redes con encapsulaciones PPPoE / GRE / IPSec.
- **Windows**: Soporte a través de adaptadores `wintun.dll` o `tap-windows6` con inyección directa de datagramas IPv4.

---

## 3. Resiliencia de Enlace y Parámetros de Red

| Parámetro | Valor por Defecto | Descripción |
| :--- | :--- | :--- |
| **MTU** | 1420 bytes | Tamaño máximo de unidad de transmisión del adaptador virtual |
| **Keepalive** | 25 segundos | Intervalo de emisión de latidos de mantenimiento NAT |
| **Idle Timeout** | 120 segundos | Tiempo máximo de inactividad antes de purgar la sesión en el servidor |
| **Backoff Min** | 1.0 segundo | Tiempo inicial de espera en reintentos de reconexión |
| **Backoff Max** | 30.0 segundos | Techo máximo de espera en retroceso exponencial |
