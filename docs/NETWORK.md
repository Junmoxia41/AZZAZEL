# 🌐 AZZAZEL VPN — Enrutamiento, Subredes y Topología de Red (NETWORK.md)

Este documento describe la gestión del espacio de direccionamiento IP, políticas de enrutamiento y reenvío de paquetes en **AZZAZEL VPN**.

---

## 1. Esquema de Direccionamiento IP

Por defecto, la red virtual del servidor VPN asigna direcciones dentro del bloque privado `10.66.66.0/24`:
- **`10.66.66.1`**: IP estática de la interfaz virtual TUN del Servidor.
- **`10.66.66.2` - `10.66.66.254`**: Pool de asignación dinámica para clientes conectados.
- **Máscara de Subred**: `255.255.255.0` (`/24`).

---

## 2. Reenvío y NAT (IP Forwarding)

Para operar como pasarela a Internet completa:
1. **Linux**: Habilitar el reenvío de paquetes en el kernel:
   ```bash
   sysctl -w net.ipv4.ip_forward=1
   iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE
   ```
2. **Windows**: Habilitar el servicio de enrutamiento y acceso remoto (RRAS) o NAT mediante PowerShell `New-NetNat`.

---

## 3. Cadenas de Proxies y Escaneo Concurrente

- **Proxy Multi-Hop**: El motor de cadenas (`ProxyChain`) permite anidar proxies HTTP y SOCKS5 sucesivamente antes de alcanzar el destino final.
- **Escáner Concurrente (`PortScanner`)**: Realiza sondeos TCP no invasivos con concurrencia adaptativa (hasta 400 sockets simultáneos) y timeouts sub-segundo para auditoría de superficie sin colapsar el ancho de banda del túnel.
