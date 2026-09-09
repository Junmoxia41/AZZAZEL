# 🔍 AZZAZEL VPN — Prevención de Fugas de DNS (DNS.md)

La fuga de consultas DNS (DNS Leaks) es uno de los vectores principales de pérdida de privacidad en entornos VPN. Este documento especifica las estrategias implementadas en AZZAZEL para garantizar la resolución privada y cifrada.

---

## 1. Vectores Comunes de Fuga de DNS

1. **Resolución Multihomed en Windows**: Windows intenta resolver consultas simultáneamente en todos los adaptadores de red activos (físicos y virtuales), permitiendo que el ISP capture dominios consultados.
2. **Fallback al Router Local en DHCP**: Al caer el túnel o durante cambios de red, el sistema operativo recurre automáticamente a los DNS de la puerta de enlace local.
3. **Peticiones UDP 53 en Claro**: Ataques Man-in-the-Middle (MitM) que interceptan o envenenan consultas sin cifrar.

---

## 2. Mitigaciones Integradas en AZZAZEL

1. **Bloqueo de Tráfico DNS fuera del Túnel**:
   - El motor de firewall inyecta una regla de bloqueo que descarta cualquier datagrama con destino al puerto `53` (TCP/UDP) que no provenga de la interfaz TUN virtual `azz0`.
2. **Desactivación de Smart Multi-Homed Name Resolution (Windows)**:
   - Configuración de políticas de clave de registro para forzar el orden estricto de interfaces DNS.
3. **Encapsulación DoH / DoT (DNS sobre HTTPS / TLS)**:
   - Capacidad de redirigir resoluciones locales a través de proxies seguros (`1.1.1.1`, `9.9.9.9`, `8.8.8.8`) encapsulados dentro del flujo cifrado del túnel.
