# 🔥 AZZAZEL VPN — Gestión de Firewall y Kill-Switch (FIREWALL.md)

Este documento describe la arquitectura declarativa de reglas de firewall, la integración con backends de sistema operativo (`iptables` / `netsh`) y el mecanismo de aislamiento de emergencia (**Kill-Switch**).

---

## 1. DSL Declarativo de Reglas de Firewall

AZZAZEL utiliza una sintaxis intermedia abstracta (DSL) que se compila de forma determinista al backend nativo del sistema operativo donde se ejecuta.

### Ejemplo de Reglas DSL:
```text
# Permitir tráfico local
ALLOW INBOUND TCP FROM 127.0.0.1 TO ANY PORT 8080
ALLOW OUTBOUND TCP FROM ANY TO 1.1.1.1 PORT 53

# Regla de Kill-Switch de Emergencia
BLOCK OUTBOUND ALL EXCEPT INTERFACE azz0
```

---

## 2. Compilación a Backends Nativos

### 2.1. Linux (`iptables` / `nftables`)
En entornos Linux, el `FirewallManager` genera cadenas personalizadas (`AZZAZEL_INPUT`, `AZZAZEL_OUTPUT`) para aislar las reglas sin alterar la configuración global del host:

```bash
# Inicialización de cadena aislada
iptables -N AZZAZEL_OUTPUT
iptables -A OUTPUT -j AZZAZEL_OUTPUT

# Reglas de Kill-Switch
iptables -A AZZAZEL_OUTPUT -o lo -j ACCEPT
iptables -A AZZAZEL_OUTPUT -o azz0 -j ACCEPT
iptables -A AZZAZEL_OUTPUT -p udp -d 198.51.100.1 --dport 51820 -j ACCEPT
iptables -A AZZAZEL_OUTPUT -j DROP
```

### 2.2. Windows (`netsh advfirewall`)
En Windows 10/11, las reglas se inyectan a través del perfil de Firewall Avanzado sin invocar consolas de comandos inseguras (`shell=False`):

```cmd
netsh advfirewall firewall add rule name="AZZAZEL-VPN-OUT" dir=out action=allow protocol=UDP remoteport=51820
netsh advfirewall firewall add rule name="AZZAZEL-KILLSWITCH" dir=out action=block
```

---

## 3. Comportamiento y Disparo del Kill-Switch

1. **Estado Normal**: El tráfico circula a través de la interfaz virtual TUN `azz0`.
2. **Detección de Caída**: Si el cliente VPN no recibe frames de keepalive durante `timeout = 2.5 * keepalive_interval`, la sesión entra en estado `DISCONNECTED`.
3. **Aislamiento Inmediato**: Se invoca el hook `kill_switch.engage(reason="Tunnel lost")`. Se bloquea todo tráfico de salida salvo los paquetes de control dirigidos a la IP y puerto del servidor VPN.
4. **Reconexión y Restauración**: Una vez completado el nuevo handshake de 3 vías con PFS, el kill-switch se desarma automáticamente (`kill_switch.disengage()`).
