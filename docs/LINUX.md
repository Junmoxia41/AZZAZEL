# 🐧 AZZAZEL VPN — Guía de Operación en GNU/Linux (LINUX.md)

Instrucciones y configuración para entornos GNU/Linux (Debian, Ubuntu, Arch, Fedora, Alpine, RHEL).

---

## 1. Requisitos y Privilegios del Kernel

- **Módulo TUN**: El soporte TUN/TAP debe estar cargado en el kernel:
  ```bash
  sudo modprobe tun
  ls -l /dev/net/tun
  ```
- **Capacidades de Red**:
  Para ejecutar sin root pero con capacidades de red:
  ```bash
  sudo setcap cap_net_admin,cap_net_raw+ep $(which python3)
  ```

---

## 2. Configuración de Reenvío y Reglas de Firewall

```bash
# Habilitar forwarding de paquetes IPv4
sudo sysctl -w net.ipv4.ip_forward=1

# Persistir en /etc/sysctl.d/99-azzazel.conf
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-azzazel.conf
```

---

## 3. Despliegue como Servicio Systemd (Headless Daemon)

Crear el archivo `/etc/systemd/system/azzazel.service`:

```ini
[Unit]
Description=AZZAZEL VPN Daemon Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/azzazel-vpn
ExecStart=/opt/azzazel-vpn/.venv/bin/python azzazel.py --daemon --mode server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Habilitar e iniciar:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now azzazel.service
sudo systemctl status azzazel.service
```
