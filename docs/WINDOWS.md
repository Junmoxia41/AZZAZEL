# 🪟 AZZAZEL VPN — Guía de Operación en Windows (WINDOWS.md)

Instrucciones y requisitos de configuración para desplegar **AZZAZEL VPN** en sistemas Microsoft Windows (10, 11 y Windows Server 2019/2022).

---

## 1. Requisitos Previos
- **Python**: Versión 3.10 o superior (64-bit recomendada).
- **Control de Cuentas de Usuario (UAC)**: Ejecutar PowerShell o Terminal como **Administrador** para habilitar cambios en el Firewall y routing.
- **Drivers de Red**:
  - `wintun.dll` (colocado en la carpeta del proyecto o en `System32`) o driver TAP `tap-windows6`.

---

## 2. Instalación y Despliegue Rápido

```powershell
# 1. Clonar el repositorio y crear entorno virtual
python -m venv .venv
.venv\Scripts\Activate.ps1

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Diagnóstico del sistema
python azzazel.py --doctor

# 4. Lanzar con Interfaz Gráfica Moderna
python azzazel.py --gui
```

---

## 3. Integración con el Firewall de Windows (`netsh advfirewall`)
AZZAZEL gestiona reglas de firewall de forma segura sin abrir consolas interactivas:
- El subproceso utiliza invocación directa por lista de argumentos (`shell=False`).
- El Kill-Switch bloquea adaptadores físicos en caso de interrupción del túnel.
