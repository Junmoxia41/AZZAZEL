# 📦 AZZAZEL VPN — Guía de Instalación (INSTALL.md)

Este documento describe el proceso paso a paso para la instalación y puesta en marcha de **AZZAZEL VPN** en cualquier entorno soportado.

---

## 1. Requisitos de Hardware y Software

- **CPU:** x86_64 o ARM64 (soporte para instrucciones AES-NI aceleradas).
- **RAM:** Mínimo 512 MB (1 GB recomendado para escaneos y proxies concurrentes).
- **Python:** 3.10 o superior (3.11, 3.12, 3.13 totalmente soportados).

---

## 2. Instalación en Entorno Virtual (Recomendado)

```bash
# 1. Clonar el repositorio
git clone https://github.com/azzazel-vpn/azzazel-vpn.git
cd azzazel-vpn

# 2. Crear y activar entorno virtual
python3 -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\Activate.ps1

# 3. Instalar dependencias del proyecto
pip install --upgrade pip
pip install -r requirements.txt

# 4. Verificar estado del entorno
python azzazel.py --doctor
```

---

## 3. Instalación con Soporte Completo de Calidad y Tests

Para entornos de auditoría, pruebas continuas y desarrollo:
```bash
pip install pytest pytest-cov ruff mypy bandit hypothesis
```
