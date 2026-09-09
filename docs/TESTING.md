# 🧪 AZZAZEL VPN — Estrategia y Ejecución de Pruebas (TESTING.md)

Este documento detalla la infraestructura de testing, la suite de pruebas automatizadas, pruebas basadas en propiedades (Property-Based Testing) y métricas de cobertura.

---

## 1. Tipologías de Pruebas Implementadas

1. **Pruebas Unitarias Aisladas (`pytest`)**:
   - Validación de hashes criptográficos fijos (vectores de prueba RFC 1320 MD4, RFC 5869 HKDF).
   - Manipulación de buffers, serialización de cabeceras binarias y cálculo AAD.
2. **Pruebas Basadas en Propiedades (`hypothesis`)**:
   - Fuzzing de serialización y deserialización de frames `AZZ1`.
   - Invariantes de la ventana anti-replay sobre secuencias aleatorias de contadores.
3. **Pruebas de Integración y Concurrencia (`asyncio`)**:
   - Handshakes completos cliente-servidor por sockets UDP en localhost.
   - Mitigación de repetición y detección de paquetes manipulados.
   - Servidor REST de métricas y cliente HTTP simultáneo.

---

## 2. Ejecución de la Suite Completa

```bash
# Ejecutar todas las pruebas con reporte detallado
pytest -v

# Ejecutar con medición de cobertura estricta
pytest --cov=. --cov-report=term-missing --cov-report=html

# Ejecutar escáner estático de seguridad
bandit -r core protocol vpn proxy bridge firewall monitoring network remote tunnel ui azzazel.py -s B101

# Escáner de fugas de secretos
python scripts/secret_scan.py
```
