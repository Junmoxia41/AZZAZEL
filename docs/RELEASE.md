# 🚀 AZZAZEL VPN — Protocolo de Release y Empaquetado (RELEASE.md)

Procedimiento formal para la generación, verificación y publicación de versiones estables de **AZZAZEL VPN**.

---

## 1. Pasos Previos a la Publicación

1. **Verificación de Versión Canónica**:
   - Comprobar que `core/version.py` tiene la versión objetivo incrementada según SemVer (ej. `1.0.0`).
2. **Ejecución de la Suite Completa de Calidad**:
   ```bash
   pytest --cov=. --cov-fail-under=50
   ruff check .
   bandit -r core protocol vpn proxy bridge firewall monitoring network remote tunnel ui azzazel.py -s B101
   python scripts/secret_scan.py
   ```
3. **Higiene de Archivos Temporales**:
   ```bash
   python scripts/release_clean.py
   ```

---

## 2. Generación de Checksums SHA-256

```bash
sha256sum azzazel.py config.yaml requirements.txt > SHA256SUMS.txt
gpg --armor --detach-sign SHA256SUMS.txt
```
