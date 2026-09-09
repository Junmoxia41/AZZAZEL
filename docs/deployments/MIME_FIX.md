# AZZAZEL Remote — Corrección MIME en Vercel

**PHASE:** corrección del despliegue web, 2026-09-09.

**STATUS:** IMPLEMENTED, TESTED, INTEGRATED y VERIFIED para la entrega de archivos estáticos y el renderizado inicial de React. No es una certificación PRODUCTION-READY del sistema completo.

**FOUND:**
- `web_pwa/vercel.json` enviaba todas las rutas a `/index.html`, incluidos `/assets/*.js` y `/assets/*.css`.
- Los recursos de PWA estaban fuera de `public/` y requerían copias manuales después de compilar.
- El enlace corto era un alias de un despliegue de vista previa, no un dominio de producción asociado al proyecto. Las comprobaciones anónimas se redirigían al login de Vercel.

**FIXED:**
- Se evalúa `handle: filesystem` antes del fallback de la SPA.
- Los recursos estáticos y las rutas API inexistentes devuelven 404; nunca `index.html` con estado 200.
- `index.html`, la raíz, el manifiesto y el service worker deben revalidar su caché. Se mantiene `X-Content-Type-Options: nosniff`; no se falsifica `Content-Type`.
- Manifiesto, iconos y service worker movidos a `web_pwa/public/`. El script de compilación prepara también la configuración de Vercel en `dist/`.
- Dominio de producción: https://azzazel-vpn.vercel.app
- Despliegue: `dpl_FAnYvBxxQ37Zd1P4wLba7ptBD28C`, estado READY.
- El alias largo anterior también apunta al despliegue corregido.

**TEST:**
- `npm run build`: correcto.
- `npm run test:build`: 12/12 pruebas del artefacto/configuración.
- `python scripts/verify-deployment.py https://azzazel-vpn.vercel.app --report ../docs/deployments/mime-http-verification.json`: 12/12 comprobaciones HTTPS anónimas.
- JavaScript original reportado: `/assets/index-DJ5g6VcP.js` → 200, `application/javascript`, bytes idénticos al build.
- CSS original reportado: `/assets/index-Dhf7MA7_.css` → 200, `text/css`, bytes idénticos al build.
- React montado, estilos aplicados y formulario de login visible en Chromium con tamaños de pantalla 390×844 y 1440×900; sin errores de módulos/MIME. 2/2 casos.
- Un primer intento del navegador no pudo arrancar por bibliotecas ausentes en el sandbox. Se extrajeron las bibliotecas en una carpeta temporal de usuario, sin modificar paquetes del sistema, y las pruebas posteriores pasaron.

**COVERAGE:** entrega HTTP, MIME, integridad binaria, caché, fallbacks, manifiesto/iconos y renderizado inicial. El navegador usa una respuesta explícitamente simulada `[]` para el descubrimiento de túneles de Supabase, para no conectar con la PC. No se probaron inicio de sesión real, archivos, VPN, túnel ni conectividad de la PC. No se midió cobertura de líneas.

**SECURITY:** configuración `ssoProtection: all_except_custom_domains` de Vercel conservada; no se desactivó la protección de vistas previas. La autenticación de AZZAZEL no fue modificada. No se enviaron credenciales de cuenta o PC en las pruebas. Escaneo del artefacto sin tokens de administración Vercel/Supabase. Credencial temporal de despliegue eliminada del sandbox después de usarla.

**BLOCKERS:** ninguno para la carga de recursos y pantalla inicial. Integraciones con cuenta/PC fuera del alcance de esta corrección.

**NEXT:** recargar el enlace corto. Si una pestaña mantiene la versión anterior, usar recarga forzada; en PWA, cerrar y volver a abrir antes de considerar borrar datos del sitio (eso puede cerrar la sesión).

**AUTO-CONTINUE:** corrección terminada.

## Evidencias y rollback

- `mime-fix-2026-09-09.json`: identidad del despliegue, protección conservada y resumen de pruebas.
- `mime-http-verification.json`: estados, MIME, hashes y cabeceras reales.
- `mime-browser-verification.json`: recursos cargados y resultados del navegador.
- `mime-fix-mobile.png`, `mime-fix-desktop-spa-route.png`: capturas del formulario cargado.
- `before-mime-fix-2026-09-09.tar.gz`: copia local previa al cambio, incluido el artefacto compilado anterior.
- `vercel-alias-before-mime-fix.json`: asociación anterior del enlace.

El despliegue previo `dpl_BYib9hAyej1j77L83eeizT9b3QkM` no se eliminó. Reasociar un dominio a ese despliegue permitiría revertirlo, pero reintroduciría el fallo MIME; no se ha realizado ese rollback.

## Repetir el smoke test de navegador

`web_pwa/tests/browser-smoke.cjs` requiere Playwright y Chromium instalados en el entorno de pruebas. Ejecutar `node tests/browser-smoke.cjs` desde `web_pwa/`; `PWA_TEST_URL` permite elegir otro despliegue. No iniciar sesión con credenciales reales para este smoke test.
