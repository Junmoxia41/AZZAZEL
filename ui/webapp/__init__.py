"""AZZAZEL ui/webapp — ventana de escritorio basada en la misma PWA web.

Sustituye la GUI antigua de CustomTkinter (tema "hacker" verde matriz) por
una ventana nativa (pywebview) que carga el HTML/CSS/JS real de la app web
(``web_pwa/dist``), de modo que el programa de escritorio y la aplicación
móvil comparten exactamente el mismo diseño gráfico e interfaz.
"""
