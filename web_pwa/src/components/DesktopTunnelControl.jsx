import React, { useEffect, useState } from 'react';
import { supabase } from '../lib/supabase';
import { IconCloud, IconCheck, IconAlert, IconRefresh } from './Icons';

/**
 * Panel de control del túnel, visible SOLO cuando la PWA corre embebida en
 * la ventana de escritorio AZZAZEL (pywebview). En el navegador/móvil este
 * componente no se monta: allí no existe `window.pywebview`, ya que iniciar
 * el túnel requiere el proxy corporativo y el proceso Python del propio PC.
 *
 * Nunca hay credenciales de proxy en este archivo: viajan de Supabase
 * (tabla `proxy_configs`, protegida por RLS) al proceso Python mediante
 * `window.pywebview.api`, usando el JWT de la sesión ya iniciada aquí mismo.
 */
export default function DesktopTunnelControl({ session, onTunnelStarted }) {
  const [status, setStatus] = useState('offline'); // offline | starting | online | error
  const [message, setMessage] = useState('');
  const [isDesktop, setIsDesktop] = useState(false);

  useEffect(() => {
    setIsDesktop(typeof window !== 'undefined' && !!window.pywebview);
  }, []);

  const handleStart = async () => {
    if (!window.pywebview?.api || !session) return;
    setStatus('starting');
    setMessage('Conectando con el proxy corporativo…');
    try {
      const { data } = await supabase.auth.getSession();
      const token = data?.session?.access_token;
      if (!token) throw new Error('Sesión de Supabase no disponible.');

      const result = await window.pywebview.api.start_tunnel(
        token, session.user.id, session.user.email
      );
      if (result?.ok) {
        setStatus('online');
        setMessage(`Túnel activo: ${result.tunnel_url}`);
        onTunnelStarted?.(result.tunnel_url);
      } else {
        setStatus('error');
        setMessage(result?.error || 'No se pudo iniciar el túnel.');
      }
    } catch (err) {
      setStatus('error');
      setMessage(err.message || 'Error iniciando el túnel.');
    }
  };

  const handleStop = async () => {
    if (!window.pywebview?.api) return;
    await window.pywebview.api.stop_tunnel();
    setStatus('offline');
    setMessage('Túnel detenido.');
  };

  if (!isDesktop) return null;

  return (
    <div className="p-4 bg-azzazel-900/90 border border-slate-800/80 rounded-2xl shadow-xl space-y-3">
      <div className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
        <IconCloud className="w-4 h-4 text-blue-400" />
        <span>Túnel de Este PC (App de Escritorio)</span>
      </div>

      <div className="flex items-center justify-between p-3 bg-azzazel-950/70 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-2 min-w-0">
          {status === 'online' && <IconCheck className="w-4 h-4 text-emerald-400 shrink-0" />}
          {status === 'error' && <IconAlert className="w-4 h-4 text-rose-400 shrink-0" />}
          {status === 'starting' && <IconRefresh className="w-4 h-4 text-blue-400 animate-spin shrink-0" />}
          <span className="text-xs text-slate-300 truncate">{message || 'Túnel no iniciado en esta PC.'}</span>
        </div>
      </div>

      {status === 'online' ? (
        <button
          onClick={handleStop}
          className="w-full py-2.5 bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 text-xs font-semibold rounded-xl border border-rose-900/50 transition-colors"
        >
          Detener Túnel Nube
        </button>
      ) : (
        <button
          onClick={handleStart}
          disabled={status === 'starting'}
          className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white text-xs font-semibold rounded-xl transition-colors"
        >
          {status === 'starting' ? 'Iniciando…' : 'Iniciar Túnel Nube'}
        </button>
      )}
    </div>
  );
}
