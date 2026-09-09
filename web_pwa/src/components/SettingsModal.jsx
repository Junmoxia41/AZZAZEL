import React, { useState } from 'react';
import { supabase } from '../lib/supabase';
import { IconClose, IconCloud, IconHardDrive, IconShield, IconRefresh, IconCheck, IconAlert } from './Icons';

export default function SettingsModal({
  isOpen,
  onClose,
  session,
  tunnelUrl,
  onSaveTunnelUrl,
  isOnline,
  lastPingTime,
  onRecheckConnection
}) {
  const [manualUrl, setManualUrl] = useState(tunnelUrl || '');
  const [savedMsg, setSavedMsg] = useState('');

  if (!isOpen) return null;

  const handleSave = (e) => {
    e.preventDefault();
    let clean = manualUrl.trim();
    if (clean && !clean.startsWith('http')) clean = 'https://' + clean;
    onSaveTunnelUrl(clean);
    setSavedMsg('Enlace de túnel actualizado y guardado.');
    setTimeout(() => setSavedMsg(''), 3000);
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    window.location.reload();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-150">
      <div className="w-full max-w-lg bg-azzazel-900 border border-slate-700/60 rounded-2xl shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-blue-950/60 text-blue-400 border border-blue-800/40">
              <IconCloud className="w-5 h-5" />
            </span>
            <div>
              <h3 className="text-base font-bold text-white">Sincronización & Ajustes</h3>
              <p className="text-xs text-slate-400">Diagnóstico de conexión PC ↔ Supabase</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <IconClose className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5 max-h-[80vh] overflow-y-auto">
          
          {/* Status Badge */}
          <div className={`p-4 rounded-xl border flex items-center justify-between ${
            isOnline
              ? 'bg-emerald-950/30 border-emerald-800/50 text-emerald-300'
              : 'bg-rose-950/30 border-rose-800/50 text-rose-300'
          }`}>
            <div className="flex items-center gap-3">
              <span className={`w-3 h-3 rounded-full ${isOnline ? 'bg-emerald-500 shadow-lg shadow-emerald-500/50 animate-pulse' : 'bg-rose-500'}`} />
              <div>
                <div className="text-xs font-bold uppercase tracking-wider">
                  {isOnline ? 'PC En Línea & Conectada' : 'PC Desconectada / Sin Túnel Activo'}
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  {lastPingTime ? `Última comprobación: ${lastPingTime}` : 'Sin respuesta de red'}
                </div>
              </div>
            </div>
            <button
              onClick={onRecheckConnection}
              className="p-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
              title="Volver a verificar"
            >
              <IconRefresh className="w-4 h-4" />
            </button>
          </div>

          {/* Account Info */}
          <div className="p-4 bg-azzazel-950/60 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <IconShield className="w-4 h-4 text-blue-400" />
              <span>Cuenta Autenticada</span>
            </div>
            <div className="text-xs text-slate-400">
              Usuario: <span className="font-mono text-white font-medium">{session?.user?.email || 'Sin sesión'}</span>
            </div>
            <div className="text-xs text-slate-400">
              Servidor Supabase: <span className="font-mono text-slate-300">vqbtuzauqchopdlbgylk.supabase.co</span>
            </div>
          </div>

          {/* Tunnel URL Configuration */}
          <form onSubmit={handleSave} className="space-y-3">
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <IconHardDrive className="w-4 h-4 text-indigo-400" />
              <span>Dirección del Túnel Inverso (PC)</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Esta dirección se actualiza automáticamente mediante Supabase al pulsar <b>"Iniciar Túnel Nube"</b> en AZZAZEL. También puedes escribirla manualmente si cambias de servidor.
            </p>

            <input
              type="text"
              value={manualUrl}
              onChange={(e) => setManualUrl(e.target.value)}
              placeholder="https://xxxx-200-55-140-137.free.pinggy.net"
              className="w-full px-3.5 py-2.5 bg-azzazel-950/80 border border-slate-700/70 rounded-xl text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
            />

            {savedMsg && (
              <div className="flex items-center gap-2 text-xs text-emerald-400 font-medium">
                <IconCheck className="w-4 h-4" />
                <span>{savedMsg}</span>
              </div>
            )}

            <button
              type="submit"
              className="w-full py-2.5 bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold rounded-xl border border-slate-700 transition-colors"
            >
              Guardar y Reconectar
            </button>
          </form>

          {/* Logout Button */}
          <div className="pt-2 border-t border-slate-800">
            <button
              onClick={handleLogout}
              className="w-full py-2.5 text-xs font-semibold text-rose-400 hover:text-rose-300 hover:bg-rose-950/30 border border-rose-900/40 rounded-xl transition-colors"
            >
              Cerrar Sesión
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
