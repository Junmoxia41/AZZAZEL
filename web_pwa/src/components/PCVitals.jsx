import React, { useEffect, useState } from 'react';
import { supabase } from '../lib/supabase';
import { IconCpu, IconRam, IconHardDrive, IconShield, IconCloud, IconCheck, IconAlert } from './Icons';
import DesktopTunnelControl from './DesktopTunnelControl';

export default function PCVitals({ isOnline, tunnelUrl, diskFree, session, onTunnelStarted }) {
  const [proxyConfig, setProxyConfig] = useState(null);
  const [loadingProxy, setLoadingProxy] = useState(true);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ proxy_host: '', proxy_port: '', proxy_username: '', proxy_password: '' });
  const [savedMsg, setSavedMsg] = useState('');

  const userId = session?.user?.id;

  const loadProxyConfig = async () => {
    if (!userId) return;
    setLoadingProxy(true);
    const { data, error } = await supabase
      .from('proxy_configs')
      .select('*')
      .eq('user_id', userId)
      .maybeSingle();

    if (!error && data) {
      setProxyConfig(data);
      setForm({
        proxy_host: data.proxy_host || '',
        proxy_port: data.proxy_port || '',
        proxy_username: data.proxy_username || '',
        proxy_password: data.proxy_password || '',
      });
    } else {
      setProxyConfig(null);
    }
    setLoadingProxy(false);
  };

  useEffect(() => {
    loadProxyConfig();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  const handleSaveProxy = async (e) => {
    e.preventDefault();
    if (!userId) return;

    const payload = {
      user_id: userId,
      proxy_host: form.proxy_host.trim(),
      proxy_port: form.proxy_port ? parseInt(form.proxy_port, 10) : null,
      proxy_username: form.proxy_username.trim(),
      proxy_password: form.proxy_password,
      updated_at: new Date().toISOString(),
    };

    const { error } = await supabase.from('proxy_configs').upsert(payload, { onConflict: 'user_id' });
    if (!error) {
      setSavedMsg('Configuración de proxy guardada en tu cuenta.');
      setEditing(false);
      loadProxyConfig();
    } else {
      setSavedMsg('⚠ No se pudo guardar: ' + error.message);
    }
    setTimeout(() => setSavedMsg(''), 3500);
  };

  const hasProxy = proxyConfig && proxyConfig.proxy_host;

  return (
    <div className="space-y-4 animate-in fade-in duration-200">

      <DesktopTunnelControl session={session} onTunnelStarted={onTunnelStarted} />

      {/* Network & Proxy Status */}
      <div className="p-4 bg-azzazel-900/90 border border-slate-800/80 rounded-2xl shadow-xl space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <IconShield className="w-4 h-4 text-blue-400" />
            <span>Proxy Corporativo & Seguridad</span>
          </div>
          <button
            onClick={() => setEditing((v) => !v)}
            className="text-[11px] font-semibold text-blue-400 hover:text-blue-300"
          >
            {editing ? 'Cancelar' : hasProxy ? 'Editar' : 'Configurar'}
          </button>
        </div>

        {editing ? (
          <form onSubmit={handleSaveProxy} className="space-y-2.5">
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Esta configuración se guarda cifrada en tu cuenta de Supabase, nunca en el código de la aplicación. Solo tú puedes verla.
            </p>
            <div className="grid grid-cols-2 gap-2">
              <input
                type="text"
                placeholder="Host del proxy (proxy.tuempresa.com)"
                value={form.proxy_host}
                onChange={(e) => setForm({ ...form, proxy_host: e.target.value })}
                className="col-span-2 px-3 py-2 bg-azzazel-950/80 border border-slate-700/70 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
              <input
                type="number"
                placeholder="Puerto (3128)"
                value={form.proxy_port}
                onChange={(e) => setForm({ ...form, proxy_port: e.target.value })}
                className="px-3 py-2 bg-azzazel-950/80 border border-slate-700/70 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
              <input
                type="text"
                placeholder="Usuario"
                value={form.proxy_username}
                onChange={(e) => setForm({ ...form, proxy_username: e.target.value })}
                className="px-3 py-2 bg-azzazel-950/80 border border-slate-700/70 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
              <input
                type="password"
                placeholder="Contraseña"
                value={form.proxy_password}
                onChange={(e) => setForm({ ...form, proxy_password: e.target.value })}
                className="col-span-2 px-3 py-2 bg-azzazel-950/80 border border-slate-700/70 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <button
              type="submit"
              className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg transition-colors"
            >
              Guardar en mi cuenta
            </button>
          </form>
        ) : (
          <div className="space-y-2">
            <div className="flex items-center justify-between p-3 bg-azzazel-950/70 border border-slate-800 rounded-xl">
              <div className="flex items-center gap-3 min-w-0">
                <span className="text-xl">🏢</span>
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-white">Proxy Corporativo</div>
                  <div className="text-[11px] text-slate-400 truncate">
                    {loadingProxy ? 'Cargando...' : hasProxy ? `${proxyConfig.proxy_host}:${proxyConfig.proxy_port || ''}` : 'Sin configurar'}
                  </div>
                </div>
              </div>
              <span className={`px-2.5 py-1 text-[10px] font-bold rounded-full border shrink-0 ${
                hasProxy ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/50' : 'bg-slate-800/60 text-slate-400 border-slate-700/50'
              }`}>
                {hasProxy ? 'CONFIGURADO' : 'PENDIENTE'}
              </span>
            </div>

            <div className="flex items-center justify-between p-3 bg-azzazel-950/70 border border-slate-800 rounded-xl">
              <div className="flex items-center gap-3 min-w-0">
                <span className="text-xl">👤</span>
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-white">Usuario de Proxy</div>
                  <div className="text-[11px] text-slate-400 truncate">
                    {hasProxy ? proxyConfig.proxy_username || 'Sin usuario' : '—'}
                  </div>
                </div>
              </div>
              <span className="px-2.5 py-1 text-[10px] font-bold rounded-full bg-blue-950/60 text-blue-400 border border-blue-800/50 shrink-0">
                {hasProxy ? 'GUARDADO' : 'N/D'}
              </span>
            </div>

            <div className="flex items-center justify-between p-3 bg-azzazel-950/70 border border-slate-800 rounded-xl">
              <div className="flex items-center gap-3 min-w-0">
                <span className="p-1.5 rounded-lg bg-indigo-950/60 text-indigo-400 border border-indigo-800/40 shrink-0">
                  <IconCloud className="w-4 h-4" />
                </span>
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-white">Cuenta Sincronizada</div>
                  <div className="text-[11px] text-slate-400 truncate">
                    {session?.user?.email || 'Sin sesión'}
                  </div>
                </div>
              </div>
              <span className="px-2.5 py-1 text-[10px] font-bold rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/50 shrink-0">
                SINCRONIZADO
              </span>
            </div>
          </div>
        )}

        {savedMsg && (
          <div className="flex items-center gap-2 text-xs text-emerald-400 font-medium pt-1">
            <IconCheck className="w-4 h-4 shrink-0" />
            <span>{savedMsg}</span>
          </div>
        )}
      </div>

      {/* Hardware Metrics */}
      <div className="p-4 bg-azzazel-900/90 border border-slate-800/80 rounded-2xl shadow-xl space-y-3">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <IconCpu className="w-4 h-4 text-indigo-400" />
          <span>Métricas de Hardware de la PC</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          <div className="p-3.5 bg-azzazel-950/70 border border-slate-800 rounded-xl flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-950/60 text-blue-400 border border-blue-800/40">
              <IconHardDrive className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Espacio en Disco C:</div>
              <div className="text-xs font-bold text-white mt-0.5">{diskFree || 'Calculando...'}</div>
            </div>
          </div>

          <div className="p-3.5 bg-azzazel-950/70 border border-slate-800 rounded-xl flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-950/60 text-purple-400 border border-purple-800/40">
              <IconRam className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Estado de Túnel</div>
              <div className="text-xs font-bold text-white mt-0.5">
                {isOnline ? 'Conexión Activa' : 'Túnel Inactivo'}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
