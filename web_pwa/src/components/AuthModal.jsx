import React, { useState } from 'react';
import { supabase } from '../lib/supabase';
import { IconLogo, IconLock, IconUser, IconAlert, IconCheck } from './Icons';

export default function AuthModal({ onAuthSuccess }) {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [infoMsg, setInfoMsg] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setInfoMsg('');
    setLoading(true);

    try {
      if (isLogin) {
        const { data, error } = await supabase.auth.signInWithPassword({
          email,
          password,
        });
        if (error) throw error;
        if (data.session) {
          onAuthSuccess(data.session);
        }
      } else {
        const { data, error } = await supabase.auth.signUp({
          email,
          password,
        });
        if (error) throw error;
        if (data.session) {
          onAuthSuccess(data.session);
        } else {
          setInfoMsg('Cuenta creada con éxito. Ya puedes iniciar sesión con tus credenciales.');
          setIsLogin(true);
        }
      }
    } catch (err) {
      setErrorMsg(err.message || 'Error durante la autenticación.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
      <div className="w-full max-w-md bg-azzazel-900 border border-slate-700/60 rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-200">
        
        {/* Header */}
        <div className="p-6 text-center border-b border-slate-800 bg-gradient-to-b from-blue-950/30 to-transparent">
          <div className="w-14 h-14 mx-auto mb-3 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center text-white shadow-lg shadow-blue-500/25">
            <IconLogo className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-bold tracking-tight text-white">AZZAZEL CLOUD</h2>
          <p className="text-xs text-slate-400 mt-1">Acceso seguro a tu PC corporativo y archivos</p>
        </div>

        {/* Tab Selector */}
        <div className="flex border-b border-slate-800 bg-azzazel-950/50 p-1.5 mx-6 mt-5 rounded-xl">
          <button
            type="button"
            onClick={() => { setIsLogin(true); setErrorMsg(''); setInfoMsg(''); }}
            className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all ${
              isLogin ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Iniciar Sesión
          </button>
          <button
            type="button"
            onClick={() => { setIsLogin(false); setErrorMsg(''); setInfoMsg(''); }}
            className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all ${
              !isLogin ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Registrarse
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {errorMsg && (
            <div className="flex items-center gap-2.5 p-3 text-xs text-rose-400 bg-rose-950/40 border border-rose-800/60 rounded-xl">
              <IconAlert className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {infoMsg && (
            <div className="flex items-center gap-2.5 p-3 text-xs text-emerald-400 bg-emerald-950/40 border border-emerald-800/60 rounded-xl">
              <IconCheck className="w-4 h-4 shrink-0" />
              <span>{infoMsg}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Correo Electrónico</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <IconUser className="w-4 h-4" />
              </div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="tu@correo.com"
                className="w-full pl-9 pr-3.5 py-2.5 bg-azzazel-950/80 border border-slate-700/70 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Contraseña Maestra</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <IconLock className="w-4 h-4" />
              </div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3.5 py-2.5 bg-azzazel-950/80 border border-slate-700/70 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 px-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-sm font-semibold rounded-xl shadow-lg shadow-blue-500/25 transition-all transform active:scale-[0.99] disabled:opacity-50"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                <span>Autenticando...</span>
              </span>
            ) : isLogin ? (
              'Ingresar a mi PC'
            ) : (
              'Crear Cuenta en Supabase'
            )}
          </button>
        </form>

        <div className="px-6 py-4 bg-azzazel-950/60 border-t border-slate-800 text-center text-[11px] text-slate-500">
          Protegido con cifrado de grado militar y autenticación Supabase JWT
        </div>
      </div>
    </div>
  );
}
