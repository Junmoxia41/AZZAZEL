import React, { useState } from 'react';
import { IconDownloads, IconCheck, IconAlert } from './Icons';

export default function RemoteDownloader({ tunnelUrl, isOnline }) {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [isError, setIsError] = useState(false);

  const handleDownload = async (e) => {
    e.preventDefault();
    if (!urlInput.trim()) return;

    if (!isOnline) {
      setIsError(true);
      setStatusMsg('Tu PC está desconectada. Inicia el túnel de AZZAZEL en la PC primero.');
      return;
    }

    setLoading(true);
    setStatusMsg('');
    setIsError(false);

    try {
      const res = await fetch(`${tunnelUrl}/remote_download`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodeURIComponent(urlInput.trim())}`
      });

      if (res.ok) {
        setIsError(false);
        setStatusMsg('🚀 ¡Descarga iniciada en tu PC! Se guardará en tu carpeta Descargas.');
        setUrlInput('');
      } else {
        setIsError(true);
        setStatusMsg('Error al enviar la orden de descarga a la PC.');
      }
    } catch (err) {
      setIsError(true);
      setStatusMsg('No se pudo comunicar con el PC: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-5 bg-azzazel-900/90 border border-slate-800/80 rounded-2xl shadow-xl backdrop-blur-sm space-y-4 animate-in fade-in duration-200">
      
      <div className="flex items-center gap-2.5">
        <span className="p-2.5 rounded-xl bg-blue-950/80 text-blue-400 border border-blue-800/40">
          <IconDownloads className="w-5 h-5" />
        </span>
        <div>
          <h3 className="text-sm font-bold text-white">Gestor de Descargas Remotas</h3>
          <p className="text-xs text-slate-400">Descarga a máxima velocidad usando el internet de tu oficina</p>
        </div>
      </div>

      <p className="text-xs text-slate-300 leading-relaxed bg-azzazel-950/60 p-3.5 rounded-xl border border-slate-800">
        Pega cualquier enlace directo (película, juego, programa, ISO o archivo ZIP). Tu PC de la oficina lo descargará en segundo plano y lo guardará en tu carpeta <b>Descargas</b>.
      </p>

      {statusMsg && (
        <div className={`flex items-center gap-2 p-3 text-xs rounded-xl border ${
          isError 
            ? 'bg-rose-950/40 text-rose-300 border-rose-800/60' 
            : 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60'
        }`}>
          {isError ? <IconAlert className="w-4 h-4 shrink-0" /> : <IconCheck className="w-4 h-4 shrink-0" />}
          <span>{statusMsg}</span>
        </div>
      )}

      <form onSubmit={handleDownload} className="space-y-3">
        <div>
          <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
            URL directa del archivo a descargar
          </label>
          <input
            type="url"
            required
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="https://ejemplo.com/archivo-grande.zip"
            className="w-full px-3.5 py-2.5 bg-azzazel-950/80 border border-slate-700/70 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono transition-colors"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-blue-500/25 transition-all transform active:scale-[0.99] disabled:opacity-50 flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
              <span>Enviando orden...</span>
            </>
          ) : (
            <>
              <IconDownloads className="w-4 h-4" />
              <span>Iniciar Descarga en PC</span>
            </>
          )}
        </button>
      </form>
    </div>
  );
}
