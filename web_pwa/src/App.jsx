import React, { useState, useEffect, useCallback } from 'react';
import { supabase } from './lib/supabase';
import {
  IconLogo, IconThisPC, IconDownloads, IconCpu,
  IconGear, IconRefresh, IconCheck, IconAlert
} from './components/Icons';
import AuthModal from './components/AuthModal';
import SettingsModal from './components/SettingsModal';
import ThisPCExplorer from './components/ThisPCExplorer';
import RemoteDownloader from './components/RemoteDownloader';
import PCVitals from './components/PCVitals';
import FileViewerModal from './components/FileViewerModal';

export default function App() {
  // Authentication
  const [session, setSession] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);

  // Connection & Tunnel State (namespaced por usuario; nunca compartido entre cuentas)
  const [tunnelUrl, setTunnelUrl] = useState('');
  const [isOnline, setIsOnline] = useState(false);
  const [checkingConnection, setCheckingConnection] = useState(false);
  const [lastPingTime, setLastPingTime] = useState('');

  // Navigation & UI State
  const [activeTab, setActiveTab] = useState('files'); // 'files' | 'downloader' | 'vitals'
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [previewFile, setPreviewFile] = useState(null);
  const [toastMsg, setToastMsg] = useState('');
  const [showSplash, setShowSplash] = useState(true);

  // Explorer State
  const [currentPath, setCurrentPath] = useState('');
  const [files, setFiles] = useState([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [filesError, setFilesError] = useState('');
  const [diskFree, setDiskFree] = useState('');

  // PWA Prompt
  const [deferredPrompt, setDeferredPrompt] = useState(null);
  const [showPwaBanner, setShowPwaBanner] = useState(false);

  const showToast = (msg) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(''), 3000);
  };

  // 1. Initial Auth Check (carga el enlace guardado SOLO del usuario que inicia sesión)
  useEffect(() => {
    const applySession = (newSession) => {
      setSession(newSession);
      setAuthChecked(true);
      if (newSession?.user?.id) {
        const stored = localStorage.getItem(`azzazel_tunnel_url_${newSession.user.id}`);
        setTunnelUrl(stored || '');
      } else {
        setTunnelUrl('');
      }
    };

    supabase.auth.getSession().then(({ data: { session } }) => applySession(session));

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      applySession(session);
    });

    return () => subscription.unsubscribe();
  }, []);

  // 2. PWA Install Event Listener
  useEffect(() => {
    const handler = (e) => {
      e.preventDefault();
      setDeferredPrompt(e);
      setShowPwaBanner(true);
    };
    window.addEventListener('beforeinstallprompt', handler);
    return () => window.removeEventListener('beforeinstallprompt', handler);
  }, []);

  const installPwa = () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      deferredPrompt.userChoice.then(() => {
        setShowPwaBanner(false);
        setDeferredPrompt(null);
      });
    }
  };

  // 3. Real Healthcheck & Supabase Tunnel Fetch (SOLO el túnel del usuario autenticado)
  const checkConnection = useCallback(async (customUrl = null) => {
    setCheckingConnection(true);
    let targetUrl = customUrl || tunnelUrl;

    // Si no hay URL local, consultar Supabase filtrando por el usuario autenticado.
    // RLS impide ver o mezclar túneles de otras cuentas.
    if (!targetUrl && session?.user?.id) {
      try {
        const { data, error } = await supabase
          .from('tunnels')
          .select('*')
          .eq('user_id', session.user.id)
          .maybeSingle();

        if (!error && data && data.tunnel_url) {
          targetUrl = data.tunnel_url;
          setTunnelUrl(targetUrl);
          localStorage.setItem(`azzazel_tunnel_url_${session.user.id}`, targetUrl);
        }
      } catch (err) {
        console.error('Supabase query error:', err);
      }
    }

    if (!targetUrl) {
      setIsOnline(false);
      setCheckingConnection(false);
      setLastPingTime('Sin enlace configurado');
      return false;
    }

    // Ping REAL con timeout de 3.5 segundos
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);

      const res = await fetch(`${targetUrl}/files`, {
        method: 'GET',
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (res.ok || res.status === 200) {
        setIsOnline(true);
        setLastPingTime(new Date().toLocaleTimeString());
        setCheckingConnection(false);
        return true;
      } else {
        setIsOnline(false);
        setLastPingTime('Respuesta no válida');
        setCheckingConnection(false);
        return false;
      }
    } catch (err) {
      setIsOnline(false);
      setLastPingTime('Sin respuesta (PC apagada o túnel cerrado)');
      setCheckingConnection(false);
      return false;
    }
  }, [tunnelUrl, session]);

  // 4. Cargar Archivos de la PC
  const loadFiles = useCallback(async (dirPath = '') => {
    if (!tunnelUrl) return;

    setLoadingFiles(true);
    setFilesError('');

    try {
      const fetchUrl = `${tunnelUrl}/files${dirPath ? '?dir=' + encodeURIComponent(dirPath) : ''}`;
      const res = await fetch(fetchUrl);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const htmlText = await res.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(htmlText, 'text/html');

      // Extraer ruta actual
      const breadcrumb = doc.querySelector('.breadcrumb');
      if (breadcrumb) {
        setCurrentPath(breadcrumb.textContent.replace('📍', '').trim());
      } else {
        setCurrentPath(dirPath || 'Este Equipo');
      }

      // Extraer espacio libre en disco
      const diskText = doc.body.textContent;
      const diskMatch = diskText.match(/Espacio Disco C:\s*([^\n\r<]+)/i);
      if (diskMatch) {
        setDiskFree(diskMatch[1].trim());
      }

      // Extraer lista de archivos
      const fileRows = doc.querySelectorAll('.file-row');
      const parsedItems = [];

      fileRows.forEach(row => {
        const href = row.getAttribute('href') || '';
        const isDir = href.includes('/files?dir=');
        const iconSpan = row.querySelector('span:first-child');
        const nameSpan = row.querySelector('.file-name');
        const sizeSpan = row.querySelector('.file-size');

        let rawPath = '';
        if (isDir) {
          rawPath = decodeURIComponent(href.split('?dir=')[1] || '');
        } else if (href.includes('/download?file=')) {
          rawPath = decodeURIComponent(href.split('?file=')[1] || '');
        }

        parsedItems.push({
          name: nameSpan?.textContent || row.textContent.trim(),
          isDir: isDir,
          size: sizeSpan?.textContent.replace('⬇', '').trim() || '',
          icon: iconSpan?.textContent || (isDir ? '📁' : '📄'),
          path: rawPath
        });
      });

      setFiles(parsedItems);
      setIsOnline(true);
    } catch (err) {
      setFilesError('No se pudo conectar con los archivos de tu PC.');
      setIsOnline(false);
    } finally {
      setLoadingFiles(false);
    }
  }, [tunnelUrl]);

  // Splash Screen initial sequence
  useEffect(() => {
    const timer = setTimeout(async () => {
      await checkConnection();
      setShowSplash(false);
    }, 1200);

    return () => clearTimeout(timer);
  }, [checkConnection]);

  // Cuando cambia el túnel o la conexión se establece, cargar archivos
  useEffect(() => {
    if (tunnelUrl && isOnline) {
      loadFiles(currentPath);
    }
  }, [tunnelUrl, isOnline, currentPath, loadFiles]);

  // Subir Archivo
  const handleUploadFile = async (file) => {
    if (!tunnelUrl || !isOnline) {
      showToast('⚠ PC desconectada. No se puede subir.');
      return;
    }

    showToast(`Subiendo ${file.name} a tu PC...`);
    const formData = new FormData();
    formData.append('file', file);
    formData.append('target_dir', currentPath);

    try {
      const res = await fetch(`${tunnelUrl}/upload`, {
        method: 'POST',
        body: formData,
      });
      if (res.ok) {
        showToast('✔ Archivo subido con éxito a tu PC');
        loadFiles(currentPath);
      } else {
        showToast('⚠ Error al subir archivo');
      }
    } catch (err) {
      showToast('⚠ Error de red al subir archivo');
    }
  };

  const handleSaveTunnelUrl = (newUrl) => {
    setTunnelUrl(newUrl);
    if (session?.user?.id) {
      localStorage.setItem(`azzazel_tunnel_url_${session.user.id}`, newUrl);
    }
    checkConnection(newUrl).then(ok => {
      if (ok) loadFiles('');
    });
  };

  if (!authChecked) {
    return (
      <div className="fixed inset-0 flex items-center justify-center bg-azzazel-950 text-white">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-azzazel-950 text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      
      {/* AUTH MODAL (SI NO HAY SESIÓN) */}
      {!session && <AuthModal onAuthSuccess={(s) => setSession(s)} />}

      {/* SPLASH SCREEN */}
      {showSplash && (
        <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-azzazel-950 p-6">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center text-white shadow-2xl shadow-blue-500/30 mb-5 animate-pulse">
            <IconLogo className="w-9 h-9" />
          </div>
          <h2 className="text-xl font-bold tracking-tight text-white mb-1">AZZAZEL REMOTE</h2>
          <p className="text-xs text-slate-400">Comprobando enlace seguro con tu PC...</p>
        </div>
      )}

      {/* TOAST NOTIFICATION */}
      {toastMsg && (
        <div className="fixed top-5 left-1/2 -translate-x-1/2 z-50 px-4 py-2.5 bg-azzazel-850/95 border border-slate-700 text-xs font-medium text-white rounded-full shadow-2xl backdrop-blur-md flex items-center gap-2 animate-in fade-in slide-in-from-top-4 duration-200">
          <span>{toastMsg}</span>
        </div>
      )}

      {/* SETTINGS GEAR MODAL */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        session={session}
        tunnelUrl={tunnelUrl}
        onSaveTunnelUrl={handleSaveTunnelUrl}
        isOnline={isOnline}
        lastPingTime={lastPingTime}
        onRecheckConnection={() => checkConnection()}
      />

      {/* FILE PREVIEW MODAL */}
      {previewFile && (
        <FileViewerModal
          file={previewFile}
          tunnelUrl={tunnelUrl}
          onClose={() => setPreviewFile(null)}
        />
      )}

      {/* TOP BAR */}
      <header className="sticky top-0 z-40 bg-azzazel-900/80 backdrop-blur-xl border-b border-slate-800/80 px-4 py-3">
        <div className="max-w-2xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-blue-500/20">
              <IconLogo className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                <span>AZZAZEL CLOUD</span>
              </h1>
              <p className="text-[11px] text-slate-400">
                {session?.user?.email ? session.user.email.split('@')[0] : 'PC Trabajo'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Real Status Badge */}
            <div className={`px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wide flex items-center gap-1.5 border transition-all ${
              isOnline
                ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                : 'bg-rose-950/60 text-rose-400 border-rose-800/60'
            }`}>
              <span className={`w-2 h-2 rounded-full ${
                isOnline ? 'bg-emerald-500 shadow-sm shadow-emerald-500 animate-pulse' : 'bg-rose-500'
              }`} />
              <span>{isOnline ? 'EN LÍNEA' : 'DESCONECTADO'}</span>
            </div>

            {/* Settings Gear Button */}
            <button
              onClick={() => setIsSettingsOpen(true)}
              className="p-2 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 hover:text-white border border-slate-700/60 transition-all active:scale-95"
              title="Ajustes de sincronización"
            >
              <IconGear className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 max-w-2xl w-full mx-auto p-4 space-y-4">
        
        {/* Connection Offline Warning Banner */}
        {!isOnline && (
          <div className="p-3.5 bg-rose-950/30 border border-rose-900/50 rounded-2xl flex items-center justify-between gap-3 text-xs text-rose-300 animate-in fade-in duration-200">
            <div className="flex items-center gap-2.5">
              <IconAlert className="w-4 h-4 shrink-0 text-rose-400" />
              <span>Tu PC de la oficina está desconectada. Inicia el túnel en AZZAZEL PC.</span>
            </div>
            <button
              onClick={() => checkConnection()}
              className="px-2.5 py-1 bg-rose-900/40 hover:bg-rose-800/50 text-rose-200 rounded-lg text-[11px] font-semibold shrink-0 border border-rose-800/50 transition-colors"
            >
              Comprobar
            </button>
          </div>
        )}

        {/* TAB 1: ESTE EQUIPO / ARCHIVOS */}
        {activeTab === 'files' && (
          <ThisPCExplorer
            tunnelUrl={tunnelUrl}
            isOnline={isOnline}
            currentPath={currentPath}
            files={files}
            loading={loadingFiles}
            error={filesError}
            diskFree={diskFree}
            onNavigate={(p) => loadFiles(p)}
            onUploadFile={handleUploadFile}
            onPreviewFile={(f) => setPreviewFile(f)}
            onRefresh={() => loadFiles(currentPath)}
          />
        )}

        {/* TAB 2: DESCARGAS REMOTAS */}
        {activeTab === 'downloader' && (
          <RemoteDownloader
            tunnelUrl={tunnelUrl}
            isOnline={isOnline}
          />
        )}

        {/* TAB 3: ESTADO PC & SQUID */}
        {activeTab === 'vitals' && (
          <PCVitals
            isOnline={isOnline}
            tunnelUrl={tunnelUrl}
            diskFree={diskFree}
            session={session}
            onTunnelStarted={(url) => handleSaveTunnelUrl(url)}
          />
        )}
      </main>

      {/* PWA INSTALL PROMPT BANNER */}
      {showPwaBanner && (
        <div className="fixed bottom-20 left-4 right-4 max-w-md mx-auto p-3 bg-azzazel-850 border border-blue-500/50 rounded-2xl shadow-2xl flex items-center justify-between gap-3 z-40 animate-in slide-in-from-bottom-5 duration-200">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-xl bg-blue-600 flex items-center justify-center text-white shrink-0">
              <IconLogo className="w-4 h-4" />
            </div>
            <div className="text-xs truncate">
              <div className="font-semibold text-white">Instalar AZZAZEL en tu teléfono</div>
              <div className="text-[10px] text-slate-400">Acceso rápido sin navegador</div>
            </div>
          </div>
          <button
            onClick={installPwa}
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold shrink-0 shadow-md shadow-blue-600/30 transition-colors"
          >
            Instalar
          </button>
        </div>
      )}

      {/* BOTTOM NAVIGATION BAR */}
      <nav className="fixed bottom-0 left-0 right-0 bg-azzazel-900/95 backdrop-blur-xl border-t border-slate-800/80 py-2 z-40">
        <div className="max-w-2xl mx-auto flex items-center justify-around">
          <button
            onClick={() => setActiveTab('files')}
            className={`flex flex-col items-center gap-1 py-1 px-4 rounded-xl transition-colors ${
              activeTab === 'files' ? 'text-blue-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <IconThisPC className="w-5 h-5" />
            <span className="text-[10px]">Este Equipo</span>
          </button>

          <button
            onClick={() => setActiveTab('downloader')}
            className={`flex flex-col items-center gap-1 py-1 px-4 rounded-xl transition-colors ${
              activeTab === 'downloader' ? 'text-blue-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <IconDownloads className="w-5 h-5" />
            <span className="text-[10px]">Descargas</span>
          </button>

          <button
            onClick={() => setActiveTab('vitals')}
            className={`flex flex-col items-center gap-1 py-1 px-4 rounded-xl transition-colors ${
              activeTab === 'vitals' ? 'text-blue-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <IconCpu className="w-5 h-5" />
            <span className="text-[10px]">Estado PC</span>
          </button>
        </div>
      </nav>
    </div>
  );
}
