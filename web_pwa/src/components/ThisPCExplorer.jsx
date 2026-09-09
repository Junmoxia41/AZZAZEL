import React, { useState } from 'react';
import {
  IconThisPC, IconHardDrive, IconFolder, IconDownloads,
  IconDesktop, IconDocuments, IconPictures, IconFile,
  IconImageFile, IconVideoFile, IconAudioFile, IconArchiveFile,
  IconCodeFile, IconUpload, IconDownload, IconSearch,
  IconRefresh, IconEye
} from './Icons';

export default function ThisPCExplorer({
  tunnelUrl,
  isOnline,
  currentPath,
  files,
  loading,
  error,
  diskFree,
  onNavigate,
  onUploadFile,
  onPreviewFile,
  onRefresh
}) {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredFiles = files.filter(f => 
    f.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getFileIcon = (fileName, isDir) => {
    if (isDir) return <IconFolder className="w-5 h-5 text-blue-400" />;
    const ext = (fileName.split('.').pop() || '').toLowerCase();
    if (['jpg', 'jpeg', 'png', 'webp', 'gif', 'svg'].includes(ext)) {
      return <IconImageFile className="w-5 h-5 text-emerald-400" />;
    }
    if (['mp4', 'mkv', 'webm', 'mov', 'avi'].includes(ext)) {
      return <IconVideoFile className="w-5 h-5 text-purple-400" />;
    }
    if (['mp3', 'wav', 'ogg', 'flac', 'm4a'].includes(ext)) {
      return <IconAudioFile className="w-5 h-5 text-pink-400" />;
    }
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) {
      return <IconArchiveFile className="w-5 h-5 text-amber-400" />;
    }
    if (['py', 'js', 'ts', 'jsx', 'tsx', 'html', 'css', 'json', 'sh', 'bat'].includes(ext)) {
      return <IconCodeFile className="w-5 h-5 text-cyan-400" />;
    }
    return <IconFile className="w-5 h-5 text-slate-400" />;
  };

  return (
    <div className="space-y-4 animate-in fade-in duration-200">
      
      {/* SECCIÓN 1: ESTE EQUIPO / UNIDADES */}
      <div className="p-4 bg-azzazel-900/90 border border-slate-800/80 rounded-2xl shadow-xl backdrop-blur-sm">
        <div className="flex items-center justify-between mb-3.5">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-300">
            <IconThisPC className="w-4 h-4 text-blue-400" />
            <span>Este Equipo • Dispositivos y Unidades</span>
          </div>
          <button
            onClick={onRefresh}
            className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
            title="Refrescar"
          >
            <IconRefresh className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Disco C: */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
          <div
            onClick={() => onNavigate('C:\\')}
            className="p-3.5 bg-azzazel-850/80 hover:bg-slate-800/80 border border-slate-700/60 rounded-xl cursor-pointer flex items-center gap-3.5 transition-all active:scale-[0.99]"
          >
            <div className="p-2.5 rounded-xl bg-blue-950/80 text-blue-400 border border-blue-800/40 shrink-0">
              <IconHardDrive className="w-6 h-6" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-xs font-bold text-white tracking-tight">Disco Local (C:)</div>
              <div className="w-full h-1.5 bg-slate-750 rounded-full my-1.5 overflow-hidden bg-slate-900 border border-slate-700/50">
                <div className="h-full bg-gradient-to-r from-blue-600 to-indigo-500 rounded-full w-[60%]" />
              </div>
              <div className="text-[11px] text-slate-400 truncate">
                {diskFree || 'Unidad Principal del Sistema'}
              </div>
            </div>
          </div>
        </div>

        {/* Carpetas Principales */}
        <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2.5">
          Carpetas Principales
        </div>
        <div className="grid grid-cols-4 gap-2">
          <button
            onClick={() => onNavigate('Downloads')}
            className="p-3 bg-azzazel-850/70 hover:bg-blue-950/40 border border-slate-700/60 hover:border-blue-700/50 rounded-xl flex flex-col items-center justify-center gap-1.5 transition-all text-slate-200 active:scale-95"
          >
            <IconDownloads className="w-5 h-5 text-blue-400" />
            <span className="text-[11px] font-medium">Descargas</span>
          </button>

          <button
            onClick={() => onNavigate('Desktop')}
            className="p-3 bg-azzazel-850/70 hover:bg-blue-950/40 border border-slate-700/60 hover:border-blue-700/50 rounded-xl flex flex-col items-center justify-center gap-1.5 transition-all text-slate-200 active:scale-95"
          >
            <IconDesktop className="w-5 h-5 text-indigo-400" />
            <span className="text-[11px] font-medium">Escritorio</span>
          </button>

          <button
            onClick={() => onNavigate('Documents')}
            className="p-3 bg-azzazel-850/70 hover:bg-blue-950/40 border border-slate-700/60 hover:border-blue-700/50 rounded-xl flex flex-col items-center justify-center gap-1.5 transition-all text-slate-200 active:scale-95"
          >
            <IconDocuments className="w-5 h-5 text-amber-400" />
            <span className="text-[11px] font-medium">Documentos</span>
          </button>

          <button
            onClick={() => onNavigate('Pictures')}
            className="p-3 bg-azzazel-850/70 hover:bg-blue-950/40 border border-slate-700/60 hover:border-blue-700/50 rounded-xl flex flex-col items-center justify-center gap-1.5 transition-all text-slate-200 active:scale-95"
          >
            <IconPictures className="w-5 h-5 text-emerald-400" />
            <span className="text-[11px] font-medium">Imágenes</span>
          </button>
        </div>
      </div>

      {/* SECCIÓN 2: EXPLORADOR DE ARCHIVOS ACTUAL */}
      <div className="p-4 bg-azzazel-900/90 border border-slate-800/80 rounded-2xl shadow-xl backdrop-blur-sm space-y-3">
        
        {/* Breadcrumb Bar */}
        <div className="flex items-center justify-between gap-2 p-2.5 bg-azzazel-950/80 border border-slate-800 rounded-xl text-xs font-mono text-slate-300 overflow-x-auto">
          <div className="flex items-center gap-1.5 truncate">
            <span className="text-blue-400">📍</span>
            <span className="truncate">{currentPath || 'Este Equipo'}</span>
          </div>
        </div>

        {/* Search & Upload Bar */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <IconSearch className="w-3.5 h-3.5" />
            </div>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar en esta carpeta..."
              className="w-full pl-8 pr-3 py-2 bg-azzazel-950/80 border border-slate-700/60 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>

          <label className="p-2 px-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 cursor-pointer shrink-0 shadow-md shadow-blue-600/20 active:scale-95 transition-all">
            <IconUpload className="w-3.5 h-3.5" />
            <span>Subir</span>
            <input
              type="file"
              className="hidden"
              onChange={(e) => {
                if (e.target.files?.[0]) onUploadFile(e.target.files[0]);
              }}
            />
          </label>
        </div>

        {/* File List */}
        <div className="space-y-1.5 pt-1">
          {loading ? (
            <div className="py-12 text-center text-xs text-slate-400 space-y-2">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto" />
              <div>Cargando archivos desde tu PC...</div>
            </div>
          ) : error ? (
            <div className="p-6 text-center text-xs space-y-3 bg-rose-950/20 border border-rose-900/40 rounded-xl">
              <div className="text-rose-400 font-semibold">{error}</div>
              <button
                onClick={onRefresh}
                className="px-4 py-1.5 bg-slate-800 text-white rounded-lg hover:bg-slate-700 text-xs font-semibold transition-colors"
              >
                Reintentar Conexión
              </button>
            </div>
          ) : filteredFiles.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">
              {searchTerm ? 'No se encontraron archivos con ese nombre.' : 'Esta carpeta está vacía.'}
            </div>
          ) : (
            filteredFiles.map((item, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-2.5 bg-azzazel-850/60 hover:bg-slate-800/70 border border-slate-750/50 rounded-xl transition-all group"
              >
                <div
                  onClick={() => {
                    if (item.isDir) {
                      onNavigate(item.path);
                    } else {
                      onPreviewFile(item);
                    }
                  }}
                  className="flex items-center gap-3 min-w-0 flex-1 cursor-pointer pr-2"
                >
                  <span className="shrink-0">{getFileIcon(item.name, item.isDir)}</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-medium text-white truncate group-hover:text-blue-400 transition-colors">
                      {item.name}
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">
                      {item.isDir ? 'Carpeta de archivos' : item.size || 'Archivo'}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  {item.isDir ? (
                    <button
                      onClick={() => onNavigate(item.path)}
                      className="px-2.5 py-1 text-[11px] font-semibold text-blue-400 bg-blue-950/50 hover:bg-blue-900/60 border border-blue-800/40 rounded-lg transition-colors"
                    >
                      Abrir ➔
                    </button>
                  ) : (
                    <>
                      <button
                        onClick={() => onPreviewFile(item)}
                        className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-700 transition-colors"
                        title="Ver / Previsualizar"
                      >
                        <IconEye className="w-3.5 h-3.5" />
                      </button>
                      <a
                        href={`${tunnelUrl}/download?file=${encodeURIComponent(item.path)}`}
                        download={item.name}
                        target="_blank"
                        rel="noreferrer"
                        className="p-1.5 text-blue-400 hover:text-white rounded-lg hover:bg-blue-600 transition-colors"
                        title="Descargar a móvil"
                      >
                        <IconDownload className="w-3.5 h-3.5" />
                      </a>
                    </>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
