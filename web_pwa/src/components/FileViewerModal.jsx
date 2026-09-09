import React from 'react';
import { IconClose, IconDownload } from './Icons';

export default function FileViewerModal({ file, onClose, tunnelUrl }) {
  if (!file) return null;

  const downloadUrl = `${tunnelUrl}/download?file=${encodeURIComponent(file.path)}`;
  const ext = (file.name.split('.').pop() || '').toLowerCase();

  const isImage = ['jpg', 'jpeg', 'png', 'webp', 'gif', 'svg'].includes(ext);
  const isVideo = ['mp4', 'webm', 'ogg', 'mov'].includes(ext);
  const isAudio = ['mp3', 'wav', 'ogg', 'm4a', 'flac'].includes(ext);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-md animate-in fade-in duration-150">
      <div className="w-full max-w-2xl bg-azzazel-900 border border-slate-700/60 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800 bg-azzazel-950/60">
          <div className="flex items-center gap-2.5 overflow-hidden pr-2">
            <span className="text-lg">{file.icon || '📄'}</span>
            <span className="text-xs font-semibold text-white truncate">{file.name}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <a
              href={downloadUrl}
              download={file.name}
              target="_blank"
              rel="noreferrer"
              className="p-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors"
            >
              <IconDownload className="w-3.5 h-3.5" />
              <span>Descargar</span>
            </a>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
            >
              <IconClose className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Viewer Body */}
        <div className="p-4 flex-1 flex items-center justify-center overflow-auto bg-black/40 min-h-[250px]">
          {isImage ? (
            <img
              src={downloadUrl}
              alt={file.name}
              className="max-h-[70vh] max-w-full object-contain rounded-lg shadow-lg"
            />
          ) : isVideo ? (
            <video
              src={downloadUrl}
              controls
              autoPlay
              className="max-h-[70vh] max-w-full rounded-lg"
            />
          ) : isAudio ? (
            <div className="w-full max-w-md p-6 bg-azzazel-850 rounded-2xl border border-slate-700 text-center space-y-4">
              <div className="text-4xl">🎵</div>
              <div className="text-sm font-semibold text-white">{file.name}</div>
              <audio src={downloadUrl} controls className="w-full" />
            </div>
          ) : (
            <div className="text-center p-8 space-y-3">
              <div className="text-4xl">{file.icon || '📑'}</div>
              <div className="text-sm font-semibold text-white">{file.name}</div>
              <p className="text-xs text-slate-400">Este tipo de archivo se puede descargar directamente a tu teléfono.</p>
              <a
                href={downloadUrl}
                download={file.name}
                className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-xl transition-all"
              >
                <IconDownload className="w-4 h-4" />
                <span>Descargar Archivo ({file.size || 'Tamaño N/A'})</span>
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
