import { useState } from 'react';
import { Download, FileCheck2, FileJson, FileText, FileType } from 'lucide-react';
import { api } from '../lib/api';

interface Props {
  scanId: string;
}

export function ExportReportButton({ scanId }: Props) {
  const [open, setOpen] = useState(false);

  const exportAs = async (format: 'json' | 'markdown' | 'pdf' | 'checklist') => {
    await api.downloadExport(scanId, format);
    setOpen(false);
  };

  return (
    <div className="relative flex-1 sm:flex-none">
      <button
        onClick={() => setOpen(!open)}
        className="btn-secondary touch-row flex w-full items-center justify-center gap-2 sm:w-auto"
      >
        <Download className="w-4 h-4" />
        Exportar
      </button>

      {open && (
        <div className="absolute right-0 top-12 z-20 w-52 overflow-hidden rounded-lg border border-dark-800 bg-dark-850 shadow-xl animate-fade-in">
          <button
            onClick={() => exportAs('json')}
            className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-300 hover:bg-dark-800 transition-colors"
          >
            <FileJson className="w-4 h-4 text-yellow-400" />
            Exportar JSON
          </button>
          <button
            onClick={() => exportAs('markdown')}
            className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-300 hover:bg-dark-800 transition-colors"
          >
            <FileText className="w-4 h-4 text-blue-400" />
            Exportar Markdown
          </button>
          <button
            onClick={() => exportAs('pdf')}
            className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-300 hover:bg-dark-800 transition-colors"
          >
            <FileType className="w-4 h-4 text-red-400" />
            Exportar PDF
          </button>
          <button
            onClick={() => exportAs('checklist')}
            className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-300 hover:bg-dark-800 transition-colors"
          >
            <FileCheck2 className="w-4 h-4 text-green-400" />
            Checklist
          </button>
        </div>
      )}
    </div>
  );
}
