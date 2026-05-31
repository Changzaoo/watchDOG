import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { History as HistoryIcon, Globe, FolderOpen, AlertTriangle } from 'lucide-react';
import { Scan, ScanSummary } from '@sentinelscope/shared';
import { useAppStore } from '../store/useAppStore';
import { api } from '../lib/api';
import { SecurityScoreCard } from '../components/SecurityScoreCard';
import { formatDate, formatDuration } from '../lib/utils';

export function History() {
  const { scans, setScans, backendOnline, localScansEnabled } = useAppStore();
  const navigate = useNavigate();

  useEffect(() => {
    if (backendOnline) {
      api.getScans().then(setScans).catch(() => {});
    }
  }, [backendOnline]);

  const visibleScans = localScansEnabled ? scans : scans.filter(scan => scan.type === 'url');

  return (
    <div className="space-y-5 sm:space-y-6 animate-fade-in">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h1 className="mobile-page-title flex items-center gap-3">
            <HistoryIcon className="h-6 w-6 text-violet-400 sm:h-7 sm:w-7" />
            Histórico de Scans
          </h1>
          <p className="text-gray-500 text-sm mt-1">{visibleScans.length} scans realizados</p>
        </div>
        <button onClick={() => navigate('/scan/url')} className="btn-primary touch-row w-full sm:w-auto">
          + Novo Scan
        </button>
      </div>

      {visibleScans.length === 0 ? (
        <div className="card text-center py-12 sm:py-16">
          <HistoryIcon className="w-12 h-12 mx-auto mb-4 text-gray-600" />
          <p className="text-gray-400 font-medium">Nenhum scan realizado ainda</p>
          <p className="text-gray-600 text-sm mt-1">Inicie seu primeiro scan clicando no botão acima</p>
        </div>
      ) : (
        <div className="space-y-2">
          {visibleScans.map(scan => {
            const summary: ScanSummary = typeof scan.summary === 'string' ? JSON.parse(scan.summary) : scan.summary;
            return (
              <div
                key={scan.id}
                onClick={() => navigate(`/scans/${scan.id}`)}
                className="card hover:border-dark-700 cursor-pointer transition-all flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-4"
              >
                <div className="w-full flex-shrink-0 sm:w-auto">
                  <SecurityScoreCard score={scan.score} size="sm" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-start gap-2">
                    {scan.type === 'url'
                      ? <Globe className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                      : <FolderOpen className="w-4 h-4 text-violet-400 flex-shrink-0" />}
                    <span className="min-w-0 flex-1 truncate font-semibold text-gray-200">{scan.projectName}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full ml-auto flex-shrink-0 ${
                      scan.status === 'completed' ? 'bg-green-900/30 text-green-400' :
                      scan.status === 'running' ? 'bg-blue-900/30 text-blue-400 animate-pulse' :
                      'bg-red-900/30 text-red-400'
                    }`}>{scan.status}</span>
                  </div>
                  <div className="text-xs text-gray-600 truncate mt-0.5">{scan.target}</div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1.5 text-xs">
                    <span className="text-gray-600">{formatDate(scan.startedAt)}</span>
                    <span className="text-gray-600">{formatDuration(scan.durationMs)}</span>
                    {summary.critical > 0 && (
                      <span className="flex items-center gap-1 text-red-400">
                        <AlertTriangle className="w-3 h-3" /> {summary.critical} críticos
                      </span>
                    )}
                    <span className="text-gray-500">{summary.total} achados</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
