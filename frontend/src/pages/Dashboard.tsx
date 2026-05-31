import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FolderOpen, Globe, Clock, TrendingUp, AlertTriangle, Plus } from 'lucide-react';
import { useAppStore } from '../store/useAppStore';
import { AppLogo } from '../components/AppLogo';
import { SecurityScoreCard } from '../components/SecurityScoreCard';
import { SeverityBadge } from '../components/SeverityBadge';
import { SeverityChart } from '../components/SeverityChart';
import { formatDate, formatDuration, scoreColor } from '../lib/utils';
import { api } from '../lib/api';
import { Scan, ScanSummary } from '@sentinelscope/shared';

// Demo data for when no scans exist
const DEMO_SUMMARY: ScanSummary = { total: 20, critical: 2, high: 5, medium: 7, low: 4, info: 2 };

function ScanCard({ scan }: { scan: Scan }) {
  const navigate = useNavigate();
  const summary: ScanSummary = typeof scan.summary === 'string'
    ? JSON.parse(scan.summary)
    : scan.summary;

  return (
    <div
      onClick={() => navigate(`/scans/${scan.id}`)}
      className="card hover:border-dark-700 cursor-pointer transition-all group"
    >
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex min-w-0 items-center gap-2">
          {scan.type === 'url' ? <Globe className="w-4 h-4 text-cyan-400" /> : <FolderOpen className="w-4 h-4 text-violet-400" />}
          <span className="min-w-0 truncate font-semibold text-gray-200 transition-colors group-hover:text-white">
            {scan.projectName}
          </span>
        </div>
        <span className="flex-shrink-0 text-lg font-bold" style={{ color: scoreColor(scan.score) }}>
          {scan.score}
        </span>
      </div>
      <div className="text-xs text-gray-500 truncate mb-3">{scan.target}</div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        {summary.critical > 0 && (
          <span className="flex items-center gap-1 text-red-400">
            <AlertTriangle className="w-3 h-3" /> {summary.critical} críticos
          </span>
        )}
        {summary.high > 0 && (
          <span className="text-orange-400">{summary.high} altos</span>
        )}
        <span className="text-gray-600 sm:ml-auto">{formatDate(scan.startedAt)}</span>
      </div>
    </div>
  );
}

export function Dashboard() {
  const { scans, backendOnline, localScansEnabled, setScans } = useAppStore();
  const navigate = useNavigate();

  useEffect(() => {
    if (backendOnline) {
      api.getScans().then(setScans).catch(() => {});
    }
  }, [backendOnline]);

  const visibleScans = localScansEnabled ? scans : scans.filter(scan => scan.type === 'url');
  const avgScore = visibleScans.length > 0
    ? Math.round(visibleScans.reduce((a, s) => a + s.score, 0) / visibleScans.length)
    : 0;

  const totalSummary = visibleScans.reduce((acc, s) => {
    const sum = typeof s.summary === 'string' ? JSON.parse(s.summary) : s.summary;
    return {
      total: acc.total + sum.total,
      critical: acc.critical + sum.critical,
      high: acc.high + sum.high,
      medium: acc.medium + sum.medium,
      low: acc.low + sum.low,
      info: acc.info + sum.info,
    };
  }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });

  const displaySummary = visibleScans.length === 0 ? DEMO_SUMMARY : totalSummary;
  const displayScore = visibleScans.length === 0 ? 62 : avgScore;

  return (
    <div className="space-y-5 sm:space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h1 className="mobile-page-title flex items-center gap-3">
            <AppLogo className="h-8 w-8 rounded-lg bg-dark-850 ring-1 ring-blue-500/30 sm:h-9 sm:w-9" />
            Dashboard
          </h1>
          <p className="text-gray-500 text-sm mt-1">
            Visão geral de segurança dos seus projetos
          </p>
        </div>
        <button
          onClick={() => navigate('/scan/url')}
          className="btn-primary touch-row flex w-full items-center justify-center gap-2 sm:w-auto"
        >
          <Plus className="w-4 h-4" />
          Novo Scan
        </button>
      </div>

      {visibleScans.length === 0 && (
        <div className="card border-dashed border-violet-800/50 bg-violet-900/5 text-center py-4">
          <AppLogo className="w-12 h-12 mx-auto mb-2 opacity-80" />
          <p className="text-gray-500 text-sm">Modo demo — dados simulados. Inicie seu primeiro scan!</p>
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 md:gap-4">
        <div className="card col-span-2 text-center sm:col-span-1">
          <SecurityScoreCard score={displayScore} />
        </div>

        {[
          { label: 'Críticos', value: displaySummary.critical, color: 'text-red-400', bg: 'bg-red-900/20' },
          { label: 'Altos', value: displaySummary.high, color: 'text-orange-400', bg: 'bg-orange-900/20' },
          { label: 'Médios', value: displaySummary.medium, color: 'text-yellow-400', bg: 'bg-yellow-900/20' },
        ].map(({ label, value, color, bg }) => (
          <div key={label} className={`card text-center ${bg} border-0`}>
            <div className={`text-3xl sm:text-4xl font-bold ${color} mb-1`}>{value}</div>
            <div className="text-sm text-gray-500">{label}</div>
          </div>
        ))}
      </div>

      {/* Charts + Stats */}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3 md:gap-4">
        <div className="card md:col-span-1">
          <div className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-violet-400" />
            Distribuição de Severidade
          </div>
          <SeverityChart summary={displaySummary} />
        </div>

        <div className="card md:col-span-2">
          <div className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            Estatísticas Gerais
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 sm:gap-4">
            {[
              { label: 'Total de Scans', value: visibleScans.length || '(demo)' },
              { label: 'Total de Achados', value: displaySummary.total },
              { label: 'Score Médio', value: displayScore + '/100' },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-lg bg-dark-800 p-3 text-center sm:p-4">
                <div className="text-xl font-bold text-gray-200 sm:text-2xl">{value}</div>
                <div className="text-xs text-gray-500 mt-1">{label}</div>
              </div>
            ))}
          </div>

          <div className="mt-4 space-y-2">
            {[
              { label: 'Críticos', value: displaySummary.critical, total: displaySummary.total, color: 'bg-red-500' },
              { label: 'Altos', value: displaySummary.high, total: displaySummary.total, color: 'bg-orange-500' },
              { label: 'Médios', value: displaySummary.medium, total: displaySummary.total, color: 'bg-yellow-500' },
              { label: 'Baixos', value: displaySummary.low, total: displaySummary.total, color: 'bg-blue-500' },
            ].map(({ label, value, total, color }) => (
              <div key={label} className="flex items-center gap-3 text-sm">
                <span className="w-16 text-xs text-gray-500">{label}</span>
                <div className="flex-1 progress-bar">
                  <div
                    className={`h-full rounded-full ${color} transition-all duration-700`}
                    style={{ width: total > 0 ? `${(value / total) * 100}%` : '0%' }}
                  />
                </div>
                <span className="w-6 text-xs text-gray-400 text-right">{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 mb-3">Ações Rápidas</h2>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {localScansEnabled && (
          <button
            onClick={() => navigate('/scan/local')}
            className="card touch-row hover:border-violet-800/50 cursor-pointer transition-all group text-left"
          >
            <FolderOpen className="w-6 h-6 text-violet-400 mb-2" />
            <div className="font-semibold text-gray-200">Analisar Projeto Local</div>
            <div className="text-xs text-gray-500 mt-1">Análise estática de código, configs, dependências</div>
          </button>
          )}
          <button
            onClick={() => navigate('/scan/url')}
            className="card touch-row hover:border-cyan-800/50 cursor-pointer transition-all group text-left"
          >
            <Globe className="w-6 h-6 text-cyan-400 mb-2" />
            <div className="font-semibold text-gray-200">Analisar URL Online</div>
            <div className="text-xs text-gray-500 mt-1">Headers, CORS, TLS, caminhos expostos</div>
          </button>
          <button
            onClick={() => navigate('/history')}
            className="card touch-row hover:border-emerald-800/50 cursor-pointer transition-all group text-left"
          >
            <Clock className="w-6 h-6 text-emerald-400 mb-2" />
            <div className="font-semibold text-gray-200">Ver Histórico</div>
            <div className="text-xs text-gray-500 mt-1">{visibleScans.length} scans realizados</div>
          </button>
        </div>
      </div>

      {/* Recent Scans */}
      {visibleScans.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-gray-400 mb-3">Scans Recentes</h2>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            {visibleScans.slice(0, 6).map(scan => (
              <ScanCard key={scan.id} scan={scan} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
