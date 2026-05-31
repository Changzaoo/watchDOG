import { useEffect, useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import {
  Globe, FolderOpen, AlertTriangle, Filter, Search,
  ArrowLeft, RefreshCw, ShieldAlert, ShieldCheck
} from 'lucide-react';
import { Finding, Severity } from '@sentinelscope/shared';
import { api } from '../lib/api';
import { useAppStore } from '../store/useAppStore';
import { SecurityScoreCard } from '../components/SecurityScoreCard';
import { SeverityBadge } from '../components/SeverityBadge';
import { ScanProgress } from '../components/ScanProgress';
import { LiveLogPanel } from '../components/LiveLogPanel';
import { FindingCard } from '../components/FindingCard';
import { TechStackDetected } from '../components/TechStackDetected';
import { CategoryChart } from '../components/CategoryChart';
import { ExportReportButton } from '../components/ExportReportButton';
import { FixPromptPanel } from '../components/FixPromptPanel';
import { AppLogo } from '../components/AppLogo';
import { formatDate, formatDuration, severityLabel } from '../lib/utils';

export function ScanResult() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { currentScan, currentFindings, currentLogs, scanProgress, setCurrentScan, setCurrentFindings, setCurrentLogs, addLog, setScanProgress } = useAppStore();

  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ severity: '', category: '', status: '', search: '' });
  const [eventSource, setEventSource] = useState<EventSource | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!id) return;
    loadScan();

    return () => { eventSource?.close(); };
  }, [id]);

  async function loadScan() {
    if (!id) return;
    try {
      setLoading(true);
      const data = await api.getScan(id);
      setCurrentScan(data.scan as any);
      setCurrentFindings(data.findings as any);
      setCurrentLogs(data.logs as any);

      if (data.scan.status === 'running' || data.scan.status === 'pending') {
        startListening(id);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function startListening(scanId: string) {
    const es = api.listenScanEvents(scanId, (event) => {
      if (event.type === 'log') {
        addLog({ id: Date.now().toString(), scanId, level: event.level || 'info', message: event.message, createdAt: new Date().toISOString() });
      } else if (event.type === 'progress') {
        setScanProgress({ step: event.data?.step || event.step || '', progress: event.data?.progress ?? event.progress ?? 0 });
        if ((event.data?.progress ?? event.progress) === 100) {
          setTimeout(() => loadScan(), 1000);
        }
      }
    });
    setEventSource(es);
  }

  const filtered = currentFindings.filter(f => {
    if (filter.severity && f.severity !== filter.severity) return false;
    if (filter.category && f.category !== filter.category) return false;
    if (filter.status && f.status !== filter.status) return false;
    if (filter.search) {
      const q = filter.search.toLowerCase();
      if (!f.title.toLowerCase().includes(q) && !f.description.toLowerCase().includes(q) && !(f.filePath || '').toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const categories = [...new Set(currentFindings.map(f => f.category))].sort();
  const summary = currentScan?.summary ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-center space-y-3">
          <AppLogo className="w-16 h-16 mx-auto animate-pulse" />
          <div className="text-gray-400">Carregando scan...</div>
        </div>
      </div>
    );
  }

  if (error || !currentScan) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-center space-y-3">
          <AlertTriangle className="w-12 h-12 text-red-400 mx-auto" />
          <div className="text-gray-300">{error || 'Scan não encontrado'}</div>
          <button onClick={() => navigate(-1)} className="btn-secondary">Voltar</button>
        </div>
      </div>
    );
  }

  const isRunning = currentScan.status === 'running' || currentScan.status === 'pending';

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div className="flex items-start gap-3">
          <button onClick={() => navigate(-1)} className="btn-secondary p-2 mt-1">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              {currentScan.type === 'url'
                ? <Globe className="w-5 h-5 text-cyan-400" />
                : <FolderOpen className="w-5 h-5 text-violet-400" />}
              <h1 className="text-xl font-bold text-white">{currentScan.projectName}</h1>
              <span className={`text-xs px-2 py-0.5 rounded-full ${
                currentScan.status === 'completed' ? 'bg-green-900/30 text-green-400' :
                currentScan.status === 'running' ? 'bg-blue-900/30 text-blue-400' :
                'bg-red-900/30 text-red-400'
              }`}>
                {currentScan.status}
              </span>
            </div>
            <div className="text-sm text-gray-500 mt-0.5">{currentScan.target}</div>
            <div className="text-xs text-gray-600 mt-0.5">
              {formatDate(currentScan.startedAt)} · {formatDuration(currentScan.durationMs)}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {currentScan.status === 'completed' && (
            <>
              <Link to={`/scans/${currentScan.id}/threat-model`} className="btn-secondary flex items-center gap-2">
                <ShieldAlert className="w-4 h-4" />
                Threat Model
              </Link>
              <Link to={`/scans/${currentScan.id}/defense-depth`} className="btn-secondary flex items-center gap-2">
                <ShieldCheck className="w-4 h-4" />
                Defense Depth
              </Link>
              <ExportReportButton scanId={currentScan.id} />
            </>
          )}
          <button onClick={loadScan} className="btn-secondary p-2">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Progress */}
      {isRunning && scanProgress && (
        <ScanProgress step={scanProgress.step} progress={scanProgress.progress} />
      )}
      {isRunning && (
        <LiveLogPanel logs={currentLogs.slice(-50)} />
      )}

      {/* Summary */}
      {!isRunning && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <div className="card col-span-1 md:col-span-1 flex flex-col items-center justify-center">
            <SecurityScoreCard score={currentScan.score} size="sm" />
          </div>
          {[
            { label: 'Críticos', value: summary.critical, cls: 'text-red-400 bg-red-900/20' },
            { label: 'Altos', value: summary.high, cls: 'text-orange-400 bg-orange-900/20' },
            { label: 'Médios', value: summary.medium, cls: 'text-yellow-400 bg-yellow-900/20' },
            { label: 'Baixos', value: summary.low, cls: 'text-blue-400 bg-blue-900/20' },
            { label: 'Info', value: summary.info, cls: 'text-gray-400 bg-gray-900/20' },
          ].map(({ label, value, cls }) => (
            <div key={label} className={`card text-center ${cls} border-0`}>
              <div className="text-2xl font-bold">{value}</div>
              <div className="text-xs text-gray-500 mt-0.5">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tech stack + Category chart */}
      {!isRunning && currentScan.techStack?.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="card">
            <div className="text-sm font-semibold text-gray-300 mb-3">Stack Detectada</div>
            <TechStackDetected techStack={currentScan.techStack} />
          </div>
          <div className="card">
            <div className="text-sm font-semibold text-gray-300 mb-3">Achados por Categoria</div>
            <CategoryChart findings={currentFindings} />
          </div>
        </div>
      )}

      {/* Findings */}
      {!isRunning && (
        <div>
          {/* Filters */}
          <div className="flex items-center gap-3 mb-4 flex-wrap">
            <div className="flex items-center gap-2 text-sm font-semibold text-gray-300">
              <Filter className="w-4 h-4 text-violet-400" />
              {filtered.length} achados
            </div>
            <div className="flex-1 relative max-w-xs">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                className="input pl-9 text-sm py-1.5"
                placeholder="Buscar..."
                value={filter.search}
                onChange={e => setFilter(f => ({ ...f, search: e.target.value }))}
              />
            </div>
            <select
              className="input py-1.5 text-sm w-auto"
              value={filter.severity}
              onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}
            >
              <option value="">Todas severidades</option>
              {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(s => (
                <option key={s} value={s}>{severityLabel(s)}</option>
              ))}
            </select>
            <select
              className="input py-1.5 text-sm w-auto"
              value={filter.category}
              onChange={e => setFilter(f => ({ ...f, category: e.target.value }))}
            >
              <option value="">Todas categorias</option>
              {categories.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <select
              className="input py-1.5 text-sm w-auto"
              value={filter.status}
              onChange={e => setFilter(f => ({ ...f, status: e.target.value }))}
            >
              <option value="">Todos status</option>
              <option value="open">Aberto</option>
              <option value="fixed">Corrigido</option>
              <option value="ignored">Ignorado</option>
              <option value="false_positive">Falso Positivo</option>
            </select>
          </div>

          {/* Findings list */}
          <div className="space-y-2">
            {filtered.length === 0 ? (
              <div className="card text-center py-10 text-gray-500">
                <AppLogo className="w-14 h-14 mx-auto mb-3 opacity-40" />
                {currentFindings.length === 0 ? 'Nenhum achado encontrado — ótimo!' : 'Nenhum achado corresponde aos filtros'}
              </div>
            ) : (
              filtered.map(f => <FindingCard key={f.id} finding={f} />)
            )}
          </div>

          {currentFindings.length > 0 && currentScan.status === 'completed' && (
            <div className="mt-6">
              <FixPromptPanel scan={currentScan} findings={currentFindings} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
