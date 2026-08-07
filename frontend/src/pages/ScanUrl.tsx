import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Globe, Play, AlertCircle, ArrowLeft } from 'lucide-react';
import { api } from '../lib/api';
import { LocalInstallPanel } from '../components/LocalInstallPanel';
import { QrCodeReaderButton } from '../components/QrCodeReaderButton';
import { useAppStore } from '../store/useAppStore';

export function ScanUrl() {
  const [url, setUrl] = useState('');
  const [depth, setDepth] = useState<'quick' | 'normal' | 'deep'>('normal');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { backendOnline, backendHealthChecked, localScansEnabled } = useAppStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!backendOnline) { setError('Backend offline. Tente novamente em alguns segundos.'); return; }
    if (!url.trim()) { setError('Informe a URL'); return; }

    let finalUrl = url.trim();
    if (!/^https?:\/\//i.test(finalUrl)) finalUrl = 'https://' + finalUrl;

    try {
      new URL(finalUrl);
    } catch {
      setError('URL invalida');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const { scanId } = await api.startUrlScan(finalUrl, { depth });
      navigate(`/scans/${scanId}`);
    } catch (err: any) {
      setError(err.message || 'Erro ao iniciar scan');
    } finally {
      setLoading(false);
    }
  };

  const DEPTHS = [
    { value: 'quick', label: 'Rapida', desc: '~30s - Headers e TLS apenas' },
    { value: 'normal', label: 'Normal', desc: '~1-2min - Analise completa padrao' },
    { value: 'deep', label: 'Profunda', desc: '~3-5min - Verifica mais caminhos' },
  ];

  return (
    <div className="mx-auto max-w-2xl space-y-5 sm:space-y-6 animate-fade-in">
      <div className="flex items-start gap-3">
        <button onClick={() => navigate(-1)} className="btn-secondary flex-shrink-0 p-2">
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="min-w-0">
          <h1 className="mobile-section-title flex items-center gap-2">
            <Globe className="h-5 w-5 flex-shrink-0 text-cyan-400" />
            Analise de URL Online
          </h1>
          <p className="text-gray-500 text-sm">Analise passiva e defensiva de aplicacao online</p>
        </div>
      </div>

      {backendHealthChecked && !localScansEnabled && <LocalInstallPanel />}

      <div className="card space-y-2">
        <h3 className="text-sm font-semibold text-gray-300">O que sera verificado:</h3>
        <div className="grid grid-cols-1 gap-1.5 text-xs text-gray-400 sm:grid-cols-2">
          {[
            'HTTPS e redirect HTTP->HTTPS',
            'Certificado TLS e expiracao',
            'Headers de seguranca',
            'Content-Security-Policy',
            'HSTS, X-Frame-Options',
            'CORS e credenciais',
            'Caminhos expostos comuns',
            'Swagger/GraphQL publico',
            'Arquivo .env exposto',
            'Endpoints de debug',
            'Tecnologias expostas',
            'Server/X-Powered-By',
          ].map(item => <div key={item}>{item}</div>)}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="card space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">
            URL da Aplicacao *
          </label>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              className="input"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://minhaaplicacao.com"
              disabled={loading}
            />
            <QrCodeReaderButton disabled={loading} onRead={setUrl} />
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Profundidade da Analise
          </label>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            {DEPTHS.map(d => (
              <button
                key={d.value}
                type="button"
                onClick={() => setDepth(d.value as any)}
                className={`touch-row rounded-lg border p-3 text-left transition-all ${
                  depth === d.value
                    ? 'border-violet-600 bg-violet-900/30 text-violet-300'
                    : 'border-dark-800 bg-dark-800 text-gray-400 hover:border-dark-700'
                }`}
              >
                <div className="text-sm font-medium">{d.label}</div>
                <div className="text-xs mt-0.5 opacity-70">{d.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-red-400 bg-red-900/20 border border-red-800/50 rounded-lg px-3 py-2 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading || !url || !backendOnline}
          className="btn-primary touch-row w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Iniciando analise...
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              Iniciar Analise
            </>
          )}
        </button>
      </form>
    </div>
  );
}
