import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Globe, Play, AlertCircle, ArrowLeft } from 'lucide-react';
import { api } from '../lib/api';
import { AuthWarningBanner } from '../components/AuthWarningBanner';
import { useAppStore } from '../store/useAppStore';

export function ScanUrl() {
  const [url, setUrl] = useState('');
  const [depth, setDepth] = useState<'quick' | 'normal' | 'deep'>('normal');
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { backendOnline } = useAppStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!backendOnline) { setError('Backend offline. Tente novamente em alguns segundos.'); return; }
    if (!authorized) { setError('Você deve confirmar a autorização antes de continuar'); return; }
    if (!url.trim()) { setError('Informe a URL'); return; }

    let finalUrl = url.trim();
    if (!finalUrl.startsWith('http')) finalUrl = 'https://' + finalUrl;

    try {
      new URL(finalUrl);
    } catch {
      setError('URL inválida');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const { scanId } = await api.startUrlScan(finalUrl, { depth, authorized });
      navigate(`/scans/${scanId}`);
    } catch (err: any) {
      setError(err.message || 'Erro ao iniciar scan');
    } finally {
      setLoading(false);
    }
  };

  const DEPTHS = [
    { value: 'quick', label: 'Rápida', desc: '~30s - Headers e TLS apenas' },
    { value: 'normal', label: 'Normal', desc: '~1-2min - Análise completa padrão' },
    { value: 'deep', label: 'Profunda', desc: '~3-5min - Verifica mais caminhos' },
  ];

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate(-1)} className="btn-secondary p-2">
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyan-400" />
            Análise de URL Online
          </h1>
          <p className="text-gray-500 text-sm">Análise passiva e defensiva de aplicação online</p>
        </div>
      </div>

      <AuthWarningBanner checked={authorized} onChange={setAuthorized} />

      <div className="card space-y-2">
        <h3 className="text-sm font-semibold text-gray-300">O que será verificado (de forma passiva):</h3>
        <div className="grid grid-cols-2 gap-1.5 text-xs text-gray-400">
          {[
            '✓ HTTPS e redirect HTTP→HTTPS',
            '✓ Certificado TLS e expiração',
            '✓ Headers de segurança',
            '✓ Content-Security-Policy',
            '✓ HSTS, X-Frame-Options',
            '✓ CORS e credenciais',
            '✓ Caminhos expostos comuns',
            '✓ Swagger/GraphQL público',
            '✓ Arquivo .env exposto',
            '✓ Endpoints de debug',
            '✓ Tecnologias expostas',
            '✓ Server/X-Powered-By',
          ].map(item => <div key={item}>{item}</div>)}
        </div>
        <div className="text-xs text-red-400/70 pt-2 border-t border-dark-800">
          ❌ Sem brute force &nbsp; ❌ Sem fuzzing &nbsp; ❌ Sem payloads maliciosos &nbsp; ❌ Sem exploração
        </div>
      </div>

      <form onSubmit={handleSubmit} className="card space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">
            URL da Aplicação *
          </label>
          <input
            className="input"
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://minhaaplicacao.com"
            disabled={loading}
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Profundidade da Análise
          </label>
          <div className="grid grid-cols-3 gap-2">
            {DEPTHS.map(d => (
              <button
                key={d.value}
                type="button"
                onClick={() => setDepth(d.value as any)}
                className={`rounded-xl border p-3 text-left transition-all ${
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
          disabled={loading || !url || !authorized || !backendOnline}
          className="btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Iniciando análise...
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              Iniciar Análise
            </>
          )}
        </button>

        {!authorized && (
          <p className="text-xs text-orange-400 text-center">
            Confirme a autorização acima para continuar
          </p>
        )}
      </form>
    </div>
  );
}
