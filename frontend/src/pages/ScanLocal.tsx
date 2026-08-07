import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FolderOpen, Play, AlertCircle, ArrowLeft } from 'lucide-react';
import { api } from '../lib/api';
import { useAppStore } from '../store/useAppStore';

export function ScanLocal() {
  const [projectPath, setProjectPath] = useState('');
  const [projectName, setProjectName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { backendOnline, localScansEnabled } = useAppStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectPath.trim()) { setError('Informe o caminho do projeto'); return; }
    if (!backendOnline) { setError('Backend offline. Execute: npm run dev:backend'); return; }
    if (!localScansEnabled) {
      setError('Scan local esta disponivel apenas com o backend rodando na sua maquina.');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const { scanId } = await api.startLocalScan(projectPath.trim(), projectName.trim() || undefined);
      navigate(`/scans/${scanId}`);
    } catch (err: any) {
      setError(err.message || 'Erro ao iniciar scan');
    } finally {
      setLoading(false);
    }
  };

  const EXAMPLES = [
    'C:\\Users\\usuario\\meu-projeto',
    'C:\\projetos\\minha-api',
    '/home/user/projeto',
  ];

  return (
    <div className="mx-auto max-w-2xl space-y-5 sm:space-y-6 animate-fade-in">
      <div className="flex items-start gap-3">
        <button onClick={() => navigate(-1)} className="btn-secondary flex-shrink-0 p-2">
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="min-w-0">
          <h1 className="mobile-section-title flex items-center gap-2">
            <FolderOpen className="h-5 w-5 flex-shrink-0 text-violet-400" />
            Análise de Projeto Local
          </h1>
          <p className="text-gray-500 text-sm">Informe o caminho do projeto para análise completa</p>
        </div>
      </div>

      <div className="card space-y-2">
        <h3 className="text-sm font-semibold text-gray-300">O que será analisado:</h3>
        <div className="grid grid-cols-1 gap-1.5 text-xs text-gray-400 sm:grid-cols-2">
          {[
            '✓ Secrets e credenciais expostas',
            '✓ Dependências vulneráveis',
            '✓ Configuração CORS e headers',
            '✓ Padrões de autenticação',
            '✓ Padrões de autorização (IDOR)',
            '✓ Configuração de upload',
            '✓ Docker e CI/CD',
            '✓ Código Web3 (Solidity)',
            '✓ Logs com dados sensíveis',
            '✓ Privacidade e LGPD',
            '✓ Injeção SQL / Command',
            '✓ Configuração de banco de dados',
          ].map(item => <div key={item}>{item}</div>)}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="card space-y-4">
        {backendOnline && !localScansEnabled && (
          <div className="flex items-start gap-2 text-yellow-300 bg-yellow-900/10 border border-yellow-800/40 rounded-lg px-3 py-2 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>Este deploy hospedado nao acessa pastas do seu computador. Para scan local, rode o backend localmente.</span>
          </div>
        )}

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">
            Caminho do Projeto *
          </label>
          <input
            className="input"
            value={projectPath}
            onChange={e => setProjectPath(e.target.value)}
            placeholder="Ex: C:\Users\usuario\meu-projeto"
            disabled={loading}
          />
          <div className="mt-2 space-y-1">
            <p className="text-xs text-gray-600">Exemplos:</p>
            {EXAMPLES.map(ex => (
              <button
                key={ex}
                type="button"
                onClick={() => setProjectPath(ex)}
                className="block max-w-full truncate text-left font-mono text-xs text-violet-500 transition-colors hover:text-violet-400"
              >
                {ex}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">
            Nome do Projeto (opcional)
          </label>
          <input
            className="input"
            value={projectName}
            onChange={e => setProjectName(e.target.value)}
            placeholder="Deixe em branco para usar o nome da pasta"
            disabled={loading}
          />
        </div>

        {error && (
          <div className="flex items-center gap-2 text-red-400 bg-red-900/20 border border-red-800/50 rounded-lg px-3 py-2 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading || !projectPath || (backendOnline && !localScansEnabled)}
          className="btn-primary touch-row w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
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
      </form>

      <div className="text-xs text-gray-600 text-center">
        node_modules, .git, dist, build e arquivos &gt;500KB são automaticamente ignorados
      </div>
    </div>
  );
}
