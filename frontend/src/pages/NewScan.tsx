import { useNavigate } from 'react-router-dom';
import { FolderOpen, Globe, ArrowRight, Lock } from 'lucide-react';
import { useAppStore } from '../store/useAppStore';

export function NewScan() {
  const navigate = useNavigate();
  const { backendOnline, localScansEnabled } = useAppStore();
  const localScanDisabled = backendOnline && !localScansEnabled;

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Novo Scan de Segurança</h1>
        <p className="text-gray-500 text-sm mt-1">
          Escolha o tipo de análise que deseja realizar
        </p>
      </div>

      <div className="space-y-4">
        <button
          onClick={() => {
            if (!localScanDisabled) navigate('/scan/local');
          }}
          disabled={localScanDisabled}
          className={`w-full card transition-all group text-left ${
            localScanDisabled
              ? 'opacity-70 cursor-not-allowed'
              : 'hover:border-violet-700/70 cursor-pointer'
          }`}
        >
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-violet-900/40 border border-violet-800/50 flex items-center justify-center flex-shrink-0">
              <FolderOpen className="w-6 h-6 text-violet-400" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <div className="font-semibold text-gray-200 group-hover:text-white transition-colors">
                  Analisar Projeto Local
                </div>
                {localScanDisabled ? (
                  <Lock className="w-4 h-4 text-gray-600" />
                ) : (
                  <ArrowRight className="w-4 h-4 text-gray-600 group-hover:text-violet-400 transition-colors" />
                )}
              </div>
              <p className="text-sm text-gray-500 mt-1">
                {localScanDisabled
                  ? 'Disponível apenas ao rodar o backend localmente na sua máquina.'
                  : 'Análise estática completa de código-fonte, configurações, dependências, secrets, Docker, CI/CD e muito mais.'}
              </p>
              <div className="flex flex-wrap gap-2 mt-3">
                {['Código', 'Dependências', 'Secrets', 'Docker', 'CI/CD', 'Web3'].map(t => (
                  <span key={t} className="text-xs px-2 py-0.5 bg-dark-800 rounded text-gray-400">{t}</span>
                ))}
              </div>
            </div>
          </div>
        </button>

        <button
          onClick={() => navigate('/scan/url')}
          className="w-full card hover:border-cyan-700/70 cursor-pointer transition-all group text-left"
        >
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-cyan-900/40 border border-cyan-800/50 flex items-center justify-center flex-shrink-0">
              <Globe className="w-6 h-6 text-cyan-400" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <div className="font-semibold text-gray-200 group-hover:text-white transition-colors">
                  Analisar URL Online
                </div>
                <ArrowRight className="w-4 h-4 text-gray-600 group-hover:text-cyan-400 transition-colors" />
              </div>
              <p className="text-sm text-gray-500 mt-1">
                Análise passiva de uma aplicação online: headers de segurança, CORS, HTTPS, certificado TLS, caminhos expostos.
              </p>
              <div className="flex flex-wrap gap-2 mt-3">
                {['HTTPS', 'Headers', 'CORS', 'TLS', 'APIs', 'Paths'].map(t => (
                  <span key={t} className="text-xs px-2 py-0.5 bg-dark-800 rounded text-gray-400">{t}</span>
                ))}
              </div>
            </div>
          </div>
        </button>
      </div>

      <div className="card border-yellow-900/30 bg-yellow-900/5 text-sm text-yellow-300/70">
        <strong className="text-yellow-400">Importante:</strong> Esta ferramenta realiza análise
        defensiva. Analise apenas projetos de sua propriedade ou com autorização explícita.
        Não executa exploração destrutiva, brute force ou ataques.
      </div>
    </div>
  );
}
