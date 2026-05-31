import { Settings as SettingsIcon, Server, Shield, Info } from 'lucide-react';
import { useAppStore } from '../store/useAppStore';

export function Settings() {
  const { backendOnline } = useAppStore();

  return (
    <div className="max-w-2xl space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <SettingsIcon className="w-7 h-7 text-violet-400" />
          Configurações
        </h1>
        <p className="text-gray-500 text-sm mt-1">Configurações da aplicação watchDOG</p>
      </div>

      <div className="card space-y-4">
        <h2 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
          <Server className="w-4 h-4 text-cyan-400" />
          Backend
        </h2>
        <div className="flex items-center justify-between py-2 border-b border-dark-800">
          <div>
            <div className="text-sm text-gray-300">Status do servidor</div>
            <div className="text-xs text-gray-600">http://localhost:3001</div>
          </div>
          <span className={`text-xs px-2 py-1 rounded-full ${backendOnline ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>
            {backendOnline ? 'Online' : 'Offline'}
          </span>
        </div>
        <div className="flex items-center justify-between py-2">
          <div>
            <div className="text-sm text-gray-300">Banco de dados</div>
            <div className="text-xs text-gray-600">SQLite local (backend/sentinelscope.db)</div>
          </div>
          <span className="text-xs text-gray-500">SQLite</span>
        </div>
      </div>

      <div className="card space-y-3">
        <h2 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
          <Shield className="w-4 h-4 text-violet-400" />
          Segurança da Aplicação
        </h2>
        {[
          { label: 'Dados enviados externamente', value: 'Nunca', ok: true },
          { label: 'Armazenamento de secrets', value: 'Local apenas', ok: true },
          { label: 'Secrets nos logs', value: 'Mascarados', ok: true },
          { label: 'Conexões externas aceitas', value: 'Nenhuma por padrão', ok: true },
          { label: 'Rate limiting', value: 'Ativo (60 req/min)', ok: true },
        ].map(({ label, value, ok }) => (
          <div key={label} className="flex items-center justify-between py-1.5 border-b border-dark-800 last:border-0">
            <div className="text-sm text-gray-400">{label}</div>
            <div className={`text-xs font-medium ${ok ? 'text-green-400' : 'text-red-400'}`}>{value}</div>
          </div>
        ))}
      </div>

      <div className="card border-blue-900/30 bg-blue-900/5">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-gray-400">
            <p className="font-medium text-blue-300 mb-1">Privacidade e Uso Responsável</p>
            <p>O watchDOG funciona 100% localmente. Nenhum dado de scan, código ou resultado é enviado para servidores externos. Toda análise é processada no seu próprio computador.</p>
            <p className="mt-2">Use apenas em projetos de sua propriedade ou com autorização explícita do proprietário.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
