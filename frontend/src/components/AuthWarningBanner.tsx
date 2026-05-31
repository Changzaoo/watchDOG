import { AlertTriangle } from 'lucide-react';

interface Props {
  checked: boolean;
  onChange: (checked: boolean) => void;
}

export function AuthWarningBanner({ checked, onChange }: Props) {
  return (
    <div className={`rounded-xl border p-4 ${checked ? 'border-green-800/50 bg-green-900/10' : 'border-orange-800/50 bg-orange-900/10'}`}>
      <div className="flex items-start gap-3">
        <AlertTriangle className={`w-5 h-5 mt-0.5 flex-shrink-0 ${checked ? 'text-green-400' : 'text-orange-400'}`} />
        <div className="flex-1">
          <div className="font-semibold text-sm text-orange-300 mb-1">
            Aviso de Uso Autorizado
          </div>
          <p className="text-sm text-gray-400 mb-3">
            Esta ferramenta realiza análise de segurança passiva e defensiva. Ela{' '}
            <strong className="text-gray-300">não executa exploração destrutiva</strong>, mas faz
            requisições HTTP seguras e verifica headers, certificados e caminhos comuns.
          </p>
          <p className="text-sm text-gray-400 mb-3">
            O uso não autorizado de ferramentas de análise de segurança em sistemas de terceiros
            pode constituir violação de leis de crimes cibernéticos. Analise{' '}
            <strong className="text-gray-300">apenas aplicações de sua propriedade</strong> ou
            onde você tenha autorização explícita por escrito do proprietário.
          </p>
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={checked}
              onChange={e => onChange(e.target.checked)}
              className="w-4 h-4 rounded border-orange-600 bg-dark-900 text-violet-500 focus:ring-violet-500"
            />
            <span className="text-sm font-medium text-gray-300">
              Confirmo que sou proprietário desta aplicação ou tenho autorização explícita para testá-la
            </span>
          </label>
        </div>
      </div>
    </div>
  );
}
