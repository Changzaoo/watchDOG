import { HelpCircle, Book, Shield, AlertTriangle, Code2 } from 'lucide-react';

const SECTIONS = [
  {
    icon: Shield,
    title: 'Como interpretar o score',
    content: [
      { range: '90-100', label: 'Excelente', color: 'text-green-400', desc: 'Projeto muito bem configurado. Continue mantendo boas práticas.' },
      { range: '75-89', label: 'Bom', color: 'text-blue-400', desc: 'Boa configuração. Corrija os achados de alta severidade.' },
      { range: '50-74', label: 'Atenção', color: 'text-yellow-400', desc: 'Vários problemas encontrados. Priorize críticos e altos.' },
      { range: '25-49', label: 'Crítico', color: 'text-orange-400', desc: 'Sérios problemas de segurança. Corrija imediatamente.' },
      { range: '0-24', label: 'Muito Crítico', color: 'text-red-400', desc: 'Aplicação altamente vulnerável. Não exponha em produção.' },
    ],
  },
  {
    icon: Book,
    title: 'Referências de Segurança',
    items: [
      'OWASP Top 10 2021 - owasp.org/www-project-top-ten/',
      'OWASP API Security Top 10 2023',
      'CIS Controls v8',
      'NIST Cybersecurity Framework',
      'LGPD - Lei Geral de Proteção de Dados',
      'SWC Registry (Smart Contracts)',
    ],
  },
];

const FAQS = [
  {
    q: 'O watchDOG pode derrubar minha aplicação?',
    a: 'Não. A ferramenta realiza apenas análise passiva e defensiva. Ela faz requisições HTTP simples e verifica respostas. Não executa DoS, brute force ou exploração.',
  },
  {
    q: 'Os dados do scan são enviados para algum servidor?',
    a: 'Não. Todo processamento é local. O backend roda na porta 3001 do seu computador e não faz conexões externas.',
  },
  {
    q: 'Posso analisar o site de outra pessoa?',
    a: 'Não. Use apenas em suas próprias aplicações ou onde você tem autorização explícita por escrito. O uso não autorizado pode violar leis de crimes cibernéticos.',
  },
  {
    q: 'Como adicionar novas regras de segurança?',
    a: 'Abra o arquivo scanner/src/rules/<categoria>.rules.ts e adicione um novo objeto seguindo o padrão FileRule. Depois execute npm run build no diretório scanner.',
  },
  {
    q: 'O score chegou a 0 mas meu projeto é seguro?',
    a: 'Pode haver falsos positivos. Marque os achados incorretos como "Falso Positivo" para que não afetem o score futuro.',
  },
];

export function Help() {
  return (
    <div className="max-w-3xl space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <HelpCircle className="w-7 h-7 text-violet-400" />
          Ajuda e Boas Práticas
        </h1>
        <p className="text-gray-500 text-sm mt-1">Guia de uso do watchDOG</p>
      </div>

      <div className="card border-orange-900/30 bg-orange-900/5">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-orange-300 mb-1">Uso Responsável</p>
            <p className="text-gray-400">
              O watchDOG é uma ferramenta de <strong className="text-gray-300">auditoria defensiva</strong> criada para ajudar desenvolvedores a identificar vulnerabilidades em seus próprios projetos. Use apenas em projetos de sua propriedade ou com autorização explícita por escrito.
            </p>
          </div>
        </div>
      </div>

      {/* Score interpretation */}
      <div className="card">
        <div className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Shield className="w-4 h-4 text-violet-400" />
          Como Interpretar o Score
        </div>
        <div className="space-y-2">
          {SECTIONS[0].content?.map(({ range, label, color, desc }) => (
            <div key={range} className="flex items-start gap-3 py-2 border-b border-dark-800 last:border-0">
              <div className="w-16 flex-shrink-0">
                <span className={`text-sm font-bold ${color}`}>{range}</span>
              </div>
              <div>
                <div className={`text-sm font-medium ${color}`}>{label}</div>
                <div className="text-xs text-gray-500 mt-0.5">{desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* FAQ */}
      <div className="card">
        <div className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <HelpCircle className="w-4 h-4 text-cyan-400" />
          Perguntas Frequentes
        </div>
        <div className="space-y-4">
          {FAQS.map(({ q, a }) => (
            <div key={q} className="border-b border-dark-800 pb-4 last:border-0 last:pb-0">
              <div className="text-sm font-medium text-gray-200 mb-1.5">{q}</div>
              <div className="text-sm text-gray-400">{a}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Adding rules */}
      <div className="card">
        <div className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Code2 className="w-4 h-4 text-emerald-400" />
          Como Adicionar Novas Regras
        </div>
        <pre className="font-mono text-xs bg-dark-900 rounded-lg p-4 text-green-400 overflow-x-auto">
{`// scanner/src/rules/minha-categoria.rules.ts

import { FileRule } from '../types';

export const minhasRegras: FileRule[] = [
  {
    id: 'CUSTOM_001',
    title: 'Título da regra',
    category: 'Minha Categoria',
    severity: 'high', // critical|high|medium|low|info
    description: 'O que esta regra detecta',
    impact: 'Qual o impacto desta vulnerabilidade',
    remediation: 'Como corrigir',
    safeExample: '// Código seguro aqui',
    reference: 'OWASP A01:2021',
    patterns: [/padrão_regex_aqui/],
    fileExtensions: ['.ts', '.js'],
  },
];`}
        </pre>
        <p className="text-xs text-gray-500 mt-3">
          Depois importe e adicione em <code className="font-mono text-violet-400">scanner/src/analyzers/localProjectAnalyzer.ts</code>
        </p>
      </div>

      {/* References */}
      <div className="card">
        <div className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <Book className="w-4 h-4 text-blue-400" />
          Referências de Segurança
        </div>
        <ul className="space-y-1.5">
          {SECTIONS[1].items?.map(item => (
            <li key={item} className="text-sm text-gray-400 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-violet-500 flex-shrink-0" />
              {item}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
