import { TechStack } from '@sentinelscope/shared';
import { Code2, Database, Server, Shield, Cpu, Globe } from 'lucide-react';

interface Props {
  techStack: TechStack[];
}

const CATEGORY_ICONS: Record<string, any> = {
  frontend: Globe,
  backend: Server,
  database: Database,
  devops: Cpu,
  web3: Shield,
  other: Code2,
};

const CATEGORY_LABELS: Record<string, string> = {
  frontend: 'Frontend',
  backend: 'Backend',
  database: 'Banco de Dados',
  devops: 'DevOps',
  web3: 'Web3',
  other: 'Outros',
};

export function TechStackDetected({ techStack }: Props) {
  if (techStack.length === 0) {
    return (
      <div className="text-gray-600 text-sm py-2">Stack não detectada</div>
    );
  }

  const grouped = techStack.reduce((acc, t) => {
    const cat = t.category || 'other';
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(t);
    return acc;
  }, {} as Record<string, TechStack[]>);

  return (
    <div className="space-y-3">
      {Object.entries(grouped).map(([cat, techs]) => {
        const Icon = CATEGORY_ICONS[cat] || Code2;
        return (
          <div key={cat}>
            <div className="flex items-center gap-2 text-xs text-gray-500 mb-1.5">
              <Icon className="w-3 h-3" />
              {CATEGORY_LABELS[cat] || cat}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {techs.map((t, i) => (
                <span
                  key={i}
                  className="inline-flex items-center gap-1 px-2 py-0.5 bg-dark-800 border border-dark-800 rounded-md text-xs text-gray-300"
                >
                  {t.name}
                  {t.version && <span className="text-gray-600">{t.version}</span>}
                </span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
