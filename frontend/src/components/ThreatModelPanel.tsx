import { AlertTriangle, CheckCircle2, Crosshair, Database, Shield, Users } from 'lucide-react';
import { ThreatModelData } from '@sentinelscope/shared';

interface Props {
  model: ThreatModelData;
}

function ListBlock({
  title,
  icon: Icon,
  items,
  accent,
}: {
  title: string;
  icon: typeof Shield;
  items: string[];
  accent: string;
}) {
  return (
    <div className="card">
      <div className="flex items-center gap-2 text-sm font-semibold text-gray-200 mb-3">
        <Icon className={`w-4 h-4 ${accent}`} />
        {title}
      </div>
      <div className="space-y-2">
        {items.length === 0 ? (
          <div className="text-sm text-gray-500">Sem dados para esta seção.</div>
        ) : (
          items.map(item => (
            <div key={item} className="flex items-start gap-2 text-sm text-gray-400">
              <span className="mt-2 h-1.5 w-1.5 rounded-full bg-dark-700 flex-shrink-0" />
              <span>{item}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export function ThreatModelPanel({ model }: Props) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ListBlock title="Ativos Críticos" icon={Database} items={model.assets} accent="text-cyan-400" />
        <ListBlock title="Perfis de Atacante" icon={Users} items={model.attackers} accent="text-orange-400" />
        <ListBlock title="Superfícies de Ataque" icon={Crosshair} items={model.attackSurfaces} accent="text-red-400" />
        <ListBlock title="Controles Esperados" icon={CheckCircle2} items={model.controls} accent="text-green-400" />
      </div>

      <div className="card">
        <div className="flex items-center gap-2 text-sm font-semibold text-gray-200 mb-3">
          <AlertTriangle className="w-4 h-4 text-yellow-400" />
          Lacunas Prioritárias
        </div>
        {model.gaps.length === 0 ? (
          <div className="text-sm text-gray-500">Nenhuma lacuna crítica ou alta foi derivada deste scan.</div>
        ) : (
          <div className="space-y-3">
            {model.gaps.map(gap => (
              <div key={`${gap.ruleId}-${gap.title}`} className="rounded-lg border border-dark-800 bg-dark-900/60 p-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-mono text-violet-300 bg-violet-900/30 px-2 py-0.5 rounded">
                    {gap.ruleId}
                  </span>
                  <span className="text-sm font-medium text-gray-200">{gap.title}</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3 text-sm">
                  <div>
                    <div className="text-xs text-gray-500 mb-1">Controle quebrado</div>
                    <div className="text-gray-300">{gap.brokenControl}</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-500 mb-1">Risco</div>
                    <div className="text-orange-300">{gap.risk}</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-500 mb-1">Correção</div>
                    <div className="text-green-300">{gap.fix}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
