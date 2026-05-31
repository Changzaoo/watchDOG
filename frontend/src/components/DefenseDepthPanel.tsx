import { AlertTriangle, CheckCircle2, Info, ShieldAlert } from 'lucide-react';
import { DefenseLayerData, DefenseLayerStatus } from '@sentinelscope/shared';
import { cn } from '../lib/utils';

interface Props {
  layers: DefenseLayerData[];
}

const STATUS_META: Record<DefenseLayerStatus, { label: string; className: string; icon: typeof CheckCircle2 }> = {
  healthy: { label: 'Saudável', className: 'text-green-400 bg-green-900/20 border-green-800/40', icon: CheckCircle2 },
  warning: { label: 'Atenção', className: 'text-yellow-400 bg-yellow-900/20 border-yellow-800/40', icon: AlertTriangle },
  critical: { label: 'Crítico', className: 'text-red-400 bg-red-900/20 border-red-800/40', icon: ShieldAlert },
  unknown: { label: 'Sem dados', className: 'text-gray-400 bg-dark-800 border-dark-700', icon: Info },
};

const STATUS_ORDER: Record<DefenseLayerStatus, number> = {
  critical: 0,
  warning: 1,
  unknown: 2,
  healthy: 3,
};

export function DefenseDepthPanel({ layers }: Props) {
  const sorted = [...layers].sort((a, b) => {
    const byStatus = STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
    return byStatus || a.name.localeCompare(b.name);
  });

  const totals = layers.reduce(
    (acc, layer) => {
      acc[layer.status] += 1;
      return acc;
    },
    { healthy: 0, warning: 0, critical: 0, unknown: 0 } as Record<DefenseLayerStatus, number>
  );

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {(Object.keys(STATUS_META) as DefenseLayerStatus[]).map(status => {
          const meta = STATUS_META[status];
          const Icon = meta.icon;
          return (
            <div key={status} className={cn('rounded-lg border p-3 sm:p-4', meta.className)}>
              <div className="flex items-center gap-2 text-xs font-medium">
                <Icon className="w-4 h-4" />
                {meta.label}
              </div>
              <div className="text-2xl font-bold mt-2">{totals[status]}</div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {sorted.map(layer => {
          const meta = STATUS_META[layer.status];
          const Icon = meta.icon;
          return (
            <div key={layer.id} className="rounded-lg border border-dark-800 bg-dark-850 p-3 sm:p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <div className="font-medium text-gray-200">{layer.name}</div>
                  <div className="text-sm text-gray-500 mt-1">{layer.summary}</div>
                </div>
                <span className={cn('text-xs px-2 py-1 rounded-full border flex w-fit items-center gap-1.5 flex-shrink-0', meta.className)}>
                  <Icon className="w-3.5 h-3.5" />
                  {meta.label}
                </span>
              </div>
              <div className="mt-3 text-xs text-gray-500">
                {layer.issuesCount} achado(s) associado(s)
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
