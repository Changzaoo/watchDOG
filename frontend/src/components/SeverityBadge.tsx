import { Severity } from '@sentinelscope/shared';
import { cn } from '../lib/utils';

interface Props {
  severity: Severity;
  size?: 'sm' | 'md';
}

const LABELS: Record<Severity, string> = {
  critical: 'Crítica',
  high: 'Alta',
  medium: 'Média',
  low: 'Baixa',
  info: 'Info',
};

const CLASSES: Record<Severity, string> = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
  info: 'severity-info',
};

export function SeverityBadge({ severity, size = 'sm' }: Props) {
  return (
    <span className={cn(
      'inline-flex items-center font-medium rounded-md border',
      CLASSES[severity],
      size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'
    )}>
      {LABELS[severity]}
    </span>
  );
}
