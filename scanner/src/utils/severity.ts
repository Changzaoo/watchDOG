import { Severity, ScanSummary } from '@sentinelscope/shared';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

export function calculateScore(summary: ScanSummary): number {
  const penalty =
    summary.critical * SEVERITY_WEIGHTS.critical +
    summary.high * SEVERITY_WEIGHTS.high +
    summary.medium * SEVERITY_WEIGHTS.medium +
    summary.low * SEVERITY_WEIGHTS.low;

  const score = Math.max(0, 100 - penalty);
  return Math.round(score);
}

export function scoreLabel(score: number): string {
  if (score >= 90) return 'Excelente';
  if (score >= 75) return 'Bom';
  if (score >= 50) return 'Atenção';
  if (score >= 25) return 'Crítico';
  return 'Muito Crítico';
}

export function scoreColor(score: number): string {
  if (score >= 90) return 'green';
  if (score >= 75) return 'blue';
  if (score >= 50) return 'yellow';
  if (score >= 25) return 'orange';
  return 'red';
}

export function severityOrder(s: Severity): number {
  const order: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  return order[s];
}

export function buildSummary(severities: Severity[]): ScanSummary {
  return {
    total: severities.length,
    critical: severities.filter(s => s === 'critical').length,
    high: severities.filter(s => s === 'high').length,
    medium: severities.filter(s => s === 'medium').length,
    low: severities.filter(s => s === 'low').length,
    info: severities.filter(s => s === 'info').length,
  };
}
