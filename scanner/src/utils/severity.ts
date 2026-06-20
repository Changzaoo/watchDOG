import { Severity, Confidence, ScanSummary, Finding } from '@sentinelscope/shared';

// Pesos base por severidade (seção F.1).
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0.5,
};

// Fatores de modulação por confiança (seção F.2).
const CONFIDENCE_FACTORS: Record<Confidence, number> = {
  high: 1.0,
  medium: 0.7,
  low: 0.4,
};

/**
 * Versão compatível baseada no `summary` (mantém a assinatura usada em
 * backend/src/routes/scans.ts). Como o summary não carrega confiança nem
 * categoria, usamos uma aproximação: confiança "medium" implícita e
 * diminishing returns aplicado por severidade (em vez de por categoria).
 * Os tetos da seção F.3 valem aqui também.
 */
export function calculateScore(summary: ScanSummary): number {
  let penalty = 0;

  const accumulate = (severity: Severity, count: number) => {
    for (let n = 1; n <= count; n++) {
      penalty +=
        SEVERITY_WEIGHTS[severity] * CONFIDENCE_FACTORS.medium * (1 / Math.sqrt(n));
    }
  };

  accumulate('critical', summary.critical);
  accumulate('high', summary.high);
  accumulate('medium', summary.medium);
  accumulate('low', summary.low);
  accumulate('info', summary.info);

  let score = Math.max(0, 100 - penalty);

  // Tetos por severidade aberta (seção F.3).
  if (summary.critical > 0) score = Math.min(score, 49);
  else if (summary.high > 0) score = Math.min(score, 74);

  return Math.round(Math.max(0, Math.min(100, score)));
}

/**
 * Modelo completo da seção F: pondera por severidade × confiança, aplica
 * diminishing returns por categoria (peso × 1/sqrt(n) do N-ésimo achado da
 * mesma categoria) e impõe os tetos por críticas/altas abertas.
 *
 * Considera apenas achados com `status === 'open'`.
 */
export function calculateScoreFromFindings(
  findings: Pick<Finding, 'severity' | 'category' | 'confidence' | 'status'>[],
): number {
  const byCategory = new Map<string, number>();
  let penalty = 0;

  const openFindings = findings.filter(f => f.status === 'open');

  for (const f of openFindings) {
    const n = (byCategory.get(f.category) ?? 0) + 1;
    byCategory.set(f.category, n);

    const weight = SEVERITY_WEIGHTS[f.severity] ?? 0;
    const confidence = CONFIDENCE_FACTORS[f.confidence] ?? CONFIDENCE_FACTORS.medium;

    penalty += weight * confidence * (1 / Math.sqrt(n));
  }

  let score = Math.max(0, 100 - penalty);

  // Tetos por severidade aberta (seção F.3).
  if (openFindings.some(f => f.severity === 'critical')) {
    score = Math.min(score, 49);
  } else if (openFindings.some(f => f.severity === 'high')) {
    score = Math.min(score, 74);
  }

  return Math.round(Math.max(0, Math.min(100, score)));
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
