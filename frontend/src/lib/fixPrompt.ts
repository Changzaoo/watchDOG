import { Finding, Scan } from '@sentinelscope/shared';

const severityRank: Record<Finding['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const severityLabel: Record<Finding['severity'], string> = {
  critical: 'Critica',
  high: 'Alta',
  medium: 'Media',
  low: 'Baixa',
  info: 'Informativa',
};

function locationFor(finding: Finding): string {
  if (finding.filePath) {
    return `${finding.filePath}${finding.line ? `:${finding.line}` : ''}`;
  }
  return finding.url || 'Nao informado';
}

function optionalLine(label: string, value?: string | number | null): string {
  if (value === undefined || value === null || value === '') return '';
  return `   - ${label}: ${value}\n`;
}

export function getFixableFindings(findings: Finding[]): Finding[] {
  return findings
    .filter(f => f.status === 'open')
    .sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.ruleId.localeCompare(b.ruleId));
}

export function generateAggregateFixPrompt(scan: Scan, findings: Finding[]): string {
  const fixable = getFixableFindings(findings);
  const selected = fixable.length > 0 ? fixable : findings;

  if (selected.length === 0) {
    return `Voce e um engenheiro de seguranca senior. O scan ${scan.projectName} nao encontrou vulnerabilidades abertas. Revise o relatorio, confirme se nao ha falsos negativos e sugira melhorias preventivas de hardening para ${scan.target}.`;
  }

  const stack = scan.techStack.length > 0
    ? scan.techStack.map(t => `${t.name}${t.version ? ` ${t.version}` : ''}`).join(', ')
    : 'Nao identificada';

  let prompt = '';
  prompt += 'Voce e um engenheiro de seguranca senior. Corrija as vulnerabilidades abaixo de forma defensiva, minimizando mudancas desnecessarias e preservando o comportamento atual da aplicacao.\n\n';
  prompt += 'Contexto do scan:\n';
  prompt += `- Projeto: ${scan.projectName}\n`;
  prompt += `- Alvo: ${scan.target}\n`;
  prompt += `- Tipo de scan: ${scan.type}\n`;
  prompt += `- Score atual: ${scan.score}/100\n`;
  prompt += `- Stack detectada: ${stack}\n\n`;
  prompt += 'Objetivo:\n';
  prompt += '1. Corrigir primeiro os achados criticos e altos, depois medios e baixos.\n';
  prompt += '2. Explicar rapidamente a causa de cada problema antes da correcao.\n';
  prompt += '3. Propor alteracoes concretas em configuracoes, headers, codigo, infraestrutura ou dependencias.\n';
  prompt += '4. Incluir comandos, snippets ou diffs quando isso ajudar a aplicar a correcao.\n';
  prompt += '5. Incluir uma forma objetiva de testar cada correcao.\n';
  prompt += '6. Nao remover funcionalidades sem justificar o impacto.\n\n';
  prompt += `Achados para corrigir (${selected.length}):\n\n`;

  selected.forEach((finding, index) => {
    prompt += `${index + 1}. [${severityLabel[finding.severity]}] ${finding.title}\n`;
    prompt += `   - Regra: ${finding.ruleId}\n`;
    prompt += `   - Categoria: ${finding.category}\n`;
    prompt += `   - Local: ${locationFor(finding)}\n`;
    prompt += optionalLine('Ocorrencias', finding.occurrences > 1 ? finding.occurrences : undefined);
    prompt += `   - Descricao: ${finding.description}\n`;
    prompt += `   - Impacto: ${finding.impact}\n`;
    prompt += optionalLine('Evidencia', finding.evidenceMasked);
    prompt += `   - Correcao esperada: ${finding.remediation}\n`;
    prompt += optionalLine('Exemplo seguro', finding.safeExample);
    prompt += optionalLine('Teste sugerido', finding.testSuggestion);
    prompt += optionalLine('Referencia', finding.reference);
    if (finding.fixPrompt) {
      prompt += `   - Prompt especifico existente: ${finding.fixPrompt}\n`;
    }
    prompt += '\n';
  });

  prompt += 'Formato da resposta desejado:\n';
  prompt += '- Plano de correcao por prioridade.\n';
  prompt += '- Alteracoes recomendadas com arquivos/configuracoes afetadas.\n';
  prompt += '- Snippets ou diffs prontos para aplicar.\n';
  prompt += '- Comandos de validacao e testes.\n';
  prompt += '- Checklist final marcando cada achado como corrigido.\n';

  return prompt;
}
