import { Finding, generateAggregateFixPrompt, Scan } from '@sentinelscope/shared';
import { scoreLabel } from '../utils/severity';

export function generateMarkdownReport(scan: Scan, findings: Finding[]): string {
  const critical = findings.filter(f => f.severity === 'critical');
  const high = findings.filter(f => f.severity === 'high');
  const medium = findings.filter(f => f.severity === 'medium');
  const low = findings.filter(f => f.severity === 'low');
  const info = findings.filter(f => f.severity === 'info');

  const date = new Date(scan.startedAt).toLocaleDateString('pt-BR');

  let md = `# Relatorio de Seguranca - watchDOG\n\n`;
  md += `**Projeto:** ${scan.projectName}\n`;
  md += `**Alvo:** ${scan.target}\n`;
  md += `**Data:** ${date}\n`;
  md += `**Score:** ${scan.score}/100 (${scoreLabel(scan.score)})\n`;
  md += `**Duracao:** ${scan.durationMs ? Math.round(scan.durationMs / 1000) + 's' : 'N/A'}\n\n`;

  md += `## Resumo Executivo\n\n`;
  md += `A analise identificou **${findings.length} achados** de seguranca no projeto.\n\n`;
  md += `| Severidade | Quantidade |\n|---|---|\n`;
  md += `| Critica | ${critical.length} |\n`;
  md += `| Alta | ${high.length} |\n`;
  md += `| Media | ${medium.length} |\n`;
  md += `| Baixa | ${low.length} |\n`;
  md += `| Informativa | ${info.length} |\n\n`;

  md += `## Stack Tecnologico\n\n`;
  if (scan.techStack.length > 0) {
    md += scan.techStack.map(t => `- ${t.name}${t.version ? ` (${t.version})` : ''}`).join('\n') + '\n\n';
  } else {
    md += 'Stack nao identificada\n\n';
  }

  const renderSection = (title: string, items: Finding[]) => {
    if (items.length === 0) return;
    md += `## ${title} (${items.length})\n\n`;
    for (const f of items) {
      md += `### ${f.title}\n\n`;
      md += `- **ID:** ${f.ruleId}\n`;
      md += `- **Categoria:** ${f.category}\n`;
      md += `- **Confianca:** ${f.confidence || 'medium'}\n`;
      md += `- **Ocorrencias:** ${f.occurrences || 1}\n`;
      if (f.filePath) md += `- **Arquivo:** \`${f.filePath}\`${f.line ? `:${f.line}` : ''}\n`;
      if (f.url) md += `- **URL:** ${f.url}\n`;
      if (f.evidenceMasked) md += `- **Evidencia:** \`${f.evidenceMasked}\`\n`;
      md += `\n**Descricao:** ${f.description}\n\n`;
      md += `**Impacto:** ${f.impact}\n\n`;
      if (f.attackScenarioDefensive) md += `**Cenario defensivo:** ${f.attackScenarioDefensive}\n\n`;
      md += `**Correcao:** ${f.remediation}\n\n`;
      if (f.safeExample) md += `**Exemplo seguro:**\n\`\`\`\n${f.safeExample}\n\`\`\`\n\n`;
      if (f.testSuggestion) md += `**Teste sugerido:** ${f.testSuggestion}\n\n`;
      if (f.fixPrompt) md += `**Prompt de correcao:**\n\`\`\`\n${f.fixPrompt}\n\`\`\`\n\n`;
      if (f.reference) md += `**Referencia:** ${f.reference}\n\n`;
      if (f.userNote) md += `**Nota do usuario:** ${f.userNote}\n\n`;
      md += '---\n\n';
    }
  };

  renderSection('Achados Criticos', critical);
  renderSection('Achados de Alta Severidade', high);
  renderSection('Achados de Media Severidade', medium);
  renderSection('Achados de Baixa Severidade', low);
  renderSection('Achados Informativos', info);

  md += `## Checklist de Correcao\n\n`;
  for (const f of [...critical, ...high, ...medium]) {
    md += `- [ ] [${f.ruleId}] ${f.title}\n`;
  }

  if (findings.length > 0) {
    md += `\n## Prompt para Corrigir Vulnerabilidades\n\n`;
    md += `\`\`\`\n${generateAggregateFixPrompt(scan, findings)}\n\`\`\`\n`;
  }

  md += `\n---\n*Relatorio gerado por watchDOG - Ferramenta de Auditoria de Seguranca Defensiva*\n`;
  md += `*Analise apenas aplicacoes de sua propriedade ou com autorizacao explicita.*\n`;

  return md;
}

export function generateJsonReport(scan: Scan, findings: Finding[]) {
  return {
    metadata: {
      tool: 'watchDOG',
      version: '1.0.0',
      generatedAt: new Date().toISOString(),
    },
    scan: {
      id: scan.id,
      projectName: scan.projectName,
      target: scan.target,
      type: scan.type,
      score: scan.score,
      scoreLabel: scoreLabel(scan.score),
      startedAt: scan.startedAt,
      finishedAt: scan.finishedAt,
      durationMs: scan.durationMs,
      techStack: scan.techStack,
      summary: scan.summary,
    },
    remediationPrompt: generateAggregateFixPrompt(scan, findings),
    findings: findings.map(f => ({
      id: f.ruleId,
      title: f.title,
      severity: f.severity,
      category: f.category,
      confidence: f.confidence,
      occurrences: f.occurrences,
      location: f.filePath ? `${f.filePath}${f.line ? ':' + f.line : ''}` : f.url,
      evidence: f.evidenceMasked,
      description: f.description,
      impact: f.impact,
      attackScenarioDefensive: f.attackScenarioDefensive,
      remediation: f.remediation,
      safeExample: f.safeExample,
      fixPrompt: f.fixPrompt,
      testSuggestion: f.testSuggestion,
      reference: f.reference,
      status: f.status,
      userNote: f.userNote,
    })),
  };
}
