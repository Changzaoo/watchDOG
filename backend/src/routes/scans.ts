import { Router, Request, Response } from 'express';
import { z } from 'zod';
import path from 'path';
import fs from 'fs';
import { prisma } from '../db/client';
import {
  analyzeLocalProject, analyzeUrl, calculateScore, buildSummary,
  generateMarkdownReport, generateJsonReport,
  generateThreatModel, generateDefenseDepth,
  validateScanUrlWithDns, validateLocalPath
} from '@sentinelscope/scanner';
import { Scan, Finding, ScanSummary } from '@sentinelscope/shared';
import { scanEventEmitters } from './events';

export const scansRouter = Router();

const localScanSchema = z.object({
  path: z.string().min(1),
  projectName: z.string().optional(),
});

const urlScanSchema = z.object({
  url: z.string().url(),
  apiUrl: z.string().url().optional(),
  depth: z.enum(['quick', 'normal', 'deep']).default('normal'),
  authorized: z.boolean().refine(v => v === true, { message: 'Você deve confirmar autorização' }),
});

async function applyRuleConfigs<T extends { ruleId: string; severity: string }>(findings: T[]): Promise<T[]> {
  const configs = await prisma.ruleConfig.findMany();
  if (configs.length === 0) return findings;

  const byRuleId = new Map(configs.map(c => [c.ruleId, c]));
  return findings
    .filter(f => byRuleId.get(f.ruleId)?.enabled !== false)
    .map(f => {
      const override = byRuleId.get(f.ruleId)?.severityOverride;
      return override ? { ...f, severity: override } : f;
    });
}

// POST /api/scans/local
scansRouter.post('/local', async (req: Request, res: Response) => {
  const parsed = localScanSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { path: projectPath, projectName } = parsed.data;

  // Security: validate path (block traversal + system dirs)
  const pathCheck = validateLocalPath(projectPath);
  if (!pathCheck.valid) {
    return res.status(400).json({ error: pathCheck.reason });
  }

  if (!fs.existsSync(projectPath)) {
    return res.status(400).json({ error: 'Caminho não encontrado' });
  }

  // Must be a directory
  const stat = fs.statSync(projectPath);
  if (!stat.isDirectory()) {
    return res.status(400).json({ error: 'O caminho deve ser um diretório' });
  }

  const name = projectName || path.basename(projectPath);
  const scan = await prisma.scan.create({
    data: {
      type: 'local',
      target: projectPath,
      projectName: name,
      status: 'running',
      techStack: '[]',
      summary: JSON.stringify({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }),
    },
  });

  res.json({ scanId: scan.id });

  // Run scan asynchronously
  runLocalScan(scan.id, projectPath).catch(console.error);
});

// POST /api/scans/url
scansRouter.post('/url', async (req: Request, res: Response) => {
  const parsed = urlScanSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { url, depth } = parsed.data;

  // Security: validate URL (block SSRF, private IPs, localhost, cloud metadata)
  const urlCheck = await validateScanUrlWithDns(url);
  if (!urlCheck.valid) {
    return res.status(400).json({ error: urlCheck.reason });
  }
  const safeUrl = urlCheck.normalizedUrl!;

  const scan = await prisma.scan.create({
    data: {
      type: 'url',
      target: safeUrl,
      projectName: new URL(safeUrl).hostname,
      status: 'running',
      techStack: '[]',
      summary: JSON.stringify({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }),
    },
  });

  res.json({ scanId: scan.id });

  runUrlScan(scan.id, safeUrl, depth).catch(console.error);
});

// GET /api/scans
scansRouter.get('/', async (_req: Request, res: Response) => {
  const scans = await prisma.scan.findMany({
    orderBy: { createdAt: 'desc' },
    take: 50,
  });

  const result = scans.map(s => ({
    ...s,
    techStack: JSON.parse(s.techStack),
    summary: JSON.parse(s.summary),
  }));

  res.json(result);
});

// GET /api/scans/:id
scansRouter.get('/:id', async (req: Request, res: Response) => {
  const scan = await prisma.scan.findUnique({
    where: { id: req.params.id },
    include: { findings: true, logs: { orderBy: { createdAt: 'asc' }, take: 500 } },
  });

  if (!scan) return res.status(404).json({ error: 'Scan não encontrado' });

  res.json({
    scan: { ...scan, techStack: JSON.parse(scan.techStack), summary: JSON.parse(scan.summary) },
    findings: scan.findings,
    logs: scan.logs,
  });
});

// GET /api/scans/:id/findings
scansRouter.get('/:id/findings', async (req: Request, res: Response) => {
  const findings = await prisma.finding.findMany({
    where: { scanId: req.params.id },
    orderBy: [{ severity: 'asc' }, { createdAt: 'asc' }],
  });
  res.json(findings);
});

// GET /api/scans/:id/threat-model
scansRouter.get('/:id/threat-model', async (req: Request, res: Response) => {
  const tm = await prisma.threatModel.findUnique({ where: { scanId: req.params.id } });
  if (!tm) return res.status(404).json({ error: 'Threat model não encontrado — execute o scan primeiro' });
  res.json({
    ...tm,
    assets: JSON.parse(tm.assets),
    attackers: JSON.parse(tm.attackers),
    attackSurfaces: JSON.parse(tm.attackSurfaces),
    controls: JSON.parse(tm.controls),
    gaps: JSON.parse(tm.gaps),
  });
});

// GET /api/scans/:id/defense-depth
scansRouter.get('/:id/defense-depth', async (req: Request, res: Response) => {
  const layers = await prisma.defenseLayer.findMany({
    where: { scanId: req.params.id },
    orderBy: { name: 'asc' },
  });
  res.json(layers);
});

// GET /api/scans/:id/export/checklist
scansRouter.get('/:id/export/checklist', async (req: Request, res: Response) => {
  const scan = await prisma.scan.findUnique({
    where: { id: req.params.id },
    include: { findings: { orderBy: [{ severity: 'asc' }] } },
  });
  if (!scan) return res.status(404).json({ error: 'Scan não encontrado' });

  const lines = [
    `# Checklist de Correção — ${scan.projectName}`,
    `Data: ${new Date(scan.startedAt).toLocaleDateString('pt-BR')}`,
    `Score: ${scan.score}/100`,
    '',
    '## Críticos (corrigir imediatamente)',
    ...scan.findings.filter(f => f.severity === 'critical').map(f => `- [ ] [${f.ruleId}] ${f.title}`),
    '',
    '## Altos',
    ...scan.findings.filter(f => f.severity === 'high').map(f => `- [ ] [${f.ruleId}] ${f.title}`),
    '',
    '## Médios',
    ...scan.findings.filter(f => f.severity === 'medium').map(f => `- [ ] [${f.ruleId}] ${f.title}`),
    '',
    '## Baixos',
    ...scan.findings.filter(f => f.severity === 'low').map(f => `- [ ] [${f.ruleId}] ${f.title}`),
    '',
    '---',
    '*Gerado por watchDOG — use apenas em aplicações de sua propriedade ou com autorização explícita.*',
  ];

  res.setHeader('Content-Type', 'text/markdown');
  res.setHeader('Content-Disposition', `attachment; filename="checklist-${scan.id}.md"`);
  res.send(lines.join('\n'));
});

// GET /api/scans/:id/export/json
scansRouter.get('/:id/export/json', async (req: Request, res: Response) => {
  const scan = await prisma.scan.findUnique({
    where: { id: req.params.id },
    include: { findings: true },
  });
  if (!scan) return res.status(404).json({ error: 'Scan não encontrado' });

  const scanData: Scan = {
    ...scan,
    type: scan.type as any,
    status: scan.status as any,
    startedAt: scan.startedAt.toISOString(),
    finishedAt: scan.finishedAt?.toISOString(),
    durationMs: scan.durationMs ?? undefined,
    techStack: JSON.parse(scan.techStack),
    summary: JSON.parse(scan.summary),
  };
  const findings = scan.findings as unknown as Finding[];
  const report = generateJsonReport(scanData, findings);

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="watchdog-${scan.id}.json"`);
  res.json(report);
});

// GET /api/scans/:id/export/markdown
scansRouter.get('/:id/export/markdown', async (req: Request, res: Response) => {
  const scan = await prisma.scan.findUnique({
    where: { id: req.params.id },
    include: { findings: true },
  });
  if (!scan) return res.status(404).json({ error: 'Scan não encontrado' });

  const scanData: Scan = {
    ...scan,
    type: scan.type as any,
    status: scan.status as any,
    durationMs: scan.durationMs ?? undefined,
    startedAt: scan.startedAt.toISOString(),
    finishedAt: scan.finishedAt?.toISOString(),
    techStack: JSON.parse(scan.techStack),
    summary: JSON.parse(scan.summary),
  };
  const findings = scan.findings as unknown as Finding[];
  const md = generateMarkdownReport(scanData, findings);

  res.setHeader('Content-Type', 'text/markdown');
  res.setHeader('Content-Disposition', `attachment; filename="watchdog-${scan.id}.md"`);
  res.send(md);
});

// GET /api/scans/:id/export/pdf
scansRouter.get('/:id/export/pdf', async (req: Request, res: Response) => {
  const scan = await prisma.scan.findUnique({
    where: { id: req.params.id },
    include: { findings: true },
  });
  if (!scan) return res.status(404).json({ error: 'Scan não encontrado' });

  const PDFDocument = require('pdfkit');
  const doc = new PDFDocument({ margin: 50 });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="watchdog-${scan.id}.pdf"`);

  doc.pipe(res);

  const summary: ScanSummary = JSON.parse(scan.summary);
  const findings = scan.findings;

  doc.fontSize(24).fillColor('#1a1a2e').text('watchDOG', { align: 'center' });
  doc.fontSize(14).fillColor('#444').text('Relatório de Segurança Defensiva', { align: 'center' });
  doc.moveDown(2);

  doc.fontSize(18).fillColor('#000').text('Informações do Scan');
  doc.fontSize(11).fillColor('#333');
  doc.text(`Projeto: ${scan.projectName}`);
  doc.text(`Alvo: ${scan.target}`);
  doc.text(`Data: ${new Date(scan.startedAt).toLocaleDateString('pt-BR')}`);
  doc.text(`Score: ${scan.score}/100`);
  doc.text(`Status: ${scan.status}`);
  doc.moveDown();

  doc.fontSize(18).fillColor('#000').text('Sumário');
  doc.fontSize(11).fillColor('#d00').text(`Críticos: ${summary.critical}`);
  doc.fillColor('#e07700').text(`Altos: ${summary.high}`);
  doc.fillColor('#aa7700').text(`Médios: ${summary.medium}`);
  doc.fillColor('#005599').text(`Baixos: ${summary.low}`);
  doc.fillColor('#666').text(`Informativos: ${summary.info}`);
  doc.moveDown();

  doc.addPage();
  doc.fontSize(18).fillColor('#000').text('Achados por Severidade');

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severityOrder) {
    const sevFindings = findings.filter(f => f.severity === sev);
    if (sevFindings.length === 0) continue;

    const colors: Record<string, string> = {
      critical: '#cc0000', high: '#e07700', medium: '#aa7700', low: '#005599', info: '#555'
    };

    doc.moveDown();
    doc.fontSize(14).fillColor(colors[sev] || '#000').text(sev.toUpperCase() + ` (${sevFindings.length})`);

    for (const f of sevFindings.slice(0, 20)) {
      doc.fontSize(10).fillColor('#000').text(`[${f.ruleId}] ${f.title}`, { continued: false });
      if (f.filePath) doc.fontSize(9).fillColor('#666').text(`  Arquivo: ${f.filePath}${f.line ? ':' + f.line : ''}`);
      doc.fontSize(9).fillColor('#333').text(`  ${f.description.slice(0, 200)}`);
      doc.fontSize(9).fillColor('#006600').text(`  Correção: ${f.remediation.slice(0, 150)}`);
      doc.moveDown(0.3);
    }
  }

  doc.addPage();
  doc.fontSize(14).fillColor('#000').text('Checklist de Correção');
  const actionable = findings.filter(f => ['critical', 'high', 'medium'].includes(f.severity));
  for (const f of actionable) {
    doc.fontSize(10).fillColor('#333').text(`☐ [${f.ruleId}] ${f.title}`);
  }

  doc.moveDown(2);
  doc.fontSize(9).fillColor('#999').text('Relatório gerado por watchDOG. Use apenas em aplicações de sua propriedade ou com autorização explícita.', { align: 'center' });

  doc.end();
});

async function runLocalScan(scanId: string, projectPath: string) {
  const startTime = Date.now();
  try {
    const result = await analyzeLocalProject({
      projectPath,
      scanId,
      onEvent: (event) => {
        const emitter = scanEventEmitters.get(scanId);
        if (emitter) emitter(event);
      },
    });

    const findingsToSave = await applyRuleConfigs(result.findings);
    const severities = findingsToSave.map(f => f.severity as any);
    const summary = buildSummary(severities);
    const score = calculateScore(summary);

    // Save findings (batch for performance)
    for (const finding of findingsToSave) {
      await prisma.finding.create({
        data: {
          scanId,
          ruleId: finding.ruleId,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          confidence: finding.confidence || 'medium',
          filePath: finding.filePath,
          line: finding.line,
          evidenceMasked: finding.evidenceMasked,
          description: finding.description,
          impact: finding.impact,
          attackScenarioDefensive: finding.attackScenarioDefensive,
          remediation: finding.remediation,
          safeExample: finding.safeExample,
          fixPrompt: finding.fixPrompt,
          testSuggestion: finding.testSuggestion,
          reference: finding.reference,
          status: finding.status,
          occurrences: finding.occurrences || 1,
        },
      });
    }

    // Save logs
    for (const log of result.logs.slice(-200)) {
      await prisma.scanLog.create({
        data: { scanId, level: log.level, message: log.message },
      });
    }

    // Generate and save threat model
    const savedFindings = await prisma.finding.findMany({ where: { scanId } });
    const threatModelData = generateThreatModel(savedFindings as any, result.techStack);
    await prisma.threatModel.create({
      data: {
        scanId,
        assets: JSON.stringify(threatModelData.assets),
        attackers: JSON.stringify(threatModelData.attackers),
        attackSurfaces: JSON.stringify(threatModelData.attackSurfaces),
        controls: JSON.stringify(threatModelData.controls),
        gaps: JSON.stringify(threatModelData.gaps),
      },
    });

    // Generate and save defense layers
    const defenseLayers = generateDefenseDepth(savedFindings as any, result.techStack, scanId);
    for (const layer of defenseLayers) {
      await prisma.defenseLayer.create({ data: layer });
    }

    // Update scan
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'completed',
        score,
        finishedAt: new Date(),
        durationMs: Date.now() - startTime,
        techStack: JSON.stringify(result.techStack),
        summary: JSON.stringify(summary),
      },
    });

    const emitter = scanEventEmitters.get(scanId);
    if (emitter) emitter({ type: 'progress', step: 'Finalizado', progress: 100 });
  } catch (err: any) {
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'failed', finishedAt: new Date(), durationMs: Date.now() - startTime },
    });
    console.error('Scan error:', err);
    const emitter = scanEventEmitters.get(scanId);
    if (emitter) emitter({ type: 'log', level: 'error', message: err.message });
  }
}

async function runUrlScan(scanId: string, url: string, depth: 'quick' | 'normal' | 'deep') {
  const startTime = Date.now();
  try {
    const result = await analyzeUrl({
      url,
      scanId,
      depth,
      onEvent: (event) => {
        const emitter = scanEventEmitters.get(scanId);
        if (emitter) emitter(event);
      },
    });

    const findingsToSave = await applyRuleConfigs(result.findings);
    const severities = findingsToSave.map(f => f.severity as any);
    const summary = buildSummary(severities);
    const score = calculateScore(summary);

    for (const finding of findingsToSave) {
      await prisma.finding.create({
        data: {
          scanId,
          ruleId: finding.ruleId,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          confidence: finding.confidence || 'high',
          url: finding.url,
          evidenceMasked: finding.evidenceMasked,
          description: finding.description,
          impact: finding.impact,
          attackScenarioDefensive: finding.attackScenarioDefensive,
          remediation: finding.remediation,
          safeExample: finding.safeExample,
          fixPrompt: finding.fixPrompt,
          testSuggestion: finding.testSuggestion,
          reference: finding.reference,
          status: finding.status,
          occurrences: finding.occurrences || 1,
        },
      });
    }

    for (const log of result.logs.slice(-200)) {
      await prisma.scanLog.create({ data: { scanId, level: log.level, message: log.message } });
    }

    // Threat model and defense layers for URL scans
    const savedFindings = await prisma.finding.findMany({ where: { scanId } });
    const threatModelData = generateThreatModel(savedFindings as any, result.techStack);
    await prisma.threatModel.create({
      data: {
        scanId,
        assets: JSON.stringify(threatModelData.assets),
        attackers: JSON.stringify(threatModelData.attackers),
        attackSurfaces: JSON.stringify(threatModelData.attackSurfaces),
        controls: JSON.stringify(threatModelData.controls),
        gaps: JSON.stringify(threatModelData.gaps),
      },
    });
    const defenseLayers = generateDefenseDepth(savedFindings as any, result.techStack, scanId);
    for (const layer of defenseLayers) {
      await prisma.defenseLayer.create({ data: layer });
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'completed',
        score,
        finishedAt: new Date(),
        durationMs: Date.now() - startTime,
        techStack: JSON.stringify(result.techStack),
        summary: JSON.stringify(summary),
      },
    });

    const emitter = scanEventEmitters.get(scanId);
    if (emitter) emitter({ type: 'progress', step: 'Finalizado', progress: 100 });
  } catch (err: any) {
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'failed', finishedAt: new Date(), durationMs: Date.now() - startTime },
    });
    const emitter = scanEventEmitters.get(scanId);
    if (emitter) emitter({ type: 'log', level: 'error', message: err.message });
  }
}
