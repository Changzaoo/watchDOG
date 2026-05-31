import path from 'path';
import { Finding, ScanLog } from '@sentinelscope/shared';
import { LocalScanOptions, ScanResultRaw } from '../types';
import { FileRule } from '../types';
import { walkFiles, checkFileExists } from './fileWalker';
import { detectTechStack } from './techDetector';
import { analyzeDependencies } from './dependencyAnalyzer';
import { findAllMatches } from '../utils/lineFinder';
import { extractAndMaskSecret } from '../utils/maskSecret';
import { generateFixPrompt, generateSecretFixPrompt } from '../utils/fixPromptGenerator';
import { validateLocalPath } from '../utils/urlValidator';
import { allFileRules } from '../rules';

import { secretsRules } from '../rules/secrets.rules';
import { dockerRules } from '../rules/docker.rules';

const ALL_RULES: FileRule[] = allFileRules;

const STEPS = [
  { key: 'tech', label: 'Detectando tecnologias', progress: 5 },
  { key: 'secrets', label: 'Verificando arquivos sensíveis e secrets', progress: 15 },
  { key: 'deps', label: 'Analisando dependências', progress: 30 },
  { key: 'auth', label: 'Analisando autenticação e autorização', progress: 45 },
  { key: 'code', label: 'Analisando código-fonte', progress: 65 },
  { key: 'docker', label: 'Analisando Docker e CI/CD', progress: 80 },
  { key: 'report', label: 'Gerando relatório', progress: 95 },
];

const SECRET_RULE_IDS = new Set(['SECRET_001', 'SECRET_002', 'SECRET_003', 'SECRET_004', 'SECRET_005', 'SECRET_006', 'SECRET_007', 'SECRET_008', 'SECRET_009', 'SECRET_010', 'SECRET_011', 'SECRET_012']);

export async function analyzeLocalProject(opts: LocalScanOptions): Promise<ScanResultRaw> {
  const { projectPath, scanId, onEvent } = opts;
  const findings: Array<Omit<Finding, 'id' | 'createdAt'>> = [];
  const logs: Array<Omit<ScanLog, 'id' | 'createdAt'>> = [];

  function log(level: 'info' | 'warn' | 'error', message: string) {
    logs.push({ scanId, level, message });
    onEvent({ type: 'log', level, message });
  }

  function progress(step: string, pct: number) {
    onEvent({ type: 'progress', step, progress: pct });
  }

  function addFinding(
    rule: FileRule,
    filePath: string,
    line?: number,
    evidence?: string,
    overrideOccurrences?: number
  ) {
    const isSecret = SECRET_RULE_IDS.has(rule.id);
    const fixPrompt = isSecret
      ? generateSecretFixPrompt(rule, filePath)
      : generateFixPrompt(rule, filePath, line);

    const finding: Omit<Finding, 'id' | 'createdAt'> = {
      scanId,
      ruleId: rule.id,
      title: rule.title,
      severity: rule.severity,
      category: rule.category,
      confidence: rule.confidence || 'medium',
      filePath,
      line,
      evidenceMasked: evidence,
      description: rule.description,
      impact: rule.impact,
      attackScenarioDefensive: rule.attackScenarioDefensive,
      remediation: rule.remediation,
      safeExample: rule.safeExample,
      fixPrompt,
      testSuggestion: rule.testSuggestion,
      reference: rule.reference,
      status: 'open',
      occurrences: overrideOccurrences || 1,
    };
    findings.push(finding);
    onEvent({ type: 'finding', finding });
  }

  log('info', 'Iniciando análise watchDOG: ' + projectPath);

  // Safety check
  const pathCheck = validateLocalPath(projectPath);
  if (!pathCheck.valid) {
    log('error', `Caminho bloqueado: ${pathCheck.reason}`);
    return { findings: [], techStack: [], logs };
  }

  // STEP 1: Detect tech
  progress(STEPS[0].label, STEPS[0].progress);
  log('info', STEPS[0].label);
  const techStack = detectTechStack(projectPath);
  log('info', `Tecnologias: ${techStack.map(t => t.name).join(', ') || 'Nenhuma detectada'}`);

  // STEP 2: Walk files and check sensitive filenames
  progress(STEPS[1].label, STEPS[1].progress);
  log('info', STEPS[1].label);

  const files = await walkFiles(projectPath);
  log('info', `${files.length} arquivos para análise`);

  const sensitiveFileNames = [
    '.env', '.env.local', '.env.production', '.env.staging', '.env.development',
    'serviceAccountKey.json', 'firebase-adminsdk.json',
    'id_rsa', 'id_ecdsa', 'id_ed25519',
    'credentials.json', 'secret.key', 'private.key',
    'wallet.json', 'keystore.json', '.npmrc',
  ];

  for (const file of files) {
    const basename = path.basename(file.path);
    if (sensitiveFileNames.includes(basename)) {
      const secretRule = secretsRules.find(r => r.id === 'SECRET_004')!;
      const { masked } = extractAndMaskSecret(file.content.slice(0, 200));
      addFinding(secretRule, file.path, 1, masked.slice(0, 100));
      log('warn', `Arquivo sensível: ${basename}`);
    }
  }

  // STEP 3: Dependencies
  progress(STEPS[2].label, STEPS[2].progress);
  log('info', STEPS[2].label);
  const depIssues = await analyzeDependencies(projectPath);
  for (const issue of depIssues) {
    findings.push({
      scanId,
      ruleId: 'DEP_001',
      title: `Dependência vulnerável: ${issue.package}`,
      severity: issue.severity,
      category: 'Dependências',
      confidence: 'high',
      filePath: path.join(projectPath, 'package.json'),
      evidenceMasked: `${issue.package}@${issue.version}`,
      description: issue.issue,
      impact: 'Versão com vulnerabilidade conhecida pode ser explorada por atacante.',
      attackScenarioDefensive: `Atacante verifica versões de dependências públicas (npm advisories) e explora CVEs conhecidos em ${issue.package}.`,
      remediation: `Atualize ${issue.package} para a versão mais recente: npm update ${issue.package}`,
      fixPrompt: generateFixPrompt(
        { id: 'DEP_001', title: `Dependência vulnerável: ${issue.package}`, description: issue.issue, impact: 'CVE conhecido', remediation: `npm update ${issue.package}` },
        path.join(projectPath, 'package.json')
      ),
      reference: 'OWASP A06:2021 - Vulnerable and Outdated Components',
      status: 'open',
      occurrences: 1,
    });
  }
  log('info', `${depIssues.length} problemas de dependências`);

  // STEP 4-6: Apply file rules
  progress(STEPS[3].label, STEPS[3].progress);
  log('info', STEPS[3].label);

  // Deduplication: track key -> { count, firstFinding }
  const dedupeMap = new Map<string, { count: number; idx: number }>();

  for (const file of files) {
    const ext = path.extname(file.path).toLowerCase();

    for (const rule of ALL_RULES) {
      if (rule.fileExtensions && !rule.fileExtensions.includes(ext)) continue;
      if (rule.fileNamePatterns) {
        const matchesName = rule.fileNamePatterns.some(p => p.test(file.path.replace(/\\/g, '/')));
        if (!matchesName) continue;
      }

      for (const pattern of rule.patterns) {
        const matches = findAllMatches(file.content, pattern, file.path);
        if (matches.length === 0) continue;

        // Use first match for evidence
        const firstMatch = matches[0];
        const dedupeKey = `${rule.id}:${path.relative(projectPath, file.path)}`;

        const existing = dedupeMap.get(dedupeKey);
        if (existing) {
          // Increment occurrence count on the first finding
          const f = findings[existing.idx];
          if (f) (f as any).occurrences = (existing.count + matches.length);
          dedupeMap.set(dedupeKey, { count: existing.count + matches.length, idx: existing.idx });
        } else {
          const { masked } = extractAndMaskSecret(firstMatch.text);
          addFinding(rule, file.path, firstMatch.line, masked.slice(0, 200), matches.length);
          dedupeMap.set(dedupeKey, { count: matches.length, idx: findings.length - 1 });
        }
      }
    }
  }

  progress(STEPS[4].label, STEPS[4].progress);
  log('info', STEPS[4].label);

  // Missing security files check
  if (!checkFileExists(projectPath, '.gitignore')) {
    const rule: FileRule = {
      id: 'CONFIG_001',
      title: '.gitignore ausente',
      category: 'Configuração',
      severity: 'low',
      confidence: 'high',
      description: 'Sem .gitignore, arquivos sensíveis como .env e node_modules podem ser versionados.',
      impact: 'Secrets, tokens e dados sensíveis podem ser expostos no repositório.',
      remediation: 'Crie um .gitignore adequado. Use gitignore.io para gerar um para seu projeto.',
      patterns: [],
    };
    addFinding(rule, projectPath);
  }

  if (!checkFileExists(projectPath, '.dockerignore') && checkFileExists(projectPath, 'Dockerfile')) {
    const rule = dockerRules.find(r => r.id === 'DOCKER_007');
    if (rule) addFinding(rule, path.join(projectPath, 'Dockerfile'));
  }

  progress(STEPS[5].label, STEPS[5].progress);
  progress(STEPS[6].label, STEPS[6].progress);
  log('info', `Análise concluída. ${findings.length} achados (${new Set(findings.map(f => f.ruleId)).size} regras distintas).`);

  return { findings, techStack, logs };
}
