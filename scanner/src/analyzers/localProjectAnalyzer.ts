import path from 'path';
import { Finding, ScanLog } from '@sentinelscope/shared';
import { LocalScanOptions, ScanResultRaw } from '../types';
import { FileRule } from '../types';
import { walkFiles, checkFileExists } from './fileWalker';
import { detectTechStack } from './techDetector';
import { analyzeDependencies } from './dependencyAnalyzer';
import { findAllMatchesMultiline } from '../utils/lineFinder';
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

// Categorias tratadas como "secret" para fins de fix prompt especializado.
const SECRET_CATEGORIES = new Set(['Secrets', 'Credenciais']);

/**
 * Considera uma regra como "de secret" (recebe generateSecretFixPrompt) quando o id
 * começa com 'SECRET_' OU a categoria é 'Secrets'/'Credenciais'. Assim novas regras
 * (SECRET_013..020 e futuras) são tratadas automaticamente sem manutenção de lista fixa.
 */
function isSecretRule(rule: FileRule): boolean {
  return rule.id.startsWith('SECRET_') || SECRET_CATEGORIES.has(rule.category);
}

// Tamanho do lote de arquivos entre yields cooperativos (não trava o event loop/SSE).
const FILE_BATCH_SIZE = 25;

const BUCKET_ANY = '__any__';

/**
 * Índice invertido de regras por extensão + bucket para regras sem fileExtensions
 * (que dependem só de fileNamePatterns/requireContent). Construído UMA vez na carga.
 */
function buildRuleBuckets(rules: FileRule[]): {
  rulesByExt: Map<string, FileRule[]>;
  rulesAnyExt: FileRule[];
} {
  const rulesByExt = new Map<string, FileRule[]>();
  const rulesAnyExt: FileRule[] = [];
  for (const r of rules) {
    if (r.fileExtensions && r.fileExtensions.length) {
      for (const e of r.fileExtensions) {
        const ext = e.toLowerCase();
        const arr = rulesByExt.get(ext);
        if (arr) arr.push(r);
        else rulesByExt.set(ext, [r]);
      }
    } else {
      rulesAnyExt.push(r);
    }
  }
  return { rulesByExt, rulesAnyExt };
}

const { rulesByExt: RULES_BY_EXT, rulesAnyExt: RULES_ANY_EXT } = buildRuleBuckets(ALL_RULES);

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
    const isSecret = isSecretRule(rule);
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

  // Supressão cross-file: regras de postura (ex.: "Express sem rate limiting") são
  // ignoradas no projeto inteiro quando a proteção correspondente existe em qualquer
  // arquivo. Calculado UMA vez para evitar falso-positivo entre arquivos.
  const suppressedRuleIds = new Set<string>();
  for (const rule of ALL_RULES) {
    if (rule.suppressIfProjectMatches) {
      const re = rule.suppressIfProjectMatches;
      if (files.some(f => re.test(f.content))) {
        suppressedRuleIds.add(rule.id);
      }
    }
  }
  if (suppressedRuleIds.size > 0) {
    log('info', `${suppressedRuleIds.size} regra(s) de postura suprimida(s) (proteção detectada no projeto): ${[...suppressedRuleIds].join(', ')}`);
  }

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

  // STEP 4-6: Single-pass — aplica todas as regras por arquivo via buckets de extensão.
  // Os "steps" abaixo são apenas marcos de progresso; não há re-scan de disco.
  progress(STEPS[3].label, STEPS[3].progress);
  log('info', STEPS[3].label);

  // Dedupe por ruleId::path::line; mantém contagem de ocorrências por (ruleId, path).
  const seen = new Set<string>();
  const occMap = new Map<string, { count: number; idx: number }>();

  // Faixa de progresso reservada à varredura single-pass: do step "auth" ao "code".
  const scanStartPct = STEPS[3].progress; // 45
  const scanEndPct = STEPS[4].progress;   // 65
  const totalFiles = files.length || 1;

  for (let fi = 0; fi < files.length; fi++) {
    const file = files[fi];
    const ext = file.ext ?? path.extname(file.path).toLowerCase();
    const normPath = file.normPath ?? file.path.replace(/\\/g, '/');
    const content = file.content;

    // candidates = regras da extensão + regras "any" (dependem de fileNamePatterns).
    const byExt = RULES_BY_EXT.get(ext);
    const candidates = byExt ? [...byExt, ...RULES_ANY_EXT] : RULES_ANY_EXT;

    for (const rule of candidates) {
      // Regra de postura suprimida por proteção presente em outro arquivo do projeto.
      if (suppressedRuleIds.has(rule.id)) continue;

      // Filtro por nome de arquivo (caminho normalizado com '/').
      if (rule.fileNamePatterns) {
        const matchesName = rule.fileNamePatterns.some(p => p.test(normPath));
        if (!matchesName) continue;
      }

      // Gate de conteúdo: a regra só se aplica se o conteúdo casar requireContent.
      if (rule.requireContent && !rule.requireContent.test(content)) continue;

      for (const pattern of rule.patterns) {
        const matches = findAllMatchesMultiline(content, pattern, file.path);
        if (matches.length === 0) continue;

        const firstMatch = matches[0];
        const occKey = `${rule.id}::${path.relative(projectPath, file.path)}`;
        const dedupeKey = `${rule.id}::${file.path}::${firstMatch.line}`;

        const existing = occMap.get(occKey);
        if (existing) {
          // Já há finding para (regra, arquivo): só incrementa ocorrências.
          const f = findings[existing.idx];
          const newCount = existing.count + matches.length;
          if (f) (f as any).occurrences = newCount;
          occMap.set(occKey, { count: newCount, idx: existing.idx });
        } else if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);
          const { masked } = extractAndMaskSecret(firstMatch.text);
          addFinding(rule, file.path, firstMatch.line, masked.slice(0, 200), matches.length);
          occMap.set(occKey, { count: matches.length, idx: findings.length - 1 });
        }
      }
    }

    // Yield cooperativo a cada lote: não trava o event loop / heartbeat SSE.
    if ((fi + 1) % FILE_BATCH_SIZE === 0) {
      const pct = scanStartPct + Math.round(((fi + 1) / totalFiles) * (scanEndPct - scanStartPct));
      progress(STEPS[4].label, Math.min(pct, scanEndPct));
      await new Promise<void>(r => setImmediate(r));
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
