import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { Severity } from '@sentinelscope/shared';
import { DependencyIssue } from '../types';

const SUSPICIOUS_PACKAGES: Array<{ pattern: RegExp; reason: string; severity: Severity }> = [
  { pattern: /^colors$/, reason: 'Maintainer injected malicious code (colors@1.4.2)', severity: 'high' },
  { pattern: /^event-stream$/, reason: 'Historical malicious code injection', severity: 'high' },
  { pattern: /^node-ipc$/, reason: 'Maintainer injected political malware (v10.1.1-10.1.3)', severity: 'high' },
  { pattern: /^flatmap-stream$/, reason: 'Malicious payload targeting BitPay', severity: 'critical' },
];

const DANGEROUS_SCRIPTS = [
  /curl\s+https?:\/\//,
  /wget\s+https?:\/\//,
  /eval\s*\(/,
  /base64/i,
  /python\s+-c/,
  /powershell/i,
  /\.exe\b/i,
  /require\s*\(\s*['"`]https?:/,
];

// Scripts de lifecycle que executam automaticamente em `npm install`.
const LIFECYCLE_SCRIPT_NAMES = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];

// Indica download remoto seguido de execução dentro de um script de install
// (SUPPLY_001/002) — IOC clássico de worm de supply chain.
const REMOTE_DOWNLOAD_EXEC = [
  /\b(?:curl|wget|invoke-webrequest|iwr)\b[^\n]*\bhttps?:\/\//i,
  /\bnode\s+(?:-e|--eval)\b/i,
  /\b(?:curl|wget)\b[^\n]*\|\s*(?:bash|sh|node)\b/i,
];

// IOCs de arquivos do worm Shai-Hulud / Bun (SUPPLY_002).
const WORM_IOC_FILES = [
  'setup_bun.js',
  'bun_environment.js',
  'shai-hulud.yml',
  'shai-hulud.yaml',
  'shai-hulud-workflow.yml',
  'shai-hulud-workflow.yaml',
];

const KNOWN_VULNERABLE: Record<string, { minSafe: string; issue: string; severity: Severity }> = {
  'lodash': { minSafe: '4.17.21', issue: 'Prototype pollution (CVE-2019-10744)', severity: 'high' },
  'minimist': { minSafe: '1.2.6', issue: 'Prototype pollution (CVE-2021-44906)', severity: 'medium' },
  'axios': { minSafe: '1.6.0', issue: 'SSRF/CSRF vulnerabilities in older versions', severity: 'medium' },
  'jsonwebtoken': { minSafe: '9.0.0', issue: 'Algorithm confusion attack (CVE-2022-23529)', severity: 'high' },
  'moment': { minSafe: '999.99.99', issue: 'Deprecated package, use date-fns or dayjs', severity: 'info' },
};

// Tabela mínima e datada de versões vulneráveis conhecidas em 2026.
// Curta e propositalmente datada; idealmente alimentada via OSV no futuro.
const KNOWN_VULNERABLE_2026: Record<string, { minSafe: string; issue: string; severity: Severity }> = {
  'axios': { minSafe: '1.12.0', issue: 'SSRF via redirect/absolute URL (CVE-2026-42033, 2026)', severity: 'high' },
  'flatted': { minSafe: '3.3.4', issue: 'Prototype pollution na desserialização (CVE-2026-33228, 2026)', severity: 'high' },
  'n8n': { minSafe: '1.78.0', issue: 'Execução remota via expressão não isolada (CVE-2026-54306, 2026)', severity: 'critical' },
  'picomatch': { minSafe: '4.0.3', issue: 'ReDoS em padrões glob maliciosos (CVE-2026-33671, 2026)', severity: 'medium' },
};

/**
 * Versões EXATAS publicadas comprometidas em campanhas confirmadas de supply
 * chain (não é "versão antiga com CVE" — é código malicioso publicado sob a
 * versão). Qualquer uma destas no projeto deve ser tratada como incidente:
 * remover, rotacionar credenciais e reinstalar a partir de lockfile limpo.
 */
const COMPROMISED_VERSIONS: Record<string, { versions: string[]; campaign: string }> = {
  // "qix" maintainer phishing (2025-09-08) — clipper de carteira cripto no bundle
  'chalk': { versions: ['5.6.1'], campaign: 'qix maintainer phishing (set/2025)' },
  'debug': { versions: ['4.4.2'], campaign: 'qix maintainer phishing (set/2025)' },
  'ansi-styles': { versions: ['6.2.2'], campaign: 'qix maintainer phishing (set/2025)' },
  'ansi-regex': { versions: ['6.2.1'], campaign: 'qix maintainer phishing (set/2025)' },
  'strip-ansi': { versions: ['7.1.1'], campaign: 'qix maintainer phishing (set/2025)' },
  'wrap-ansi': { versions: ['9.0.1'], campaign: 'qix maintainer phishing (set/2025)' },
  'supports-color': { versions: ['10.2.1'], campaign: 'qix maintainer phishing (set/2025)' },
  'color-convert': { versions: ['3.1.1'], campaign: 'qix maintainer phishing (set/2025)' },
  'color-name': { versions: ['2.0.1'], campaign: 'qix maintainer phishing (set/2025)' },
  'color-string': { versions: ['2.1.1'], campaign: 'qix maintainer phishing (set/2025)' },
  'slice-ansi': { versions: ['7.1.1'], campaign: 'qix maintainer phishing (set/2025)' },
  'is-arrayish': { versions: ['0.3.3'], campaign: 'qix maintainer phishing (set/2025)' },
  'error-ex': { versions: ['1.3.3'], campaign: 'qix maintainer phishing (set/2025)' },
  // "Scavenger" phishing via npnjs.com (2025-07) — CVE-2025-54313
  'eslint-config-prettier': { versions: ['8.10.1', '9.1.1', '10.1.6', '10.1.7'], campaign: 'Scavenger (CVE-2025-54313, jul/2025)' },
  'eslint-plugin-prettier': { versions: ['4.2.2', '4.2.3'], campaign: 'Scavenger (jul/2025)' },
  'synckit': { versions: ['0.11.9', '0.11.10'], campaign: 'Scavenger (jul/2025)' },
  'napi-postinstall': { versions: ['0.3.1', '0.3.2'], campaign: 'Scavenger (jul/2025)' },
  'is': { versions: ['3.3.1', '5.0.0'], campaign: 'Scavenger — RAT WebSocket (jul/2025)' },
  // nx / s1ngularity (2025-08) — CVE-2025-10894
  'nx': { versions: ['20.9.0', '20.10.0', '20.11.0', '20.12.0', '21.5.0', '21.6.0', '21.7.0', '21.8.0'], campaign: 's1ngularity (CVE-2025-10894, ago/2025)' },
  // Shai-Hulud v1 (2025-09) — worm auto-propagante
  '@ctrl/tinycolor': { versions: ['4.1.1', '4.1.2'], campaign: 'Shai-Hulud worm (set/2025)' },
  'ngx-bootstrap': { versions: ['18.1.4', '19.0.3', '19.0.4', '20.0.3', '20.0.4', '20.0.5', '20.0.6'], campaign: 'Shai-Hulud worm (set/2025)' },
  'ngx-toastr': { versions: ['19.0.1', '19.0.2'], campaign: 'Shai-Hulud worm (set/2025)' },
  'angulartics2': { versions: ['14.1.1', '14.1.2'], campaign: 'Shai-Hulud worm (set/2025)' },
  // rspack / vant (2024-12) — XMRig cryptominer
  '@rspack/core': { versions: ['1.1.7'], campaign: 'XMRig miner (dez/2024)' },
  '@rspack/cli': { versions: ['1.1.7'], campaign: 'XMRig miner (dez/2024)' },
  // axios RAT (2026-03) — CISA
  'axios': { versions: ['1.14.1', '0.30.4'], campaign: 'RAT Sapphire Sleet (mar/2026)' },
  'plain-crypto-js': { versions: ['4.2.1'], campaign: 'dependencia fantasma — dropper de RAT (mar/2026)' },
  // ChainDrop / keyv & cacheable (2026-08)
  'keyv': { versions: ['6.0.0'], campaign: 'ChainDrop worm (ago/2026)' },
  'flat-cache': { versions: ['6.1.24'], campaign: 'ChainDrop worm (ago/2026)' },
  'file-entry-cache': { versions: ['11.1.6'], campaign: 'ChainDrop worm (ago/2026)' },
  'cacheable-request': { versions: ['13.0.20'], campaign: 'ChainDrop worm (ago/2026)' },
  'cacheable': { versions: ['2.5.1'], campaign: 'ChainDrop worm (ago/2026)' },
  'cache-manager': { versions: ['7.2.10'], campaign: 'ChainDrop worm (ago/2026)' },
  // Mastra / Sapphire Sleet (2026-06) — typosquat injetado como dependencia
  'easy-day-js': { versions: ['*'], campaign: 'Mastra/Sapphire Sleet — typosquat de dayjs (jun/2026)' },
};

// Allowlist de pacotes populares para heurística de typosquat (Levenshtein <= 1).
const POPULAR_PACKAGES = ['react', 'lodash', 'dayjs', 'axios', 'express', 'chalk', 'next', 'vue'];

interface PackageJson {
  name?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export async function analyzeDependencies(projectPath: string): Promise<DependencyIssue[]> {
  const issues: DependencyIssue[] = [];

  const pkgPath = path.join(projectPath, 'package.json');
  if (!fs.existsSync(pkgPath)) return issues;

  let pkg: PackageJson;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
  } catch {
    return issues;
  }

  // Check dangerous scripts
  if (pkg.scripts) {
    for (const [scriptName, scriptValue] of Object.entries(pkg.scripts)) {
      for (const pattern of DANGEROUS_SCRIPTS) {
        if (pattern.test(scriptValue)) {
          issues.push({
            package: `package.json scripts.${scriptName}`,
            version: scriptValue.slice(0, 60),
            issue: `Script potencialmente perigoso: ${scriptValue.slice(0, 80)}`,
            severity: 'high',
          });
        }
      }
    }

    // SUPPLY_001: scripts de lifecycle com download remoto + execução => crítico.
    for (const scriptName of LIFECYCLE_SCRIPT_NAMES) {
      const scriptValue = pkg.scripts[scriptName];
      if (!scriptValue) continue;
      if (REMOTE_DOWNLOAD_EXEC.some((p) => p.test(scriptValue))) {
        issues.push({
          package: `package.json scripts.${scriptName}`,
          version: scriptValue.slice(0, 60),
          issue: `SUPPLY_001: lifecycle script "${scriptName}" baixa e executa código remoto (IOC de supply chain): ${scriptValue.slice(0, 80)}`,
          severity: 'critical',
        });
      }
    }
  }

  // SUPPLY_005: dependências apontando para git+http / tarball http / git sem commit pin.
  for (const [pkgName, spec] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
    if (typeof spec !== 'string') continue;
    if (/^git\+http:\/\//i.test(spec)) {
      issues.push({
        package: pkgName,
        version: spec,
        issue: 'SUPPLY_005: dependência via git+http inseguro (sem TLS), sujeita a MITM no install',
        severity: 'high',
      });
    } else if (/^http:\/\/[^"]+\.(?:tgz|tar\.gz)$/i.test(spec)) {
      issues.push({
        package: pkgName,
        version: spec,
        issue: 'SUPPLY_005: dependência via tarball http inseguro (sem TLS), sujeita a MITM/substituição',
        severity: 'high',
      });
    } else if (/^(?:github:|git\+https:\/\/)/i.test(spec) && !/#[0-9a-f]{40}/.test(spec)) {
      issues.push({
        package: pkgName,
        version: spec,
        issue: 'SUPPLY_005: dependência git sem commit pin (#<sha40>); o conteúdo pode mudar sem aviso',
        severity: 'high',
      });
    }
  }

  // SUPPLY_004: .npmrc apontando escopos para o registry público (dependency confusion).
  const npmrcPath = path.join(projectPath, '.npmrc');
  if (fs.existsSync(npmrcPath)) {
    try {
      const npmrc = fs.readFileSync(npmrcPath, 'utf-8');
      if (/@[a-z0-9-]+:registry\s*=\s*https?:\/\/registry\.npmjs\.org/i.test(npmrc)) {
        issues.push({
          package: '.npmrc',
          version: '-',
          issue: 'SUPPLY_004: escopo privado mapeado para o registry público (registry.npmjs.org), habilitando dependency confusion',
          severity: 'high',
        });
      }
    } catch {
      // ignore
    }
  }

  // SUPPLY_009: lockfile tampering — entradas "resolved"/"resolution" fora dos
  // registries oficiais (npm/yarn).
  const lockFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
  for (const lockName of lockFiles) {
    const lockFilePath = path.join(projectPath, lockName);
    if (!fs.existsSync(lockFilePath)) continue;
    try {
      const lockContent = fs.readFileSync(lockFilePath, 'utf-8');
      const tampered =
        /"resolved"\s*:\s*"https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)[^"]+\.(?:tgz|tar\.gz)"/i.test(lockContent) ||
        /resolution:\s*"https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)/i.test(lockContent);
      if (tampered) {
        issues.push({
          package: lockName,
          version: '-',
          issue: 'SUPPLY_009: lockfile com "resolved" apontando para fora do registry oficial (possível tampering/substituição de pacote)',
          severity: 'high',
        });
      }
    } catch {
      // ignore
    }
  }

  // SUPPLY_002: IOCs de arquivos do worm Shai-Hulud/Bun na raiz do projeto.
  for (const iocFile of WORM_IOC_FILES) {
    if (fs.existsSync(path.join(projectPath, iocFile))) {
      issues.push({
        package: iocFile,
        version: '-',
        issue: 'SUPPLY_002: arquivo associado ao worm de supply chain Shai-Hulud detectado no projeto',
        severity: 'critical',
      });
    }
  }

  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
  };

  // Check suspicious packages
  for (const [pkgName] of Object.entries(allDeps)) {
    for (const { pattern, reason, severity } of SUSPICIOUS_PACKAGES) {
      if (pattern.test(pkgName)) {
        issues.push({
          package: pkgName,
          version: allDeps[pkgName],
          issue: reason,
          severity,
        });
      }
    }
  }

  // Check known vulnerable versions (tabelas histórica + 2026)
  for (const [pkgName, version] of Object.entries(allDeps)) {
    const cleanVersion = version.replace(/^[^0-9]/, '');
    for (const table of [KNOWN_VULNERABLE, KNOWN_VULNERABLE_2026]) {
      const vulnerable = table[pkgName];
      if (vulnerable && compareVersions(cleanVersion, vulnerable.minSafe) < 0) {
        issues.push({
          package: pkgName,
          version,
          issue: vulnerable.issue,
          severity: vulnerable.severity,
        });
      }
    }
  }

  // Versões comprometidas por campanha confirmada de supply chain.
  // Diferente de "versão com CVE": aqui a versão publicada CONTÉM malware.
  for (const [pkgName, version] of Object.entries(allDeps)) {
    const entry = COMPROMISED_VERSIONS[pkgName];
    if (!entry) continue;

    // Versão declarada com range (^1.2.3) — comparamos o número base.
    const cleanVersion = version.replace(/^[^0-9]*/, '').trim();
    const atingido =
      entry.versions.includes('*') || entry.versions.includes(cleanVersion);

    if (atingido) {
      issues.push({
        package: pkgName,
        version,
        issue:
          `VERSÃO COMPROMETIDA — ${entry.campaign}. Esta versão publicada contém código malicioso ` +
          `(roubo de tokens npm/GitHub e credenciais de nuvem). Trate como incidente: remova a versão, ` +
          `rotacione TODAS as credenciais do ambiente e reinstale a partir de um lockfile limpo.`,
        severity: 'critical',
      });
    }
  }

  // Typosquat: distância de Levenshtein <= 1 contra a allowlist popular.
  const popularSet = new Set(POPULAR_PACKAGES);
  for (const pkgName of Object.keys(allDeps)) {
    if (popularSet.has(pkgName)) continue; // o pacote legítimo em si não é typosquat
    if (pkgName.startsWith('@')) continue; // pacotes com escopo não casam com a allowlist
    for (const popular of POPULAR_PACKAGES) {
      if (levenshtein(pkgName, popular) <= 1) {
        issues.push({
          package: pkgName,
          version: allDeps[pkgName],
          issue: `Possível typosquat de "${popular}" (distância de edição <= 1). Confirme se o nome do pacote está correto.`,
          severity: 'high',
        });
        break;
      }
    }
  }

  // Recomendação npm ci --ignore-scripts quando houver lifecycle scripts.
  const lifecycleScriptsPresent = pkg.scripts
    ? LIFECYCLE_SCRIPT_NAMES.filter((name) => !!pkg.scripts![name])
    : [];
  if (lifecycleScriptsPresent.length > 0) {
    issues.push({
      package: 'package.json',
      version: '-',
      issue: `Foram encontrados ${lifecycleScriptsPresent.length} lifecycle script(s) (${lifecycleScriptsPresent.join(', ')}) que executam automaticamente no install. Em CI/produção, prefira "npm ci --ignore-scripts" para mitigar execução de código de dependências comprometidas.`,
      severity: 'low',
    });
  }

  // Try npm audit (non-blocking, best-effort)
  try {
    const lockPath = path.join(projectPath, 'package-lock.json');
    const pnpmLockPath = path.join(projectPath, 'pnpm-lock.yaml');
    if (fs.existsSync(lockPath) || fs.existsSync(pnpmLockPath)) {
      const cmd = fs.existsSync(pnpmLockPath) ? 'pnpm audit --json' : 'npm audit --json';
      const result = execSync(cmd, { cwd: projectPath, timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] });
      const audit = JSON.parse(result.toString());
      const vulns = audit.vulnerabilities || audit.advisories || {};
      for (const [pkgName, vuln] of Object.entries(vulns) as any[]) {
        if (vuln.severity && ['critical', 'high'].includes(vuln.severity)) {
          issues.push({
            package: pkgName,
            version: vuln.range || '?',
            issue: vuln.title || `npm audit: ${vuln.severity}`,
            severity: vuln.severity as Severity,
          });
        }
      }
    }
  } catch {
    // npm audit failed or not available, ignore
  }

  return issues;
}

function compareVersions(a: string, b: string): number {
  const partsA = a.split('.').map(Number);
  const partsB = b.split('.').map(Number);
  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const pa = partsA[i] ?? 0;
    const pb = partsB[i] ?? 0;
    if (pa < pb) return -1;
    if (pa > pb) return 1;
  }
  return 0;
}

// Distância de Levenshtein clássica (programação dinâmica), limitada a nomes
// curtos de pacotes — sem risco de ReDoS por ser aritmética pura.
function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const prev = new Array<number>(n + 1);
  const curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= n; j++) prev[j] = curr[j];
  }
  return prev[n];
}
