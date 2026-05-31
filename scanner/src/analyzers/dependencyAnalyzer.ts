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

const KNOWN_VULNERABLE: Record<string, { minSafe: string; issue: string; severity: Severity }> = {
  'lodash': { minSafe: '4.17.21', issue: 'Prototype pollution (CVE-2019-10744)', severity: 'high' },
  'minimist': { minSafe: '1.2.6', issue: 'Prototype pollution (CVE-2021-44906)', severity: 'medium' },
  'axios': { minSafe: '1.6.0', issue: 'SSRF/CSRF vulnerabilities in older versions', severity: 'medium' },
  'jsonwebtoken': { minSafe: '9.0.0', issue: 'Algorithm confusion attack (CVE-2022-23529)', severity: 'high' },
  'moment': { minSafe: '999.99.99', issue: 'Deprecated package, use date-fns or dayjs', severity: 'info' },
};

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

  // Check known vulnerable versions
  for (const [pkgName, version] of Object.entries(allDeps)) {
    const cleanVersion = version.replace(/^[^0-9]/, '');
    const vulnerable = KNOWN_VULNERABLE[pkgName];
    if (vulnerable) {
      const isVulnerable = compareVersions(cleanVersion, vulnerable.minSafe) < 0;
      if (isVulnerable) {
        issues.push({
          package: pkgName,
          version,
          issue: vulnerable.issue,
          severity: vulnerable.severity,
        });
      }
    }
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
