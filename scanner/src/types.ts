import { Severity, Confidence, Finding, TechStack, ScanLog } from '@sentinelscope/shared';

export interface FileRule {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence?: Confidence;
  description: string;
  impact: string;
  attackScenarioDefensive?: string;
  remediation: string;
  safeExample?: string;
  testSuggestion?: string;
  reference?: string;
  patterns: RegExp[];
  fileExtensions?: string[];
  fileNamePatterns?: RegExp[];
  requireContent?: RegExp;
  /**
   * Gate cross-file: se QUALQUER arquivo do projeto casar este padrão, a regra inteira
   * é suprimida no scan. Usado por regras de postura (ex.: "Express sem rate limiting")
   * para não disparar falso-positivo quando a proteção existe em outro arquivo.
   */
  suppressIfProjectMatches?: RegExp;
}

export interface HttpRule {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  description: string;
  impact: string;
  remediation: string;
  safeExample?: string;
  reference?: string;
  check: (headers: Record<string, string>, body?: string) => boolean;
}

export interface ScannerContext {
  scanId: string;
  emit: (event: ScannerEvent) => void;
}

export interface ScannerEvent {
  type: 'log' | 'progress' | 'finding';
  level?: 'info' | 'warn' | 'error';
  message?: string;
  step?: string;
  progress?: number;
  finding?: Partial<Finding>;
}

export interface LocalScanOptions {
  projectPath: string;
  scanId: string;
  onEvent: (event: ScannerEvent) => void;
}

export interface UrlScanOptions {
  url: string;
  apiUrl?: string;
  customHeaders?: Record<string, string>;
  depth?: 'quick' | 'normal' | 'deep';
  scanId: string;
  onEvent: (event: ScannerEvent) => void;
}

export interface ScanResultRaw {
  findings: Array<Omit<Finding, 'id' | 'createdAt'>>;
  techStack: TechStack[];
  logs: Array<Omit<ScanLog, 'id' | 'createdAt'>>;
}

export type { Confidence };

export interface FileWalkResult {
  path: string;
  content: string;
  size: number;
  ext?: string;
  normPath?: string;
}

export interface DependencyIssue {
  package: string;
  version: string;
  issue: string;
  severity: Severity;
}
