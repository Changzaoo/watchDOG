export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type FindingStatus = 'open' | 'ignored' | 'fixed' | 'false_positive';
export type ScanType = 'local' | 'url' | 'api';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type LogLevel = 'info' | 'warn' | 'error' | 'debug';

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface TechStack {
  name: string;
  version?: string;
  category: 'frontend' | 'backend' | 'database' | 'devops' | 'web3' | 'other';
}

export interface Scan {
  id: string;
  type: ScanType;
  target: string;
  projectName: string;
  score: number;
  status: ScanStatus;
  startedAt: string;
  finishedAt?: string;
  durationMs?: number;
  techStack: TechStack[];
  summary: ScanSummary;
}

export interface Finding {
  id: string;
  scanId: string;
  ruleId: string;
  title: string;
  severity: Severity;
  category: string;
  confidence: Confidence;
  filePath?: string;
  url?: string;
  line?: number;
  evidenceMasked?: string;
  description: string;
  impact: string;
  attackScenarioDefensive?: string;
  remediation: string;
  safeExample?: string;
  fixPrompt?: string;
  testSuggestion?: string;
  reference?: string;
  status: FindingStatus;
  userNote?: string;
  occurrences: number;
  createdAt: string;
}

export interface ThreatModelData {
  id: string;
  scanId: string;
  assets: string[];
  attackers: string[];
  attackSurfaces: string[];
  controls: string[];
  gaps: ThreatGap[];
}

export interface ThreatGap {
  findingId?: string;
  ruleId: string;
  title: string;
  brokenControl: string;
  risk: string;
  fix: string;
}

export type DefenseLayerStatus = 'healthy' | 'warning' | 'critical' | 'unknown';

export interface DefenseLayerData {
  id: string;
  scanId: string;
  name: string;
  status: DefenseLayerStatus;
  issuesCount: number;
  summary: string;
}

export interface ScanLog {
  id: string;
  scanId: string;
  level: LogLevel;
  message: string;
  createdAt: string;
}

export interface ScanProgressEvent {
  scanId: string;
  step: string;
  progress: number;
  message: string;
}

export interface Rule {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  description: string;
  impact: string;
  remediation: string;
  safeExample?: string;
  reference?: string;
}

export interface FileRule extends Rule {
  patterns: RegExp[];
  fileExtensions?: string[];
  fileNamePatterns?: RegExp[];
}

export interface HttpRule extends Rule {
  check: (headers: Record<string, string>, body?: string) => boolean;
}

export interface LocalScanRequest {
  path: string;
  projectName?: string;
}

export interface UrlScanRequest {
  url: string;
  apiUrl?: string;
  customHeaders?: Record<string, string>;
  depth?: 'quick' | 'normal' | 'deep';
}

export interface ScanResult {
  scan: Scan;
  findings: Finding[];
  logs: ScanLog[];
}

export interface ExportOptions {
  format: 'json' | 'markdown' | 'pdf';
  includeFixed?: boolean;
  includeIgnored?: boolean;
}

export interface DashboardStats {
  totalScans: number;
  lastScan?: Scan;
  averageScore: number;
  totalFindings: ScanSummary;
  recentScans: Scan[];
}

export interface FileNode {
  name: string;
  path: string;
  type: 'file' | 'directory';
  children?: FileNode[];
  size?: number;
}

export interface UpdateFindingStatusRequest {
  status: FindingStatus;
}

export interface ScanEvent {
  type: 'log' | 'progress' | 'complete' | 'error';
  data: ScanLog | ScanProgressEvent | Scan | { message: string };
}
