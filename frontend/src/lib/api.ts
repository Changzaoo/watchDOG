import { Scan, Finding, ScanLog, ThreatModelData, DefenseLayerData } from '@sentinelscope/shared';

const __wdEnv = ((import.meta as any).env) || {};
const API_ROOT = (__wdEnv.VITE_API_URL || '');
const BASE = API_ROOT ? (API_ROOT + '/api') : '/api';
const HEALTH_URL = API_ROOT ? (API_ROOT + '/health') : '/health';
const NGROK_SKIP_WARNING_HEADER = 'ngrok-skip-browser-warning';

export interface BackendHealth {
  status: string;
  version: string;
  localScansEnabled: boolean;
  authRequired: boolean;
  authConfigured: boolean;
  authMissingConfig?: string[];
  timestamp: string;
}

export interface AuthUser {
  uid: string;
  email?: string;
  name?: string;
}

export interface AuthSession {
  authenticated: boolean;
  authConfigured: boolean;
  authRequired: boolean;
  user?: AuthUser;
}

function formatApiError(err: any, fallback: string): string {
  if (!err) return fallback;
  const missing = Array.isArray(err.missing) && err.missing.length
    ? ` Faltando: ${err.missing.join(', ')}.`
    : '';
  if (typeof err.error === 'string') {
    const message = err.detail ? `${err.error}: ${err.detail}` : err.error;
    return `${message}${missing}`;
  }
  const fieldErrors = err.error?.fieldErrors;
  if (fieldErrors && typeof fieldErrors === 'object') {
    const first = Object.values(fieldErrors).flat().find(Boolean);
    if (first) return String(first);
  }
  if (typeof err.detail === 'string') return err.detail;
  return fallback;
}

function buildHeaders(headers?: HeadersInit, json = false): Headers {
  const nextHeaders = new Headers(headers);
  nextHeaders.set(NGROK_SKIP_WARNING_HEADER, 'true');
  if (json && !nextHeaders.has('Content-Type')) {
    nextHeaders.set('Content-Type', 'application/json');
  }
  return nextHeaders;
}

async function fetchJson<T>(url: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(BASE + url, {
    ...opts,
    headers: buildHeaders(opts?.headers, true),
    credentials: 'same-origin',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(formatApiError(err, `HTTP ${res.status}`));
  }
  return res.json();
}

function getFilenameFromDisposition(disposition: string | null, fallback: string): string {
  const match = disposition?.match(/filename="?([^";]+)"?/i);
  return match?.[1] || fallback;
}

async function downloadFromApi(url: string, fallbackFilename: string): Promise<void> {
  const res = await fetch(url, {
    headers: buildHeaders(),
    credentials: 'same-origin',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(formatApiError(err, `HTTP ${res.status}`));
  }

  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = getFilenameFromDisposition(
    res.headers.get('Content-Disposition'),
    fallbackFilename
  );
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}

export interface ScanEventSubscription {
  close: () => void;
}

function handleSseBlock(block: string, onEvent: (event: any) => void) {
  const data = block
    .split(/\r?\n/)
    .filter(line => line.startsWith('data:'))
    .map(line => line.slice(5).trimStart())
    .join('\n');

  if (!data) return;

  try {
    onEvent(JSON.parse(data));
  } catch {}
}

function listenWithFetchSse(url: string, onEvent: (event: any) => void): ScanEventSubscription {
  const controller = new AbortController();

  fetch(url, {
    headers: buildHeaders(),
    credentials: 'same-origin',
    signal: controller.signal,
  }).then(async (res) => {
    if (!res.ok || !res.body) return;

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (!controller.signal.aborted) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const blocks = buffer.split(/\r?\n\r?\n/);
      buffer = blocks.pop() || '';
      for (const block of blocks) {
        handleSseBlock(block, onEvent);
      }
    }
  }).catch(() => {});

  return {
    close: () => controller.abort(),
  };
}

export interface ScanWithDetails {
  scan: Scan;
  findings: Finding[];
  logs: ScanLog[];
}

export const api = {
  getAuthSession: () => fetchJson<AuthSession>('/auth/me'),

  login: (email: string, password: string) =>
    fetchJson<AuthSession>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  logout: () =>
    fetchJson<{ ok: boolean }>('/auth/logout', {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  getScans: () => fetchJson<Scan[]>('/scans'),

  getScan: (id: string) => fetchJson<ScanWithDetails>(`/scans/${id}`),

  getThreatModel: (id: string) => fetchJson<ThreatModelData>(`/scans/${id}/threat-model`),

  getDefenseDepth: (id: string) => fetchJson<DefenseLayerData[]>(`/scans/${id}/defense-depth`),

  startLocalScan: (path: string, projectName?: string) =>
    fetchJson<{ scanId: string }>('/scans/local', {
      method: 'POST',
      body: JSON.stringify({ path, projectName }),
    }),

  startUrlScan: (url: string, opts?: { depth?: string }) =>
    fetchJson<{ scanId: string }>('/scans/url', {
      method: 'POST',
      body: JSON.stringify({ url, depth: opts?.depth || 'normal' }),
    }),

  updateFindingStatus: (id: string, status: string) =>
    fetchJson(`/findings/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),

  updateFindingNote: (id: string, note: string) =>
    fetchJson<Finding>(`/findings/${id}/note`, {
      method: 'PATCH',
      body: JSON.stringify({ note }),
    }),

  exportJson: (scanId: string) => `${BASE}/scans/${scanId}/export/json`,
  exportMarkdown: (scanId: string) => `${BASE}/scans/${scanId}/export/markdown`,
  exportPdf: (scanId: string) => `${BASE}/scans/${scanId}/export/pdf`,
  exportChecklist: (scanId: string) => `${BASE}/scans/${scanId}/export/checklist`,
  downloadExport: (scanId: string, format: 'json' | 'markdown' | 'pdf' | 'checklist') => {
    const url = format === 'json'
      ? api.exportJson(scanId)
      : format === 'markdown'
      ? api.exportMarkdown(scanId)
      : format === 'checklist'
      ? api.exportChecklist(scanId)
      : api.exportPdf(scanId);
    return downloadFromApi(url, `watchdog-${scanId}.${format === 'pdf' ? 'pdf' : format === 'json' ? 'json' : 'md'}`);
  },

  listenScanEvents: (scanId: string, onEvent: (event: any) => void): ScanEventSubscription =>
    listenWithFetchSse(`${BASE}/events/scans/${scanId}`, onEvent),
};

export async function checkBackendHealth(): Promise<boolean> {
  const health = await getBackendHealth();
  return Boolean(health);
}

export async function getBackendHealth(): Promise<BackendHealth | null> {
  try {
    const res = await fetch(HEALTH_URL, {
      headers: buildHeaders(),
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}
