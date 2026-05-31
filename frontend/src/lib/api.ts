import { Scan, Finding, ScanLog, ThreatModelData, DefenseLayerData } from '@sentinelscope/shared';

const API_ORIGIN = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');
const BASE = API_ORIGIN ? `${API_ORIGIN}/api` : '/api';
const HEALTH_URL = API_ORIGIN ? `${API_ORIGIN}/health` : '/health';

async function fetchJson<T>(url: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(BASE + url, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export interface ScanWithDetails {
  scan: Scan;
  findings: Finding[];
  logs: ScanLog[];
}

export const api = {
  getScans: () => fetchJson<Scan[]>('/scans'),

  getScan: (id: string) => fetchJson<ScanWithDetails>(`/scans/${id}`),

  getThreatModel: (id: string) => fetchJson<ThreatModelData>(`/scans/${id}/threat-model`),

  getDefenseDepth: (id: string) => fetchJson<DefenseLayerData[]>(`/scans/${id}/defense-depth`),

  startLocalScan: (path: string, projectName?: string) =>
    fetchJson<{ scanId: string }>('/scans/local', {
      method: 'POST',
      body: JSON.stringify({ path, projectName }),
    }),

  startUrlScan: (url: string, opts?: { depth?: string; authorized: boolean }) =>
    fetchJson<{ scanId: string }>('/scans/url', {
      method: 'POST',
      body: JSON.stringify({ url, depth: opts?.depth || 'normal', authorized: opts?.authorized }),
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

  listenScanEvents: (scanId: string, onEvent: (event: any) => void): EventSource => {
    const es = new EventSource(`${BASE}/events/scans/${scanId}`);
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        onEvent(data);
      } catch {}
    };
    return es;
  },
};

export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(3000) });
    return res.ok;
  } catch {
    return false;
  }
}
