import { create } from 'zustand';
import { Scan, Finding, ScanLog } from '@sentinelscope/shared';

interface AppState {
  scans: Scan[];
  currentScan: Scan | null;
  currentFindings: Finding[];
  currentLogs: ScanLog[];
  scanProgress: { step: string; progress: number } | null;
  backendOnline: boolean;

  setScans: (scans: Scan[]) => void;
  setCurrentScan: (scan: Scan | null) => void;
  setCurrentFindings: (findings: Finding[]) => void;
  setCurrentLogs: (logs: ScanLog[]) => void;
  addLog: (log: ScanLog) => void;
  setScanProgress: (p: { step: string; progress: number } | null) => void;
  setBackendOnline: (online: boolean) => void;
  updateFindingStatus: (findingId: string, status: string) => void;
  updateFindingNote: (findingId: string, note: string) => void;
}

export const useAppStore = create<AppState>((set) => ({
  scans: [],
  currentScan: null,
  currentFindings: [],
  currentLogs: [],
  scanProgress: null,
  backendOnline: false,

  setScans: (scans) => set({ scans }),
  setCurrentScan: (scan) => set({ currentScan: scan }),
  setCurrentFindings: (findings) => set({ currentFindings: findings }),
  setCurrentLogs: (logs) => set({ currentLogs: logs }),
  addLog: (log) => set((state) => ({
    currentLogs: [...state.currentLogs.slice(-499), log],
  })),
  setScanProgress: (scanProgress) => set({ scanProgress }),
  setBackendOnline: (backendOnline) => set({ backendOnline }),
  updateFindingStatus: (findingId, status) =>
    set((state) => ({
      currentFindings: state.currentFindings.map(f =>
        f.id === findingId ? { ...f, status: status as any } : f
      ),
    })),
  updateFindingNote: (findingId, note) =>
    set((state) => ({
      currentFindings: state.currentFindings.map(f =>
        f.id === findingId ? { ...f, userNote: note } : f
      ),
    })),
}));
