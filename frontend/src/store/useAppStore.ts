import { create } from 'zustand';
import { Scan, Finding, ScanLog } from '@sentinelscope/shared';

export interface AuthUser {
  uid: string;
  email?: string;
  name?: string;
}

interface AppState {
  scans: Scan[];
  currentScan: Scan | null;
  currentFindings: Finding[];
  currentLogs: ScanLog[];
  scanProgress: { step: string; progress: number } | null;
  backendOnline: boolean;
  backendHealthChecked: boolean;
  localScansEnabled: boolean;
  authChecked: boolean;
  authUser: AuthUser | null;

  setScans: (scans: Scan[]) => void;
  setCurrentScan: (scan: Scan | null) => void;
  setCurrentFindings: (findings: Finding[]) => void;
  setCurrentLogs: (logs: ScanLog[]) => void;
  addLog: (log: ScanLog) => void;
  setScanProgress: (p: { step: string; progress: number } | null) => void;
  setBackendOnline: (online: boolean) => void;
  setBackendHealthChecked: (checked: boolean) => void;
  setLocalScansEnabled: (enabled: boolean) => void;
  setAuthChecked: (checked: boolean) => void;
  setAuthUser: (user: AuthUser | null) => void;
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
  backendHealthChecked: false,
  localScansEnabled: false,
  authChecked: false,
  authUser: null,

  setScans: (scans) => set({ scans }),
  setCurrentScan: (scan) => set({ currentScan: scan }),
  setCurrentFindings: (findings) => set({ currentFindings: findings }),
  setCurrentLogs: (logs) => set({ currentLogs: logs }),
  addLog: (log) => set((state) => ({
    currentLogs: [...state.currentLogs.slice(-499), log],
  })),
  setScanProgress: (scanProgress) => set({ scanProgress }),
  setBackendOnline: (backendOnline) => set({ backendOnline }),
  setBackendHealthChecked: (backendHealthChecked) => set({ backendHealthChecked }),
  setLocalScansEnabled: (localScansEnabled) => set({ localScansEnabled }),
  setAuthChecked: (authChecked) => set({ authChecked }),
  setAuthUser: (authUser) => set({ authUser }),
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
