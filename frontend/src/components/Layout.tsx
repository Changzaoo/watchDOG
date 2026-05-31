import { useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { useAppStore } from '../store/useAppStore';
import { getBackendHealth, api } from '../lib/api';

export function Layout() {
  const { setBackendOnline, setBackendHealthChecked, setLocalScansEnabled, setScans } = useAppStore();

  useEffect(() => {
    // Check backend health
    const check = async () => {
      const health = await getBackendHealth();
      const online = Boolean(health);
      setBackendOnline(online);
      setLocalScansEnabled(Boolean(health?.localScansEnabled));
      setBackendHealthChecked(true);
      if (online) {
        try {
          const scans = await api.getScans();
          setScans(scans);
        } catch {}
      }
    };

    check();
    const interval = setInterval(check, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex min-h-screen bg-dark-900">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-7xl mx-auto p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
