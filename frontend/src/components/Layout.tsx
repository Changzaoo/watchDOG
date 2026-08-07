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
    <div className="min-h-screen bg-dark-900 md:flex">
      <Sidebar />
      <main className="min-w-0 flex-1 overflow-y-auto pt-16 pb-24 md:pt-0 md:pb-0">
        <div className="mx-auto w-full max-w-7xl px-3 py-4 sm:px-4 sm:py-5 md:p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
