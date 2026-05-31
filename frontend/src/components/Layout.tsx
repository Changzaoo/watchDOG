import { useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { useAppStore } from '../store/useAppStore';
import { checkBackendHealth, api } from '../lib/api';

export function Layout() {
  const { setBackendOnline, setScans } = useAppStore();

  useEffect(() => {
    // Check backend health
    const check = async () => {
      const online = await checkBackendHealth();
      setBackendOnline(online);
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
