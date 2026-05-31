import { useEffect } from 'react';
import { Navigate, Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { ScanLocal } from './pages/ScanLocal';
import { ScanUrl } from './pages/ScanUrl';
import { ScanResult } from './pages/ScanResult';
import { History } from './pages/History';
import { Login } from './pages/Login';
import { ThreatModel } from './pages/ThreatModel';
import { DefenseDepth } from './pages/DefenseDepth';
import { useAppStore } from './store/useAppStore';
import { api, AuthSession } from './lib/api';

function LocalOnlyRoute({ children }: { children: JSX.Element }) {
  const { backendHealthChecked, localScansEnabled } = useAppStore();

  if (!backendHealthChecked) {
    return (
      <div className="flex items-center justify-center min-h-96 text-sm text-gray-500">
        Verificando disponibilidade...
      </div>
    );
  }

  if (!localScansEnabled) {
    return <Navigate to="/scan/url" replace />;
  }

  return children;
}

function AuthGate({ children }: { children: JSX.Element }) {
  const { authChecked, authUser, setAuthChecked, setAuthUser } = useAppStore();

  useEffect(() => {
    let cancelled = false;

    api.getAuthSession()
      .then(session => {
        if (cancelled) return;
        setAuthUser(session.authenticated ? session.user || null : null);
      })
      .catch(() => {
        if (!cancelled) setAuthUser(null);
      })
      .finally(() => {
        if (!cancelled) setAuthChecked(true);
      });

    return () => {
      cancelled = true;
    };
  }, [setAuthChecked, setAuthUser]);

  function handleAuthenticated(session: AuthSession) {
    setAuthUser(session.authenticated ? session.user || null : null);
    setAuthChecked(true);
  }

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-dark-900 flex items-center justify-center">
        <div className="text-sm text-gray-500">Verificando sessao...</div>
      </div>
    );
  }

  if (!authUser) {
    return <Login onAuthenticated={handleAuthenticated} />;
  }

  return children;
}

export default function App() {
  return (
    <AuthGate>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="scan/new" element={<Navigate to="/scan/url" replace />} />
          <Route path="scan/local" element={<LocalOnlyRoute><ScanLocal /></LocalOnlyRoute>} />
          <Route path="scan/url" element={<ScanUrl />} />
          <Route path="scans/:id" element={<ScanResult />} />
          <Route path="scans/:id/threat-model" element={<ThreatModel />} />
          <Route path="scans/:id/defense-depth" element={<DefenseDepth />} />
          <Route path="history" element={<History />} />
          <Route path="*" element={<Dashboard />} />
        </Route>
      </Routes>
    </AuthGate>
  );
}
