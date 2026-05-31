import { Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { NewScan } from './pages/NewScan';
import { ScanLocal } from './pages/ScanLocal';
import { ScanUrl } from './pages/ScanUrl';
import { ScanResult } from './pages/ScanResult';
import { History } from './pages/History';
import { Settings } from './pages/Settings';
import { Help } from './pages/Help';
import { ThreatModel } from './pages/ThreatModel';
import { DefenseDepth } from './pages/DefenseDepth';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="scan/new" element={<NewScan />} />
        <Route path="scan/local" element={<ScanLocal />} />
        <Route path="scan/url" element={<ScanUrl />} />
        <Route path="scans/:id" element={<ScanResult />} />
        <Route path="scans/:id/threat-model" element={<ThreatModel />} />
        <Route path="scans/:id/defense-depth" element={<DefenseDepth />} />
        <Route path="history" element={<History />} />
        <Route path="settings" element={<Settings />} />
        <Route path="help" element={<Help />} />
        <Route path="*" element={<Dashboard />} />
      </Route>
    </Routes>
  );
}
