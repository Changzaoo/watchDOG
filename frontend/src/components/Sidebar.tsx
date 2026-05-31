import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, PlusCircle, History, Settings,
  HelpCircle, Shield, Wifi, WifiOff
} from 'lucide-react';
import { useAppStore } from '../store/useAppStore';
import { cn } from '../lib/utils';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/scan/new', label: 'Novo Scan', icon: PlusCircle },
  { to: '/history', label: 'Histórico', icon: History },
  { to: '/settings', label: 'Configurações', icon: Settings },
  { to: '/help', label: 'Ajuda', icon: HelpCircle },
];

export function Sidebar() {
  const backendOnline = useAppStore(s => s.backendOnline);

  return (
    <aside className="w-60 bg-dark-850 border-r border-dark-800 flex flex-col h-screen sticky top-0 flex-shrink-0">
      {/* Logo */}
      <div className="p-4 border-b border-dark-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-violet-600 to-cyan-500 flex items-center justify-center">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="font-bold text-white text-sm tracking-wide">watchDOG</div>
            <div className="text-xs text-gray-500">Security Auditor</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-1">
        {NAV_ITEMS.map(({ to, label, icon: Icon, exact }) => (
          <NavLink
            key={to}
            to={to}
            end={exact}
            className={({ isActive }) => cn('sidebar-item', isActive && 'active')}
          >
            <Icon className="w-4 h-4" />
            <span className="text-sm">{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Backend status */}
      <div className="p-4 border-t border-dark-800">
        <div className={cn(
          'flex items-center gap-2 text-xs px-3 py-2 rounded-lg',
          backendOnline
            ? 'bg-green-900/20 text-green-400 border border-green-800/30'
            : 'bg-red-900/20 text-red-400 border border-red-800/30'
        )}>
          {backendOnline
            ? <><Wifi className="w-3 h-3" /> Backend online</>
            : <><WifiOff className="w-3 h-3" /> Backend offline</>}
        </div>
        <div className="mt-2 text-xs text-gray-600 text-center">v1.0.0</div>
      </div>
    </aside>
  );
}
