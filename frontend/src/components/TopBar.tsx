import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { LogOut, Radio } from 'lucide-react';
import { useAppStore } from '../store/useAppStore';
import { api } from '../lib/api';
import { cn } from '../lib/utils';

function titleForPath(pathname: string): string {
  if (pathname === '/' || pathname === '') return 'Visão de Mercado';
  if (pathname.startsWith('/scan/url')) return 'Novo Scan';
  if (pathname.startsWith('/scan/local')) return 'Scan Local';
  if (pathname.includes('/threat-model')) return 'Threat Model';
  if (pathname.includes('/defense-depth')) return 'Defense Depth';
  if (pathname.startsWith('/scans/')) return 'Resultado do Scan';
  if (pathname.startsWith('/history')) return 'Histórico';
  return 'watchDOG';
}

function useClock(): string {
  const [now, setNow] = useState<Date>(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return now.toLocaleTimeString('pt-BR', { hour12: false });
}

/**
 * Top bar no estilo do dashboard de referência: título da seção à esquerda;
 * status "AO VIVO" do backend, usuário, relógio e sair à direita.
 * Visível apenas em telas md+ (no mobile o header fica na Sidebar).
 */
export function TopBar() {
  const location = useLocation();
  const clock = useClock();
  const backendOnline = useAppStore(s => s.backendOnline);
  const authUser = useAppStore(s => s.authUser);
  const setAuthUser = useAppStore(s => s.setAuthUser);
  const setScans = useAppStore(s => s.setScans);

  async function handleLogout() {
    await api.logout().catch(() => {});
    setScans([]);
    setAuthUser(null);
  }

  const title = titleForPath(location.pathname);

  return (
    <header className="sticky top-0 z-20 hidden border-b border-dark-800 bg-dark-900/80 backdrop-blur md:block">
      <div className="flex h-14 items-center justify-between gap-4 px-6">
        <div className="flex min-w-0 items-center gap-2">
          <h1 className="truncate text-[15px] font-semibold text-white">{title}</h1>
        </div>

        <div className="flex items-center gap-3">
          <span className={cn('live-pill', backendOnline ? 'live-pill-on' : 'live-pill-off')}>
            <Radio className={cn('h-3 w-3', backendOnline && 'animate-live-pulse')} />
            {backendOnline ? 'Ao Vivo' : 'Offline'}
          </span>

          {authUser && (
            <div className="hidden items-center gap-2 rounded-lg border border-dark-800 bg-dark-850 px-2.5 py-1.5 lg:flex">
              <span className="grid h-6 w-6 place-items-center rounded-md bg-brand/15 text-[11px] font-bold text-brand">
                {(authUser.email || 'U').charAt(0).toUpperCase()}
              </span>
              <span className="max-w-[160px] truncate text-xs text-gray-300">{authUser.email || 'Usuário'}</span>
            </div>
          )}

          <span className="font-mono text-sm tabular-nums text-gray-400">{clock}</span>

          {authUser && (
            <button
              type="button"
              onClick={handleLogout}
              className="flex items-center gap-1.5 rounded-lg border border-dark-800 bg-dark-850 px-2.5 py-1.5 text-xs text-gray-300 transition-colors hover:border-red-800/50 hover:bg-red-900/20 hover:text-red-300"
              title="Sair"
            >
              <LogOut className="h-3.5 w-3.5" />
              Sair
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
