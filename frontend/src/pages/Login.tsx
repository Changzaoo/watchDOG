import { FormEvent, useState } from 'react';
import { AlertTriangle, KeyRound, LogIn, Mail, ShieldCheck } from 'lucide-react';
import { AppLogo } from '../components/AppLogo';
import { api, AuthSession } from '../lib/api';

interface Props {
  onAuthenticated: (session: AuthSession) => void;
}

export function Login({ onAuthenticated }: Props) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError('');

    if (!email.trim() || !password) {
      setError('Informe email e senha.');
      return;
    }

    setLoading(true);
    try {
      const session = await api.login(email.trim(), password);
      onAuthenticated(session);
    } catch (err: any) {
      setError(err.message || 'Nao foi possivel entrar.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-dark-900 flex items-center justify-center px-3 py-6 sm:p-6">
      <div className="w-full max-w-md space-y-5 animate-fade-in">
        <div className="text-center">
          <AppLogo className="w-16 h-16 mx-auto rounded-xl bg-dark-850 ring-1 ring-blue-500/30" />
          <h1 className="mobile-page-title mt-4">watchDOG</h1>
          <p className="text-sm text-gray-500 mt-1">Acesso protegido pelo Firebase</p>
        </div>

        <form onSubmit={handleSubmit} className="card space-y-4">
          <div className="flex items-start gap-3 rounded-lg border border-cyan-900/40 bg-cyan-950/10 p-3">
            <ShieldCheck className="w-5 h-5 text-cyan-300 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-gray-400">
              Use uma conta que ja existe no Firebase. Cadastro de novos usuarios nao fica disponivel neste app.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                type="email"
                autoComplete="email"
                className="input pl-9"
                value={email}
                onChange={event => setEmail(event.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Senha</label>
            <div className="relative">
              <KeyRound className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                type="password"
                autoComplete="current-password"
                className="input pl-9"
                value={password}
                onChange={event => setPassword(event.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          {error && (
            <div className="flex items-start gap-2 text-red-300 bg-red-900/20 border border-red-800/50 rounded-lg px-3 py-2 text-sm">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="btn-primary touch-row w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Entrando...
              </>
            ) : (
              <>
                <LogIn className="w-4 h-4" />
                Entrar
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
