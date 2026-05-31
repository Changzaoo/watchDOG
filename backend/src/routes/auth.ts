import { Router } from 'express';
import { z } from 'zod';
import {
  createSessionCookie,
  isAuthConfigured,
  isEmailAllowed,
  isAuthRequired,
  SESSION_COOKIE_NAME,
  SESSION_MAX_AGE_MS,
  signInWithPassword,
  verifySessionCookie,
} from '../auth/firebase';

export const authRouter = Router();

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

function cookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    path: '/',
    maxAge: SESSION_MAX_AGE_MS,
  };
}

authRouter.get('/me', async (req, res) => {
  if (!isAuthRequired()) {
    return res.json({
      authenticated: true,
      authConfigured: isAuthConfigured(),
      authRequired: false,
      user: {
        uid: 'local-dev',
        email: 'local@watchdog.local',
        name: 'Local Development',
      },
    });
  }

  if (!isAuthConfigured()) {
    return res.json({ authenticated: false, authConfigured: false, authRequired: true });
  }

  const sessionCookie = req.cookies?.[SESSION_COOKIE_NAME];
  if (!sessionCookie) {
    return res.json({ authenticated: false, authConfigured: true, authRequired: true });
  }

  try {
    const decoded = await verifySessionCookie(sessionCookie);
    if (!isEmailAllowed(decoded.email)) {
      return res.json({ authenticated: false, authConfigured: true, authRequired: true });
    }

    return res.json({
      authenticated: true,
      authConfigured: true,
      authRequired: true,
      user: {
        uid: decoded.uid,
        email: decoded.email,
        name: decoded.name,
      },
    });
  } catch {
    res.clearCookie(SESSION_COOKIE_NAME, cookieOptions());
    return res.json({ authenticated: false, authConfigured: true, authRequired: true });
  }
});

authRouter.post('/login', async (req, res) => {
  if (!isAuthRequired()) {
    return res.json({
      authenticated: true,
      authConfigured: isAuthConfigured(),
      authRequired: false,
      user: {
        uid: 'local-dev',
        email: 'local@watchdog.local',
        name: 'Local Development',
      },
    });
  }

  if (!isAuthConfigured()) {
    return res.status(503).json({ error: 'Autenticacao Firebase nao configurada no backend.' });
  }

  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  try {
    const login = await signInWithPassword(parsed.data.email, parsed.data.password);
    if (!isEmailAllowed(login.email)) {
      return res.status(403).json({ error: 'Usuario nao autorizado.' });
    }

    const sessionCookie = await createSessionCookie(login.idToken);
    res.cookie(SESSION_COOKIE_NAME, sessionCookie, cookieOptions());
    return res.json({
      authenticated: true,
      authConfigured: true,
      authRequired: true,
      user: {
        uid: login.localId,
        email: login.email,
        name: login.displayName,
      },
    });
  } catch {
    return res.status(401).json({ error: 'Email ou senha invalidos.' });
  }
});

authRouter.post('/logout', (_req, res) => {
  res.clearCookie(SESSION_COOKIE_NAME, cookieOptions());
  res.json({ ok: true });
});
