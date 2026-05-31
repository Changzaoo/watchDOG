import { NextFunction, Request, Response } from 'express';
import {
  getMissingAuthConfig,
  isAuthConfigured,
  isEmailAllowed,
  isAuthRequired,
  SESSION_COOKIE_NAME,
  verifySessionCookie,
} from '../auth/firebase';

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  if (!isAuthRequired()) {
    (req as any).authUser = {
      uid: 'local-dev',
      email: 'local@watchdog.local',
      name: 'Local Development',
    };
    return next();
  }

  if (!isAuthConfigured()) {
    return res.status(503).json({
      error: 'Autenticacao Firebase nao configurada no backend.',
      detail: 'Configure a service account do Firebase e FIREBASE_WEB_API_KEY no ambiente do backend.',
      missing: getMissingAuthConfig(),
    });
  }

  const sessionCookie = req.cookies?.[SESSION_COOKIE_NAME];
  if (!sessionCookie) {
    return res.status(401).json({ error: 'Sessao obrigatoria.' });
  }

  try {
    const decoded = await verifySessionCookie(sessionCookie);
    if (!isEmailAllowed(decoded.email)) {
      return res.status(403).json({
        error: 'Usuario nao autorizado.',
        detail: 'Defina AUTH_ALLOWED_EMAILS com seu email ou use AUTH_ALLOW_ALL_USERS=true conscientemente.',
      });
    }

    (req as any).authUser = {
      uid: decoded.uid,
      email: decoded.email,
      name: decoded.name,
    };
    return next();
  } catch {
    res.clearCookie(SESSION_COOKIE_NAME, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    });
    return res.status(401).json({ error: 'Sessao invalida ou expirada.' });
  }
}
