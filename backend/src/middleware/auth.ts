import { NextFunction, Request, Response } from 'express';
import {
  getMissingAuthConfig,
  isAuthConfigured,
  isAuthRequiredForRequest,
  isCookieSecureForRequest,
  SESSION_COOKIE_NAME,
  verifySessionCookie,
} from '../auth/firebase';

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  if (!isAuthRequiredForRequest(req)) {
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
    (req as any).authUser = {
      uid: decoded.uid,
      email: decoded.email,
      name: decoded.name,
    };
    return next();
  } catch {
    res.clearCookie(SESSION_COOKIE_NAME, {
      httpOnly: true,
      secure: isCookieSecureForRequest(req),
      sameSite: 'lax',
      path: '/',
    });
    return res.status(401).json({ error: 'Sessao invalida ou expirada.' });
  }
}
