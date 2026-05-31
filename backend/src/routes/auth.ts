import { Router } from 'express';
import { z } from 'zod';
import {
  createSessionCookie,
  FirebasePasswordSignInError,
  getMissingAuthConfig,
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

function firebaseConfigError() {
  return {
    error: 'Autenticacao Firebase nao configurada no backend.',
    detail: 'Configure a service account do Firebase e FIREBASE_WEB_API_KEY no ambiente do backend.',
    missing: getMissingAuthConfig(),
  };
}

function firebaseLoginError(error: unknown) {
  if (!(error instanceof FirebasePasswordSignInError)) {
    return { status: 401, body: { error: 'Email ou senha invalidos.' } };
  }

  const code = error.code;
  const messages: Record<string, { status: number; error: string; detail?: string }> = {
    EMAIL_NOT_FOUND: {
      status: 401,
      error: 'Usuario nao encontrado no Firebase Auth.',
      detail: 'Crie este email em Authentication > Users ou use uma conta existente.',
    },
    INVALID_PASSWORD: {
      status: 401,
      error: 'Senha invalida para este usuario.',
    },
    INVALID_LOGIN_CREDENTIALS: {
      status: 401,
      error: 'Email ou senha invalidos.',
    },
    USER_DISABLED: {
      status: 403,
      error: 'Usuario desativado no Firebase Auth.',
    },
    OPERATION_NOT_ALLOWED: {
      status: 503,
      error: 'Login por email e senha esta desativado no Firebase Auth.',
      detail: 'Ative Email/Password em Authentication > Sign-in method.',
    },
    API_KEY_INVALID: {
      status: 503,
      error: 'FIREBASE_WEB_API_KEY invalida para este projeto Firebase.',
    },
  };

  const mapped = messages[code] || {
    status: 401,
    error: 'Firebase recusou o login.',
    detail: code,
  };

  return {
    status: mapped.status,
    body: {
      error: mapped.error,
      ...(mapped.detail ? { detail: mapped.detail } : {}),
    },
  };
}

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
    return res.status(503).json(firebaseConfigError());
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
  } catch (error) {
    const mapped = firebaseLoginError(error);
    return res.status(mapped.status).json(mapped.body);
  }
});

authRouter.post('/logout', (_req, res) => {
  res.clearCookie(SESSION_COOKIE_NAME, cookieOptions());
  res.json({ ok: true });
});
