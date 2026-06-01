import { Router } from 'express';
import { z } from 'zod';
import {
  createSessionCookie,
  FirebasePasswordSignInError,
  getMissingAuthConfig,
  isAuthConfigured,
  isAuthRequiredForRequest,
  isCookieSecureForRequest,
  SESSION_COOKIE_NAME,
  SESSION_MAX_AGE_MS,
  signInWithPassword,
  verifySessionCookie,
} from '../auth/firebase';
import {
  getLoginBlock,
  getRequestIp,
  normalizeLoginEmail,
  recordLoginFailure,
  recordLoginSuccess,
} from '../auth/loginProtection';

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
  if (code === 'TOO_MANY_ATTEMPTS_TRY_LATER') {
    return {
      status: 429,
      body: {
        error: 'Muitas tentativas de login. Aguarde alguns minutos e tente novamente.',
      },
    };
  }

  const messages: Record<string, { status: number; error: string; detail?: string }> = {
    EMAIL_NOT_FOUND: {
      status: 401,
      error: 'Email ou senha invalidos.',
    },
    INVALID_PASSWORD: {
      status: 401,
      error: 'Email ou senha invalidos.',
    },
    INVALID_LOGIN_CREDENTIALS: {
      status: 401,
      error: 'Email ou senha invalidos.',
    },
    USER_DISABLED: {
      status: 401,
      error: 'Email ou senha invalidos.',
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

function shouldRecordLoginFailure(error: unknown): boolean {
  if (!(error instanceof FirebasePasswordSignInError)) return true;
  return !['OPERATION_NOT_ALLOWED', 'API_KEY_INVALID'].includes(error.code);
}

function loginLockoutError(retryAfterSeconds: number) {
  return {
    error: 'Muitas tentativas de login. Aguarde alguns minutos e tente novamente.',
    retryAfterSeconds,
  };
}

function cookieOptions(req?: any) {
  return {
    httpOnly: true,
    secure: isCookieSecureForRequest(req),
    sameSite: 'lax' as const,
    path: '/',
    maxAge: SESSION_MAX_AGE_MS,
  };
}

authRouter.get('/me', async (req, res) => {
  if (!isAuthRequiredForRequest(req)) {
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
    res.clearCookie(SESSION_COOKIE_NAME, cookieOptions(req));
    return res.json({ authenticated: false, authConfigured: true, authRequired: true });
  }
});

authRouter.post('/login', async (req, res) => {
  if (!isAuthRequiredForRequest(req)) {
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

  const email = normalizeLoginEmail(parsed.data.email);
  const clientIp = getRequestIp(req);
  const lock = getLoginBlock(email, clientIp);
  if (lock) {
    res.setHeader('Retry-After', String(lock.retryAfterSeconds));
    return res.status(429).json(loginLockoutError(lock.retryAfterSeconds));
  }

  try {
    const login = await signInWithPassword(email, parsed.data.password);
    recordLoginSuccess(email);

    const sessionCookie = await createSessionCookie(login.idToken);
    res.cookie(SESSION_COOKIE_NAME, sessionCookie, cookieOptions(req));
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
    if (shouldRecordLoginFailure(error)) {
      recordLoginFailure(email, clientIp);
      const lockAfterFailure = getLoginBlock(email, clientIp);
      if (lockAfterFailure) {
        res.setHeader('Retry-After', String(lockAfterFailure.retryAfterSeconds));
        return res.status(429).json(loginLockoutError(lockAfterFailure.retryAfterSeconds));
      }
    }

    const mapped = firebaseLoginError(error);
    return res.status(mapped.status).json(mapped.body);
  }
});

authRouter.post('/logout', (req, res) => {
  res.clearCookie(SESSION_COOKIE_NAME, cookieOptions(req));
  res.json({ ok: true });
});
