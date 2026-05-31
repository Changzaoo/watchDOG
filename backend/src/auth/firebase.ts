import { cert, getApps, initializeApp, ServiceAccount } from 'firebase-admin/app';
import { DecodedIdToken, getAuth } from 'firebase-admin/auth';

export const SESSION_COOKIE_NAME = 'watchdog_session';
export const SESSION_MAX_AGE_MS = 5 * 24 * 60 * 60 * 1000;

interface FirebaseLoginResponse {
  idToken: string;
  localId: string;
  email?: string;
  displayName?: string;
}

function env(name: string): string {
  return process.env[name]?.trim() || '';
}

function privateKey(): string {
  return env('FIREBASE_PRIVATE_KEY').replace(/\\n/g, '\n');
}

export function isAuthConfigured(): boolean {
  return Boolean(
    env('FIREBASE_PROJECT_ID') &&
    env('FIREBASE_CLIENT_EMAIL') &&
    privateKey() &&
    env('FIREBASE_WEB_API_KEY')
  );
}

export function isAuthRequired(): boolean {
  return process.env.NODE_ENV === 'production' || env('AUTH_REQUIRED') === 'true';
}

export function getAllowedEmails(): Set<string> {
  return new Set(
    env('AUTH_ALLOWED_EMAILS')
      .split(',')
      .map(email => email.trim().toLowerCase())
      .filter(Boolean)
  );
}

export function isEmailAllowed(email?: string): boolean {
  const allowed = getAllowedEmails();
  if (allowed.size === 0) return true;
  return Boolean(email && allowed.has(email.toLowerCase()));
}

export function getFirebaseAuth() {
  if (!isAuthConfigured()) {
    throw new Error('Firebase authentication is not configured');
  }

  if (getApps().length === 0) {
    const serviceAccount: ServiceAccount = {
      projectId: env('FIREBASE_PROJECT_ID'),
      clientEmail: env('FIREBASE_CLIENT_EMAIL'),
      privateKey: privateKey(),
    };

    initializeApp({
      credential: cert(serviceAccount),
    });
  }

  return getAuth();
}

export async function signInWithPassword(email: string, password: string): Promise<FirebaseLoginResponse> {
  const apiKey = env('FIREBASE_WEB_API_KEY');
  if (!apiKey) {
    throw new Error('Firebase Web API key is not configured');
  }

  const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      password,
      returnSecureToken: true,
    }),
  });

  const data = await response.json().catch(() => ({})) as Partial<FirebaseLoginResponse> & {
    error?: { message?: string };
  };
  if (!response.ok || !data.idToken) {
    throw new Error(data?.error?.message || 'INVALID_LOGIN');
  }

  return data as FirebaseLoginResponse;
}

export async function createSessionCookie(idToken: string): Promise<string> {
  return getFirebaseAuth().createSessionCookie(idToken, { expiresIn: SESSION_MAX_AGE_MS });
}

export async function verifySessionCookie(sessionCookie: string): Promise<DecodedIdToken> {
  return getFirebaseAuth().verifySessionCookie(sessionCookie, true);
}
