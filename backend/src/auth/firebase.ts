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

interface FirebaseAdminConfig {
  projectId: string;
  clientEmail: string;
  privateKey: string;
}

function env(name: string): string {
  return process.env[name]?.trim() || '';
}

function decodeBase64(value: string): string {
  try {
    return Buffer.from(value, 'base64').toString('utf8').trim();
  } catch {
    return '';
  }
}

function normalizePrivateKey(value?: string): string {
  return (value || '')
    .trim()
    .replace(/^"|"$/g, '')
    .replace(/\\n/g, '\n');
}

function parseServiceAccountJson(): FirebaseAdminConfig | null {
  const rawJson = env('FIREBASE_SERVICE_ACCOUNT_JSON') ||
    decodeBase64(env('FIREBASE_SERVICE_ACCOUNT_JSON_BASE64'));
  if (!rawJson) return null;

  try {
    const parsed = JSON.parse(rawJson) as Record<string, string | undefined>;
    const projectId = parsed.project_id || parsed.projectId || '';
    const clientEmail = parsed.client_email || parsed.clientEmail || '';
    const privateKey = normalizePrivateKey(parsed.private_key || parsed.privateKey);

    if (!projectId || !clientEmail || !privateKey) return null;
    return { projectId, clientEmail, privateKey };
  } catch {
    return null;
  }
}

function getFirebaseAdminConfig(): FirebaseAdminConfig | null {
  const serviceAccount = parseServiceAccountJson();
  if (serviceAccount) return serviceAccount;

  const projectId = env('FIREBASE_PROJECT_ID');
  const clientEmail = env('FIREBASE_CLIENT_EMAIL');
  const privateKey = normalizePrivateKey(env('FIREBASE_PRIVATE_KEY'));

  if (!projectId || !clientEmail || !privateKey) return null;
  return { projectId, clientEmail, privateKey };
}

export function getMissingAuthConfig(): string[] {
  const missing: string[] = [];

  if (!getFirebaseAdminConfig()) {
    missing.push(
      'FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_JSON_BASE64, or FIREBASE_PROJECT_ID + FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY'
    );
  }

  if (!env('FIREBASE_WEB_API_KEY')) {
    missing.push('FIREBASE_WEB_API_KEY');
  }

  return missing;
}

export function isAuthConfigured(): boolean {
  return getMissingAuthConfig().length === 0;
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
  const adminConfig = getFirebaseAdminConfig();
  if (!adminConfig) {
    throw new Error(`Firebase authentication is not configured: ${getMissingAuthConfig().join(', ')}`);
  }

  if (getApps().length === 0) {
    const serviceAccount: ServiceAccount = {
      projectId: adminConfig.projectId,
      clientEmail: adminConfig.clientEmail,
      privateKey: adminConfig.privateKey,
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
