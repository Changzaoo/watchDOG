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

export class FirebasePasswordSignInError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = 'FirebasePasswordSignInError';
  }
}

interface FirebaseAdminConfig {
  projectId: string;
  clientEmail: string;
  privateKey: string;
}

function env(name: string): string {
  return process.env[name]?.trim() || '';
}

type HeaderValue = string | string[] | undefined;

interface RequestLike {
  headers?: Record<string, HeaderValue>;
  get?: (name: string) => string | undefined;
}

function readHeader(req: RequestLike | undefined, name: string): string {
  if (!req) return '';

  const fromGetter = req.get?.(name);
  if (fromGetter) return fromGetter;

  const value = req.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value.join(',') : value || '';
}

function hostFromUrl(value: string): string {
  try {
    return new URL(value).host;
  } catch {
    return value;
  }
}

function normalizeHost(value: string): string {
  const host = hostFromUrl(value)
    .trim()
    .toLowerCase()
    .replace(/^\[/, '')
    .replace(/\]$/, '');

  if (!host) return '';
  const colonAt = host.lastIndexOf(':');
  return colonAt > -1 ? host.slice(0, colonAt) : host;
}

function splitHeaderValues(value: string): string[] {
  return value
    .split(',')
    .map(part => part.trim())
    .filter(Boolean);
}

function forwardedHosts(value: string): string[] {
  return splitHeaderValues(value)
    .flatMap(part => part.split(';').map(item => item.trim()))
    .filter(part => /^host=/i.test(part))
    .map(part => part.slice(part.indexOf('=') + 1).replace(/^"|"$/g, ''));
}

function isLocalRequestHost(value: string): boolean {
  const host = normalizeHost(value);
  return !host ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '127.0.0.1' ||
    host === '0.0.0.0' ||
    host === '::1';
}

export function isPublicRequest(req?: RequestLike): boolean {
  const configuredPublicHosts = (process.env.PUBLIC_REQUEST_HOSTS || '')
    .split(',')
    .map(normalizeHost)
    .filter(Boolean);

  const candidates = [
    ...splitHeaderValues(readHeader(req, 'host')),
    ...splitHeaderValues(readHeader(req, 'x-forwarded-host')),
    ...splitHeaderValues(readHeader(req, 'x-original-host')),
    ...splitHeaderValues(readHeader(req, 'origin')),
    ...splitHeaderValues(readHeader(req, 'referer')),
    ...forwardedHosts(readHeader(req, 'forwarded')),
  ];

  return candidates.some(candidate => {
    const host = normalizeHost(candidate);
    if (isLocalRequestHost(host)) return false;
    if (configuredPublicHosts.includes(host)) return true;
    return true;
  });
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

function parseServiceAccountCandidate(rawJson: string): FirebaseAdminConfig | null {
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

function parseServiceAccountJson(): FirebaseAdminConfig | null {
  const candidates = [
    env('FIREBASE_SERVICE_ACCOUNT_JSON'),
    decodeBase64(env('FIREBASE_SERVICE_ACCOUNT_JSON_BASE64')),
  ].filter(Boolean);

  for (const candidate of candidates) {
    const parsed = parseServiceAccountCandidate(candidate);
    if (parsed) return parsed;
  }

  return null;
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

export function isAuthRequiredForRequest(req?: RequestLike): boolean {
  return isAuthRequired() || isPublicRequest(req);
}

export function isCookieSecureForRequest(req?: RequestLike): boolean {
  return process.env.NODE_ENV === 'production' ||
    env('PUBLIC_BACKEND') === 'true' ||
    isPublicRequest(req);
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
    throw new FirebasePasswordSignInError(data?.error?.message || 'INVALID_LOGIN');
  }

  return data as FirebaseLoginResponse;
}

export async function createSessionCookie(idToken: string): Promise<string> {
  return getFirebaseAuth().createSessionCookie(idToken, { expiresIn: SESSION_MAX_AGE_MS });
}

export async function verifySessionCookie(sessionCookie: string): Promise<DecodedIdToken> {
  return getFirebaseAuth().verifySessionCookie(sessionCookie, true);
}
