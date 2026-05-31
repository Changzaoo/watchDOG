import { Request } from 'express';

interface LoginAttemptState {
  failures: number;
  windowStartedAt: number;
  lockedUntil: number;
  lockLevel: number;
  lastSeenAt: number;
}

interface LoginBlock {
  lockedUntil: number;
  retryAfterSeconds: number;
}

const attempts = new Map<string, LoginAttemptState>();

function envInt(name: string, fallback: number): number {
  const parsed = Number.parseInt(process.env[name] || '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function minutes(name: string, fallback: number): number {
  return envInt(name, fallback) * 60 * 1000;
}

function maxFailedAttempts(): number {
  return envInt('LOGIN_MAX_FAILED_ATTEMPTS', 5);
}

function attemptWindowMs(): number {
  return minutes('LOGIN_ATTEMPT_WINDOW_MINUTES', 15);
}

function baseLockoutMs(): number {
  return minutes('LOGIN_LOCKOUT_MINUTES', 15);
}

function maxLockoutMs(): number {
  return minutes('LOGIN_MAX_LOCKOUT_MINUTES', 60);
}

function retentionMs(): number {
  return Math.max(attemptWindowMs(), maxLockoutMs()) * 2;
}

export function normalizeLoginEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function getRequestIp(req: Request): string {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

function loginKeys(email: string, ip: string): string[] {
  return [`email:${normalizeLoginEmail(email)}`, `ip:${ip}`];
}

function getFreshState(key: string, now: number): LoginAttemptState | null {
  const state = attempts.get(key);
  if (!state) return null;

  if (state.lockedUntil <= now && state.lastSeenAt + retentionMs() < now) {
    attempts.delete(key);
    return null;
  }

  return state;
}

export function getLoginBlock(email: string, ip: string, now = Date.now()): LoginBlock | null {
  const activeLocks = loginKeys(email, ip)
    .map(key => getFreshState(key, now)?.lockedUntil || 0)
    .filter(lockedUntil => lockedUntil > now);

  if (activeLocks.length === 0) return null;

  const lockedUntil = Math.max(...activeLocks);
  return {
    lockedUntil,
    retryAfterSeconds: Math.max(1, Math.ceil((lockedUntil - now) / 1000)),
  };
}

export function recordLoginFailure(email: string, ip: string, now = Date.now()): void {
  for (const key of loginKeys(email, ip)) {
    const state = getFreshState(key, now) || {
      failures: 0,
      windowStartedAt: now,
      lockedUntil: 0,
      lockLevel: 0,
      lastSeenAt: now,
    };

    if (now - state.windowStartedAt > attemptWindowMs()) {
      state.failures = 0;
      state.windowStartedAt = now;
      if (state.lockedUntil <= now) state.lockLevel = 0;
    }

    state.failures += 1;
    state.lastSeenAt = now;

    if (state.failures >= maxFailedAttempts()) {
      state.lockLevel += 1;
      state.failures = 0;
      state.windowStartedAt = now;
      state.lockedUntil = now + Math.min(
        baseLockoutMs() * 2 ** Math.max(0, state.lockLevel - 1),
        maxLockoutMs()
      );
    }

    attempts.set(key, state);
  }
}

export function recordLoginSuccess(email: string): void {
  attempts.delete(`email:${normalizeLoginEmail(email)}`);
}
