export function maskSecret(value: string): string {
  if (!value || value.length < 4) return '***';
  if (value.length <= 8) return value.slice(0, 2) + '***';
  const show = Math.min(4, Math.floor(value.length * 0.15));
  return value.slice(0, show) + '*'.repeat(8) + value.slice(-show);
}

export function maskUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.password) u.password = '***';
    if (u.username) u.username = u.username.slice(0, 2) + '***';
    return u.toString();
  } catch {
    return url.replace(/:\/\/[^@]+@/, '://***@');
  }
}

export function maskLine(line: string): string {
  return line
    .replace(/(["'`])[A-Za-z0-9+/=_\-]{20,}(["'`])/g, '$1***masked***$2')
    .replace(/(password|secret|key|token|auth|credential)\s*[:=]\s*["'`]?[^\s"'`]+["'`]?/gi,
      (m) => m.replace(/[:=]\s*["'`]?[^\s"'`]+["'`]?$/, '= ***'));
}

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS Secret Key', pattern: /[A-Za-z0-9+/]{40}/ },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { name: 'Stripe Live Key', pattern: /sk_live_[A-Za-z0-9]{24,}/ },
  { name: 'Stripe Test Key', pattern: /sk_test_[A-Za-z0-9]{24,}/ },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{20,}/ },
  { name: 'Private Key PEM', pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/ },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z-_]{35}/ },
  { name: 'Firebase Config', pattern: /[A-Za-z0-9_-]{20}\.firebaseio\.com/ },
  { name: 'MongoDB URI', pattern: /mongodb(\+srv)?:\/\/[^"'\s]+/ },
  { name: 'PostgreSQL URI', pattern: /postgres(ql)?:\/\/[^"'\s]+:[^"'\s]+@/ },
  { name: 'Generic Secret', pattern: /(secret|password|passwd|pwd|token|apikey|api_key)\s*[=:]\s*["']?[A-Za-z0-9+/=_\-]{8,}["']?/i },
];

export function detectSecretType(value: string): string | null {
  for (const { name, pattern } of SECRET_PATTERNS) {
    if (pattern.test(value)) return name;
  }
  return null;
}

export function extractAndMaskSecret(line: string): { found: boolean; masked: string; type?: string } {
  for (const { name, pattern } of SECRET_PATTERNS) {
    const match = line.match(pattern);
    if (match) {
      const masked = maskSecret(match[0]);
      return { found: true, masked: line.replace(match[0], masked), type: name };
    }
  }
  return { found: false, masked: maskLine(line) };
}
