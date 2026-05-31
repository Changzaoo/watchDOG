import { URL } from 'url';
import net from 'net';
import dns from 'dns/promises';

const CLOUD_METADATA_HOSTS = [
  '169.254.169.254',
  'metadata.google.internal',
  'fd00:ec2::254',
  '169.254.170.2',
];

export interface UrlValidationResult {
  valid: boolean;
  reason?: string;
  normalizedUrl?: string;
}

export interface PublicScanAddress extends UrlValidationResult {
  address?: string;
  family?: 4 | 6;
}

function normalizeHost(host: string): string {
  return host.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
}

function isCloudMetadataHost(host: string): boolean {
  const normalized = normalizeHost(host);
  return CLOUD_METADATA_HOSTS.some(m => normalized === m || normalized.endsWith('.' + m));
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const normalized = normalizeHost(ip);
  const mappedIpv4 = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mappedIpv4) return isPrivateOrReservedIp(mappedIpv4[1]);

  if (net.isIPv4(normalized)) {
    const parts = normalized.split('.').map(Number);
    return (
      parts[0] === 0 ||
      parts[0] === 10 ||
      parts[0] === 127 ||
      parts[0] >= 224 ||
      (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) ||
      (parts[0] === 169 && parts[1] === 254) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) ||
      (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) ||
      (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) ||
      (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) ||
      (parts[0] === 203 && parts[1] === 0 && parts[2] === 113)
    );
  }

  if (net.isIPv6(normalized)) {
    return (
      normalized === '::' ||
      normalized === '::1' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe80:') ||
      normalized.startsWith('ff')
    );
  }

  return false;
}

export function validateScanUrl(rawUrl: string): UrlValidationResult {
  let parsed: URL;
  const input = rawUrl.trim();

  if (input.length > 2048) {
    return { valid: false, reason: 'URL invalida: tamanho maximo excedido' };
  }

  try {
    parsed = new URL(input);
  } catch {
    return { valid: false, reason: 'URL invalida: formato incorreto' };
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, reason: `Protocolo nao permitido: ${parsed.protocol}. Use apenas http:// ou https://` };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, reason: 'URL bloqueada: credenciais embutidas nao sao permitidas' };
  }

  const host = normalizeHost(parsed.hostname);
  if (!host) {
    return { valid: false, reason: 'URL invalida: host ausente' };
  }

  if (isCloudMetadataHost(host)) {
    return { valid: false, reason: 'URL bloqueada: endpoint de metadata de cloud nao permitido' };
  }

  if (host === 'localhost' || host === '0.0.0.0' || host === '::1') {
    return { valid: false, reason: 'URL bloqueada: localhost nao e permitido para scan de URL' };
  }

  if (net.isIP(host) && isPrivateOrReservedIp(host)) {
    return { valid: false, reason: `URL bloqueada: endereco IP privado/reservado nao permitido (${host})` };
  }

  const defaultPort = parsed.protocol === 'https:' ? 443 : 80;
  const port = parsed.port ? Number(parsed.port) : defaultPort;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { valid: false, reason: 'URL invalida: porta fora do intervalo permitido' };
  }

  if (process.env.ALLOW_NON_STANDARD_SCAN_PORTS !== 'true' && port !== defaultPort) {
    return { valid: false, reason: 'URL bloqueada: somente portas padrao HTTP/HTTPS sao permitidas neste backend publico' };
  }

  return { valid: true, normalizedUrl: parsed.toString() };
}

export async function resolvePublicScanAddress(rawUrl: string): Promise<PublicScanAddress> {
  const base = validateScanUrl(rawUrl);
  if (!base.valid || !base.normalizedUrl) return base;

  const host = normalizeHost(new URL(base.normalizedUrl).hostname);
  if (isCloudMetadataHost(host)) return base;
  const ipFamily = net.isIP(host);
  if (ipFamily) {
    return { ...base, address: host, family: ipFamily as 4 | 6 };
  }

  try {
    const addresses = await dns.lookup(host, { all: true, verbatim: true });
    const blocked = addresses.find(a => isPrivateOrReservedIp(a.address));
    if (blocked) {
      return {
        valid: false,
        reason: `URL bloqueada: DNS resolve para IP privado/reservado (${blocked.address})`,
      };
    }
    const selected = addresses.find(a => a.family === 4 || a.family === 6);
    if (!selected) {
      return { valid: false, reason: 'URL bloqueada: DNS nao retornou endereco IP publico valido' };
    }
    return { ...base, address: selected.address, family: selected.family as 4 | 6 };
  } catch {
    return { valid: false, reason: 'URL bloqueada: nao foi possivel resolver DNS com seguranca' };
  }
}

export async function validateScanUrlWithDns(rawUrl: string): Promise<UrlValidationResult> {
  const resolved = await resolvePublicScanAddress(rawUrl);
  return {
    valid: resolved.valid,
    reason: resolved.reason,
    normalizedUrl: resolved.normalizedUrl,
  };
}

export function validateLocalPath(inputPath: string): { valid: boolean; reason?: string } {
  const normalized = inputPath.replace(/\//g, '\\');

  if (normalized.split('\\').includes('..')) {
    return { valid: false, reason: 'Caminho invalido: path traversal detectado (..)' };
  }

  const isAbsolute = /^[A-Za-z]:\\/.test(normalized) || normalized.startsWith('/') || normalized.startsWith('\\\\');
  if (!isAbsolute) {
    return { valid: false, reason: 'Informe um caminho absoluto (ex: C:\\Users\\usuario\\projeto)' };
  }

  const dangerous = [
    /^[A-Za-z]:\\Windows(?:\\|$)/i,
    /^[A-Za-z]:\\System32(?:\\|$)/i,
    /^[A-Za-z]:\\Program Files(?:\\|$)/i,
    /^\/etc\//i,
    /^\/sys\//i,
    /^\/proc\//i,
    /^\/dev\//i,
  ];
  for (const pattern of dangerous) {
    if (pattern.test(normalized)) {
      return { valid: false, reason: 'Caminho bloqueado: diretorio de sistema nao permitido' };
    }
  }

  return { valid: true };
}
