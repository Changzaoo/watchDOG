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

function isCloudMetadataHost(host: string): boolean {
  return CLOUD_METADATA_HOSTS.some(m => host === m || host.endsWith('.' + m));
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const normalized = ip.replace(/^\[|\]$/g, '').toLowerCase();
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
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return { valid: false, reason: 'URL invalida: formato incorreto' };
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, reason: `Protocolo nao permitido: ${parsed.protocol}. Use apenas http:// ou https://` };
  }

  const host = parsed.hostname.toLowerCase();

  if (isCloudMetadataHost(host)) {
    return { valid: false, reason: 'URL bloqueada: endpoint de metadata de cloud nao permitido' };
  }

  if (host === 'localhost' || host === '0.0.0.0' || host === '[::1]' || host === '::1') {
    return { valid: false, reason: 'URL bloqueada: localhost nao e permitido para scan de URL' };
  }

  if (net.isIP(host) && isPrivateOrReservedIp(host)) {
    return { valid: false, reason: `URL bloqueada: endereco IP privado/reservado nao permitido (${host})` };
  }

  const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
  if ([3000, 3001, 5173].includes(port)) {
    return { valid: false, reason: 'URL bloqueada: porta local da aplicacao nao permitida' };
  }

  return { valid: true, normalizedUrl: parsed.toString() };
}

export async function validateScanUrlWithDns(rawUrl: string): Promise<UrlValidationResult> {
  const base = validateScanUrl(rawUrl);
  if (!base.valid || !base.normalizedUrl) return base;

  const host = new URL(base.normalizedUrl).hostname.toLowerCase();
  if (net.isIP(host) || isCloudMetadataHost(host)) return base;

  try {
    const addresses = await dns.lookup(host, { all: true, verbatim: true });
    const blocked = addresses.find(a => isPrivateOrReservedIp(a.address));
    if (blocked) {
      return {
        valid: false,
        reason: `URL bloqueada: DNS resolve para IP privado/reservado (${blocked.address})`,
      };
    }
  } catch {
    return { valid: false, reason: 'URL bloqueada: nao foi possivel resolver DNS com seguranca' };
  }

  return base;
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
