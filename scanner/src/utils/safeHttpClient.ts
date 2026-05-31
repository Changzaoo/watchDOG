import https from 'https';
import http from 'http';
import { URL } from 'url';
import { validateScanUrlWithDns } from './urlValidator';

export interface SafeHttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  redirectChain: string[];
  finalUrl?: string;
  tlsValid?: boolean;
  tlsExpiry?: Date;
  error?: string;
}

const SAFE_TIMEOUT_MS = 10000;
const MAX_BODY_SIZE = 512 * 1024;
const MAX_REDIRECTS = 5;

export async function safeGet(
  urlStr: string,
  customHeaders: Record<string, string> = {},
  redirectChain: string[] = []
): Promise<SafeHttpResponse> {
  if (redirectChain.length > MAX_REDIRECTS) {
    return { statusCode: 0, headers: {}, body: '', redirectChain, error: 'Too many redirects' };
  }

  const validation = await validateScanUrlWithDns(urlStr);
  if (!validation.valid || !validation.normalizedUrl) {
    return { statusCode: 0, headers: {}, body: '', redirectChain, error: validation.reason || 'Blocked URL' };
  }

  return new Promise((resolve) => {
    let parsed: URL;
    try {
      parsed = new URL(validation.normalizedUrl!);
    } catch {
      resolve({ statusCode: 0, headers: {}, body: '', redirectChain, error: 'Invalid URL' });
      return;
    }

    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'watchDOG/1.0 Security-Audit',
        'Accept': 'text/html,application/json,*/*',
        ...customHeaders,
      },
      timeout: SAFE_TIMEOUT_MS,
      rejectUnauthorized: false,
    };

    let tlsValid: boolean | undefined;
    let tlsExpiry: Date | undefined;

    const req = lib.request(options, (res) => {
      if (isHttps) {
        const socket = res.socket as any;
        if (socket && socket.getPeerCertificate) {
          const cert = socket.getPeerCertificate();
          tlsValid = socket.authorized;
          if (cert && cert.valid_to) {
            tlsExpiry = new Date(cert.valid_to);
          }
        }
      }

      const statusCode = res.statusCode || 0;
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : (v || '');
      }

      if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location) {
        const nextUrl = headers.location.startsWith('http')
          ? headers.location
          : new URL(headers.location, urlStr).toString();
        safeGet(nextUrl, customHeaders, [...redirectChain, urlStr]).then(resolve);
        return;
      }

      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        body += chunk;
        if (body.length > MAX_BODY_SIZE) {
          req.destroy();
          body = body.slice(0, MAX_BODY_SIZE);
        }
      });
      res.on('end', () => {
        resolve({ statusCode, headers, body, redirectChain, finalUrl: parsed.toString(), tlsValid, tlsExpiry });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ statusCode: 0, headers: {}, body: '', redirectChain, error: 'Request timeout' });
    });

    req.on('error', (err) => {
      resolve({ statusCode: 0, headers: {}, body: '', redirectChain, error: err.message });
    });

    req.end();
  });
}

export async function checkPath(baseUrl: string, path: string): Promise<SafeHttpResponse> {
  const url = baseUrl.replace(/\/$/, '') + path;
  return safeGet(url);
}
