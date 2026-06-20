import https from 'https';
import http from 'http';
import { URL } from 'url';
import type { LookupFunction } from 'net';
import { resolvePublicScanAddress, PublicScanAddress } from './urlValidator';

export interface SafeHttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  redirectChain: string[];
  finalUrl?: string;
  tlsValid?: boolean;
  tlsExpiry?: Date;
  /** Corpo truncado por exceder MAX_BODY_SIZE (a resposta ainda é válida para análise de headers). */
  truncated?: boolean;
  error?: string;
}

const SAFE_TIMEOUT_MS = 12000;
const MAX_BODY_SIZE = 768 * 1024;
const MAX_REDIRECTS = 5;

// ---------------------------------------------------------------------------
// Governador de saída — o watchDOG NUNCA consulta um alvo em massa.
//
// Toda requisição HTTP do scanner passa por aqui. Garantias estruturais:
//  - concorrência 1 (requisições serializadas, nunca em paralelo);
//  - intervalo mínimo entre quaisquer requisições (espaçamento global);
//  - teto de requisições por host dentro de uma janela (anti-flood);
//  - respeito a Retry-After / 429 / 503 (back-off educado por host).
// Isso impede que a ferramenta (ou uma IA que a opere) seja usada para
// sobrecarregar um site, e também evita parecer um ataque (o que faz alvos
// grandes simplesmente bloquearem o scan).
// ---------------------------------------------------------------------------
const MIN_REQUEST_INTERVAL_MS = 600;     // espaçamento mínimo entre requisições
const MAX_REQUESTS_PER_HOST = 60;        // teto por host dentro da janela
const HOST_WINDOW_MS = 60_000;           // janela do teto por host
const MAX_RETRY_AFTER_WAIT_MS = 8_000;   // espera máxima honrando Retry-After

let lastDispatchAt = 0;
let queue: Promise<unknown> = Promise.resolve();
const hostTimestamps = new Map<string, number[]>();
const hostBackoffUntil = new Map<string, number>();

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, Math.max(0, ms)));

/** Aplica (e registra) o teto de requisições por host na janela corrente. */
function withinHostCap(host: string): boolean {
  const nowT = Date.now();
  const arr = (hostTimestamps.get(host) || []).filter(t => nowT - t < HOST_WINDOW_MS);
  if (arr.length >= MAX_REQUESTS_PER_HOST) {
    hostTimestamps.set(host, arr);
    return false;
  }
  arr.push(nowT);
  hostTimestamps.set(host, arr);
  return true;
}

/** Serializa (concorrência 1), espaça as requisições e respeita o back-off por host. */
function scheduleRequest<T>(host: string, task: () => Promise<T>): Promise<T> {
  const result = queue.then(async () => {
    const backoff = (hostBackoffUntil.get(host) || 0) - Date.now();
    if (backoff > 0) await sleep(Math.min(backoff, MAX_RETRY_AFTER_WAIT_MS));
    const gap = Date.now() - lastDispatchAt;
    if (gap < MIN_REQUEST_INTERVAL_MS) await sleep(MIN_REQUEST_INTERVAL_MS - gap);
    lastDispatchAt = Date.now();
    return task();
  });
  // Mantém a cadeia viva mesmo que a task rejeite (não deve, mas por segurança).
  queue = result.then(() => undefined, () => undefined);
  return result;
}

function parseRetryAfter(value?: string): number {
  if (!value) return 0;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const when = Date.parse(value);
  return Number.isFinite(when) ? Math.max(0, when - Date.now()) : 0;
}

type RawResponse = SafeHttpResponse & { redirectLocation?: string };

export async function safeGet(
  urlStr: string,
  customHeaders: Record<string, string> = {},
  redirectChain: string[] = []
): Promise<SafeHttpResponse> {
  if (redirectChain.length > MAX_REDIRECTS) {
    return { statusCode: 0, headers: {}, body: '', redirectChain, error: 'Too many redirects' };
  }

  const validation = await resolvePublicScanAddress(urlStr);
  if (!validation.valid || !validation.normalizedUrl || !validation.address || !validation.family) {
    return { statusCode: 0, headers: {}, body: '', redirectChain, error: validation.reason || 'Blocked URL' };
  }

  let host = 'desconhecido';
  try { host = new URL(validation.normalizedUrl).host; } catch { /* mantém fallback */ }

  // Teto anti-abuso por host: jamais ultrapassa o limite por janela.
  if (!withinHostCap(host)) {
    return {
      statusCode: 0,
      headers: {},
      body: '',
      redirectChain,
      error: `Limite anti-abuso do watchDOG atingido: não mais que ${MAX_REQUESTS_PER_HOST} requisições/min ao host ${host}.`,
    };
  }

  const res = await scheduleRequest(host, () => performRequest(validation, customHeaders, redirectChain, urlStr));

  // Back-off educado: se o alvo sinalizou limite (429/503), respeita Retry-After
  // por host nas próximas requisições.
  if (res.statusCode === 429 || res.statusCode === 503) {
    const ra = parseRetryAfter(res.headers['retry-after']);
    hostBackoffUntil.set(host, Date.now() + Math.min(ra > 0 ? ra : 2000, MAX_RETRY_AFTER_WAIT_MS));
  }

  // Redirecionamento: cada salto re-passa pelo governador (re-valida SSRF + espaça).
  if (res.redirectLocation) {
    let nextUrl: string;
    try {
      nextUrl = res.redirectLocation.startsWith('http')
        ? res.redirectLocation
        : new URL(res.redirectLocation, urlStr).toString();
    } catch {
      const { redirectLocation, ...rest } = res;
      return rest;
    }
    return safeGet(nextUrl, customHeaders, [...redirectChain, urlStr]);
  }

  return res;
}

/** Executa UM salto HTTP (sem seguir redirect) e resolve no máximo uma vez. Exportado para testes. */
export function performRequest(
  validation: PublicScanAddress,
  customHeaders: Record<string, string>,
  redirectChain: string[],
  originalUrl: string
): Promise<RawResponse> {
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
    const lookup = ((_hostname: string, options: unknown, callback?: unknown) => {
      const cb = typeof options === 'function' ? options : callback;
      if (typeof cb !== 'function') return;
      if (typeof options === 'object' && options !== null && (options as { all?: boolean }).all) {
        (cb as (err: NodeJS.ErrnoException | null, addresses: Array<{ address: string; family: number }>) => void)(
          null,
          [{ address: validation.address!, family: validation.family! }]
        );
        return;
      }
      (cb as (err: NodeJS.ErrnoException | null, address: string, family: number) => void)(null, validation.address!, validation.family!);
    }) as LookupFunction;

    const baseOptions: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'watchDOG/2.0 (+auditoria de seguranca defensiva; passivo e com limite de taxa)',
        'Accept': 'text/html,application/json,*/*',
        'Accept-Encoding': 'identity',
        ...customHeaders,
      },
      timeout: SAFE_TIMEOUT_MS,
      lookup,
    };

    const options: http.RequestOptions | https.RequestOptions = isHttps ? {
      ...baseOptions,
      servername: parsed.hostname,
      rejectUnauthorized: false,
    } : {
      ...baseOptions,
    };

    let tlsValid: boolean | undefined;
    let tlsExpiry: Date | undefined;
    let settled = false;
    const done = (r: RawResponse) => {
      if (settled) return;
      settled = true;
      resolve(r);
    };

    const req = lib.request(options, (res) => {
      if (isHttps) {
        const socket = res.socket as any;
        if (socket && socket.getPeerCertificate) {
          const cert = socket.getPeerCertificate();
          tlsValid = socket.authorized;
          if (cert && cert.valid_to) tlsExpiry = new Date(cert.valid_to);
        }
      }

      const statusCode = res.statusCode || 0;
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : (v || '');
      }

      // Redirecionamento: não baixa o corpo; devolve a location para o safeGet seguir.
      if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location) {
        res.resume(); // descarta o corpo do redirect
        done({
          statusCode, headers, body: '', redirectChain,
          finalUrl: parsed.toString(), tlsValid, tlsExpiry,
          redirectLocation: headers.location,
        });
        return;
      }

      let body = '';
      let truncated = false;
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        if (truncated) return;
        body += chunk;
        if (body.length >= MAX_BODY_SIZE) {
          // Corpo grande (ex.: homepage do YouTube): paramos de baixar, mas a
          // resposta com headers/status JÁ recebidos continua válida e analisável.
          body = body.slice(0, MAX_BODY_SIZE);
          truncated = true;
          res.destroy();
          done({ statusCode, headers, body, redirectChain, finalUrl: parsed.toString(), tlsValid, tlsExpiry, truncated: true });
        }
      });
      res.on('end', () => {
        done({ statusCode, headers, body, redirectChain, finalUrl: parsed.toString(), tlsValid, tlsExpiry, truncated });
      });
      res.on('error', () => {
        // Já temos headers/status: resolve com o que houver em vez de descartar tudo.
        done({ statusCode, headers, body, redirectChain, finalUrl: parsed.toString(), tlsValid, tlsExpiry, truncated });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      done({ statusCode: 0, headers: {}, body: '', redirectChain, error: 'Request timeout' });
    });

    req.on('error', (err) => {
      // Se já resolvemos (ex.: destroy após corpo grande), este erro é ignorado.
      done({ statusCode: 0, headers: {}, body: '', redirectChain, error: err.message });
    });

    req.end();
  });
}

export async function checkPath(baseUrl: string, path: string): Promise<SafeHttpResponse> {
  const url = baseUrl.replace(/\/$/, '') + path;
  return safeGet(url);
}
