import 'dotenv/config';
import 'express-async-errors';
import express from 'express';
import type { Request } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import hpp from 'hpp';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import cookieParser from 'cookie-parser';
import { authRouter } from './routes/auth';
import { scansRouter } from './routes/scans';
import { findingsRouter } from './routes/findings';
import { eventsRouter } from './routes/events';
import { rulesRouter } from './routes/rules';
import { prisma } from './db/client';
import { getMissingAuthConfig, isAuthConfigured, isAuthRequiredForRequest, isPublicRequest } from './auth/firebase';
import { requireAuth } from './middleware/auth';

const app = express();
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === 'production';
const isPublicBackend = isProduction || process.env.PUBLIC_BACKEND === 'true';
const HOST = process.env.HOST || (isPublicBackend ? '0.0.0.0' : '127.0.0.1');
const localScansEnabled = isPublicBackend
  ? process.env.ENABLE_LOCAL_SCANS === 'true' && process.env.ALLOW_LOCAL_SCANS_ON_PUBLIC_BACKEND === 'true'
  : process.env.ENABLE_LOCAL_SCANS === 'true' || !isProduction;

function areLocalScansEnabledForRequest(req?: Request): boolean {
  if (req && isPublicRequest(req) && process.env.ALLOW_PUBLIC_LOCAL_SCANS !== 'true') {
    return false;
  }

  return localScansEnabled;
}

app.disable('x-powered-by');

if (isPublicBackend) {
  app.set('trust proxy', 1);
}

const defaultCorsOrigins = [
  'https://watchdog-chi.vercel.app',
];
const localCorsOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:3000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:5174',
];
const defaultCorsOriginPatterns = isPublicBackend ? [] : [
  /^https:\/\/watchdog-[a-z0-9-]+-changzaoos-projects\.vercel\.app$/i,
];
const configuredCorsOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);
const allowedCorsOrigins = new Set([
  ...defaultCorsOrigins,
  ...(!isPublicBackend ? localCorsOrigins : []),
  ...configuredCorsOrigins,
]);

function isAllowedCorsOrigin(origin: string): boolean {
  try {
    const normalizedOrigin = new URL(origin).origin;
    return allowedCorsOrigins.has(normalizedOrigin) ||
      defaultCorsOriginPatterns.some(pattern => pattern.test(normalizedOrigin));
  } catch {
    return false;
  }
}

// Security middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false,
}));

// Proteção contra HTTP Parameter Pollution (ex.: ?a=1&a=2 vira array inesperado).
app.use(hpp());

// Compressão seletiva: NÃO comprimir streams SSE (text/event-stream), pois a
// compressão segura buffers e quebra o fluxo de eventos em tempo real.
app.use(compression({
  threshold: 1024,
  filter: (req, res) => {
    const accept = req.headers['accept'];
    if (typeof accept === 'string' && accept.includes('text/event-stream')) {
      return false;
    }
    return compression.filter(req, res);
  },
}));

app.use(cors({
  origin(origin, callback) {
    if (!origin || isAllowedCorsOrigin(origin)) return callback(null, true);
    console.warn(`Origin not allowed by CORS: ${origin}`);
    return callback(null, false);
  },
  credentials: true,
}));

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));
app.use(cookieParser());

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas de login. Aguarde alguns minutos e tente novamente.' },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
});

const scanLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scan requests' },
});

// Atraso progressivo (anti brute-force) nas rotas de autenticação: após as 5
// primeiras requisições na janela, cada requisição extra ganha +500ms acumulativos.
const authSlowDown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 5,
  delayMs: () => 500,
});

app.use('/api/auth/login', loginLimiter);
app.use('/api', apiLimiter);
app.use('/api/scans/url', scanLimiter);
app.use('/api/auth', authSlowDown);
app.use('/api/auth', authRouter);
app.use('/api', requireAuth);

app.use('/api/scans/local', (req, res, next) => {
  if (isPublicRequest(req) && process.env.ALLOW_PUBLIC_LOCAL_SCANS !== 'true') {
    return res.status(403).json({
      error: 'Scan local esta bloqueado em acessos publicos via Vercel/ngrok.',
    });
  }

  if (areLocalScansEnabledForRequest(req)) return next();
  return res.status(403).json({
    error: 'Scan local esta desabilitado neste backend hospedado. Use a versao local para analisar pastas do seu computador.',
  });
});

// Routes
app.use('/api/scans', scansRouter);
app.use('/api/findings', findingsRouter);
app.use('/api/events', eventsRouter);
app.use('/api/rules', rulesRouter);

// Health check
app.get('/health', (req, res) => {
  const health: Record<string, unknown> = {
    status: 'ok',
    version: '1.0.0',
    localScansEnabled: areLocalScansEnabledForRequest(req),
    timestamp: new Date().toISOString(),
  };

  if (!isPublicBackend || process.env.EXPOSE_HEALTH_DETAILS === 'true') {
    health.authRequired = isAuthRequiredForRequest(req);
    health.authConfigured = isAuthConfigured();
    health.authMissingConfig = getMissingAuthConfig();
  }

  res.json(health);
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err: any, _req: any, res: any, _next: any) => {
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload muito grande.' });
  }

  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ error: 'JSON invalido.' });
  }

  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
async function main() {
  try {
    await prisma.$connect();
    console.log('Database connected');
  } catch (e) {
    console.error('Database connection failed:', e);
    process.exit(1);
  }

  const server = app.listen(Number(PORT), HOST, () => {
    console.log(`watchDOG Backend running on http://${HOST}:${PORT}`);
    console.log(`Health check: http://${HOST}:${PORT}/health`);
  });

  // Timeouts de servidor/socket (anti-Slowloris). Nunca usar 0.
  server.requestTimeout = 30_000;   // tempo máximo para receber a requisição inteira
  server.headersTimeout = 20_000;   // tempo máximo para receber os headers
  server.keepAliveTimeout = 5_000;  // mantém-se acima do timeout do LB para evitar 502
  server.setTimeout(35_000);        // timeout de socket ocioso

  // Graceful shutdown: para de aceitar conexões, fecha o servidor e desconecta o
  // Prisma; se travar, força a saída após 10s (timer unref para não segurar o loop).
  let shuttingDown = false;
  async function shutdown(signal: string) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`Recebido ${signal}, encerrando graciosamente...`);

    const forceExit = setTimeout(() => {
      console.error('Encerramento forçado após timeout.');
      process.exit(1);
    }, 10_000);
    forceExit.unref();

    server.close(async () => {
      try {
        await prisma.$disconnect();
      } catch (e) {
        console.error('Erro ao desconectar o banco:', e);
      }
      clearTimeout(forceExit);
      process.exit(0);
    });
  }

  (['SIGTERM', 'SIGINT'] as const).forEach((signal) => {
    process.on(signal, () => shutdown(signal));
  });
}

main();

process.on('beforeExit', async () => {
  await prisma.$disconnect();
});
