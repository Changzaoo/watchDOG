import 'dotenv/config';
import 'express-async-errors';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import { authRouter } from './routes/auth';
import { scansRouter } from './routes/scans';
import { findingsRouter } from './routes/findings';
import { eventsRouter } from './routes/events';
import { rulesRouter } from './routes/rules';
import { prisma } from './db/client';
import { getMissingAuthConfig, isAuthConfigured, isAuthRequired } from './auth/firebase';
import { requireAuth } from './middleware/auth';

const app = express();
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === 'production';
const localScansEnabled = process.env.ENABLE_LOCAL_SCANS === 'true' || !isProduction;

if (isProduction) {
  app.set('trust proxy', 1);
}

const defaultCorsOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:3000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:5174',
  'https://watchdog-chi.vercel.app',
];
const defaultCorsOriginPatterns = [
  /^https:\/\/watchdog-[a-z0-9-]+-changzaoos-projects\.vercel\.app$/i,
];
const configuredCorsOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);
const allowedCorsOrigins = new Set([...defaultCorsOrigins, ...configuredCorsOrigins]);

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

app.use(cors({
  origin(origin, callback) {
    if (!origin || isAllowedCorsOrigin(origin)) return callback(null, true);
    console.warn(`Origin not allowed by CORS: ${origin}`);
    return callback(null, false);
  },
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Too many requests' },
});

app.use('/api', apiLimiter);
app.use('/api/auth', authRouter);
app.use('/api', requireAuth);

app.use('/api/scans/local', (_req, res, next) => {
  if (localScansEnabled) return next();
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
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    localScansEnabled,
    authRequired: isAuthRequired(),
    authConfigured: isAuthConfigured(),
    authMissingConfig: getMissingAuthConfig(),
    timestamp: new Date().toISOString(),
  });
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err: any, _req: any, res: any, _next: any) => {
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
  }

  app.listen(PORT, () => {
    console.log(`watchDOG Backend running on http://localhost:${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
  });
}

main();

process.on('beforeExit', async () => {
  await prisma.$disconnect();
});
