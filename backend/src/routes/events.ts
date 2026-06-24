import { Router, Request, Response } from 'express';

export const eventsRouter = Router();

// Map of scanId -> SSE emitter function
export const scanEventEmitters = new Map<string, (event: any) => void>();

// Teto de conexões SSE simultâneas. Cada conexão segura um socket aberto; sem
// limite, um flood de aberturas esgotaria sockets/memória do processo (DoS).
const MAX_SSE_CONNECTIONS = 500;
let sseConnections = 0;

// Intervalo do heartbeat de keep-alive: mantém a conexão viva através de proxies/
// load balancers que derrubam streams ociosos e detecta clientes desconectados.
const SSE_HEARTBEAT_MS = 15 * 1000;

// GET /api/events/scans/:id - Server-Sent Events for real-time scan progress
eventsRouter.get('/scans/:id', (req: Request, res: Response) => {
  const { id } = req.params;

  // Rejeita novas conexões quando o teto é atingido, protegendo o processo.
  if (sseConnections >= MAX_SSE_CONNECTIONS) {
    return res.status(503).json({ error: 'Limite de conexões em tempo real atingido. Tente novamente em instantes.' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  // Nunca deixar o socket SSE expirar por inatividade — o heartbeat o mantém vivo.
  res.setTimeout(0);

  sseConnections++;

  const sendEvent = (event: any) => {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  };

  // Register emitter for this scan
  scanEventEmitters.set(id, sendEvent);

  // Send initial keepalive
  res.write(`: keepalive\n\n`);

  // Heartbeat periódico (comentário SSE, ignorado pelo cliente) para manter a
  // conexão aberta e provocar erro de escrita quando o cliente já saiu.
  const heartbeat = setInterval(() => {
    res.write(`: keep-alive\n\n`);
  }, SSE_HEARTBEAT_MS);

  // Auto cleanup after 30 minutes
  const timeout = setTimeout(() => {
    scanEventEmitters.delete(id);
    res.end();
  }, 30 * 60 * 1000);

  let cleanedUp = false;
  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    clearInterval(heartbeat);
    clearTimeout(timeout);
    scanEventEmitters.delete(id);
    sseConnections--;
  };

  // Cleanup on disconnect
  req.on('close', cleanup);
});
