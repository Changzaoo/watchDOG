import { Router, Request, Response } from 'express';

export const eventsRouter = Router();

// Map of scanId -> SSE emitter function
export const scanEventEmitters = new Map<string, (event: any) => void>();

// GET /api/events/scans/:id - Server-Sent Events for real-time scan progress
eventsRouter.get('/scans/:id', (req: Request, res: Response) => {
  const { id } = req.params;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const sendEvent = (event: any) => {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  };

  // Register emitter for this scan
  scanEventEmitters.set(id, sendEvent);

  // Send initial keepalive
  res.write(`: keepalive\n\n`);

  // Cleanup on disconnect
  req.on('close', () => {
    scanEventEmitters.delete(id);
  });

  // Auto cleanup after 30 minutes
  const timeout = setTimeout(() => {
    scanEventEmitters.delete(id);
    res.end();
  }, 30 * 60 * 1000);

  req.on('close', () => clearTimeout(timeout));
});
