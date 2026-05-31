import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../db/client';

export const findingsRouter = Router();

const statusSchema = z.object({
  status: z.enum(['open', 'ignored', 'fixed', 'false_positive']),
});

// PATCH /api/findings/:id/status
findingsRouter.patch('/:id/status', async (req: Request, res: Response) => {
  const parsed = statusSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const finding = await prisma.finding.findUnique({ where: { id: req.params.id } });
  if (!finding) return res.status(404).json({ error: 'Finding não encontrado' });

  const updated = await prisma.finding.update({
    where: { id: req.params.id },
    data: { status: parsed.data.status },
  });

  res.json(updated);
});

// PATCH /api/findings/:id/note
findingsRouter.patch('/:id/note', async (req: Request, res: Response) => {
  const schema = z.object({ note: z.string().max(1000) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const updated = await prisma.finding.update({
    where: { id: req.params.id },
    data: { userNote: parsed.data.note },
  });
  res.json(updated);
});

// DELETE /api/findings/:id (soft delete via status)
findingsRouter.delete('/:id', async (req: Request, res: Response) => {
  await prisma.finding.update({
    where: { id: req.params.id },
    data: { status: 'ignored' },
  });
  res.json({ success: true });
});
