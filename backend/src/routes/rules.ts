import { Router, Request, Response } from 'express';
import { z } from 'zod';
import type { RuleConfig as RuleConfigModel } from '@prisma/client';
import { allFileRules } from '@sentinelscope/scanner';
import { prisma } from '../db/client';

export const rulesRouter = Router();

// GET /api/rules - list scanner rule catalog with local config overrides
rulesRouter.get('/', async (_req: Request, res: Response) => {
  const configs = await prisma.ruleConfig.findMany() as RuleConfigModel[];
  const configByRuleId = new Map<string, RuleConfigModel>(
    configs.map((c: RuleConfigModel) => [c.ruleId, c])
  );

  const rules = allFileRules.map(rule => {
    const config = configByRuleId.get(rule.id);
    return {
      id: rule.id,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      effectiveSeverity: config?.severityOverride || rule.severity,
      confidence: rule.confidence || 'medium',
      enabled: config?.enabled ?? true,
      severityOverride: config?.severityOverride || null,
      description: rule.description,
      impact: rule.impact,
      remediation: rule.remediation,
      safeExample: rule.safeExample,
      testSuggestion: rule.testSuggestion,
      reference: rule.reference,
      fileExtensions: rule.fileExtensions,
      patternsCount: rule.patterns.length,
    };
  });

  res.json(rules);
});

// PATCH /api/rules/:ruleId - update rule config (enable/disable, severity override)
rulesRouter.patch('/:ruleId', async (req: Request, res: Response) => {
  const schema = z.object({
    enabled: z.boolean().optional(),
    severityOverride: z.enum(['critical', 'high', 'medium', 'low', 'info']).nullable().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const exists = allFileRules.some(rule => rule.id === req.params.ruleId);
  if (!exists) return res.status(404).json({ error: 'Regra nao encontrada' });

  const config = await prisma.ruleConfig.upsert({
    where: { ruleId: req.params.ruleId },
    update: parsed.data,
    create: {
      ruleId: req.params.ruleId,
      enabled: parsed.data.enabled ?? true,
      severityOverride: parsed.data.severityOverride ?? null,
    },
  });
  res.json(config);
});
