// O gerador do "fix prompt" vive em @sentinelscope/shared (fonte única de verdade).
// Reexportado aqui para manter o import existente (../lib/fixPrompt) usado pelo FixPromptPanel.
export { generateAggregateFixPrompt, getFixableFindings } from '@sentinelscope/shared';
export type { FixPromptOptions } from '@sentinelscope/shared';
