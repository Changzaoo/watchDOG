import { FileRule } from '../types';

export function generateFixPrompt(
  rule: { id: string; title: string; description: string; impact: string; remediation: string; safeExample?: string },
  filePath?: string,
  line?: number
): string {
  const fileInfo = filePath
    ? `Arquivo afetado:\n${filePath}${line ? ':' + line : ''}`
    : 'Afeta a aplicação como um todo.';

  return `Corrija a vulnerabilidade detectada pelo watchDOG.

Regra: ${rule.id} — ${rule.title}

${fileInfo}

Problema:
${rule.description}

Impacto:
${rule.impact}

Correção esperada:
${rule.remediation}
${rule.safeExample ? `\nExemplo seguro:\n${rule.safeExample}` : ''}

Instruções:
- Não altere funcionalidades não relacionadas a esta vulnerabilidade.
- Preserve o padrão de código do projeto.
- Não remova validações existentes.
- Não exponha secrets ou dados sensíveis.
- Adicione ou ajuste testes quando aplicável.
- Explique ao final quais arquivos foram alterados e por quê.

Após a correção, rode:
npm run typecheck
npm run lint
npm run build`;
}

export function generateSecretFixPrompt(
  rule: { id: string; title: string },
  filePath?: string
): string {
  const fileInfo = filePath ? `Arquivo: ${filePath}` : '';
  return `Corrija a exposição de secret detectada pelo watchDOG.

Regra: ${rule.id} — ${rule.title}
${fileInfo}

Passos obrigatórios:
1. Remova o secret do código-fonte imediatamente.
2. Mova para variável de ambiente (process.env.NOME_VAR).
3. Adicione a variável ao arquivo .env (local, não versionado).
4. Adicione ao .env.example com valor de exemplo (nunca o valor real).
5. Adicione .env ao .gitignore se ainda não estiver.
6. ROTACIONE a chave comprometida nos painéis do serviço (não basta remover do código).
7. Verifique o histórico do Git: git log --all -p --follow -- ${filePath || '<arquivo>'} | grep -i secret
8. Se já foi commitado, remova do histórico (git-filter-repo ou BFG) e force-push.

NUNCA commite secrets mesmo que "só por enquanto".`;
}
