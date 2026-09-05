import { FileRule } from '../types';

/**
 * OWASP Top 10:2025 — A10 "Mishandling of Exceptional Conditions".
 *
 * Categoria NOVA do Top 10 2025, raramente coberta por scanners. Agrupa 24 CWEs
 * sobre o que a aplicação faz quando algo dá errado: liberar acesso no catch
 * (fail open), engolir erro de verificação, vazar stack trace ao cliente e
 * deixar operações críticas parcialmente aplicadas.
 */
export const exceptionRules: FileRule[] = [
  {
    id: 'EXC_001',
    title: 'Fail open: erro na verificação de segurança libera o acesso',
    category: 'Condições Excepcionais',
    severity: 'critical',
    confidence: 'medium',
    description:
      'Bloco catch em torno de verificação de autenticação/autorização/assinatura que retorna valor permissivo (true/next()/allow) quando a checagem falha.',
    impact:
      'Fail open (CWE-636): basta derrubar ou instabilizar o serviço de verificação para que TODOS os acessos sejam liberados. Uma indisponibilidade vira bypass total de autorização.',
    attackScenarioDefensive:
      'O atacante satura o serviço de authz até ele começar a lançar exceção; como o catch retorna true, todas as requisições passam a ser autorizadas e ele acessa recursos administrativos.',
    remediation:
      'Falhe fechado: no catch, registre o erro e NEGUE o acesso (retorne false / 403 / lance). Só libere no caminho de sucesso explícito da verificação.',
    safeExample:
      "try {\n  return await authz.check(user, recurso);\n} catch (err) {\n  logger.error({ err, user }, 'authz indisponivel');\n  return false; // nega por padrao\n}",
    testSuggestion:
      'Force a dependência de autorização a lançar exceção (derrube o serviço/mock) e confirme que o acesso é NEGADO, não liberado.',
    reference: 'OWASP A10:2025 - Mishandling of Exceptional Conditions; CWE-636',
    patterns: [
      /catch\s*(?:\([^)]*\))?\s*\{(?:(?!\})[\s\S]){0,200}?return\s+true\s*[;\n}]/,
      /catch\s*(?:\([^)]*\))?\s*\{(?:(?!\})[\s\S]){0,200}?(?:next\s*\(\s*\)|return\s+next\s*\(\s*\))/,
      /catch\s*(?:\([^)]*\))?\s*\{(?:(?!\})[\s\S]){0,160}?(?:isAuthorized|authorized|isValid|allow(?:ed)?|hasAccess)\s*=\s*true/i,
    ],
    requireContent:
      /auth|authz|permission|permiss|verify|verifica|signature|assinatura|token|session|acesso|access/i,
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'],
  },
  {
    id: 'EXC_002',
    title: 'Erro de verificação silenciado (catch vazio)',
    category: 'Condições Excepcionais',
    severity: 'high',
    confidence: 'medium',
    description:
      'Bloco catch vazio (ou apenas com comentário) envolvendo verificação de assinatura, token, integridade ou permissão — a falha é engolida e a execução continua.',
    impact:
      'A verificação deixa de existir na prática: como o erro não interrompe o fluxo nem é registrado, uma assinatura inválida ou token corrompido passa despercebido e a operação segue.',
    attackScenarioDefensive:
      'O atacante envia um webhook com assinatura inválida; verifySignature lança, o catch vazio engole o erro, o código continua e o evento forjado é processado como legítimo.',
    remediation:
      'Nunca deixe catch vazio em código de segurança. Registre o erro com contexto e interrompa o fluxo (throw / return 4xx). Se o erro for realmente ignorável, documente o porquê explicitamente.',
    safeExample:
      "try {\n  await verifySignature(payload, assinatura);\n} catch (err) {\n  logger.warn({ err }, 'assinatura invalida');\n  return res.status(401).json({ error: 'assinatura invalida' });\n}",
    testSuggestion:
      'Envie um payload com assinatura inválida e confirme que a requisição é rejeitada com 401/400 e que o evento aparece nos logs.',
    reference: 'OWASP A10:2025; CWE-252 - Unchecked Return Value; CWE-390',
    patterns: [
      /(?:verify|verifica|validate|valida|check|authenticate|autentica)[A-Za-z]*\s*\([^)]*\)[\s\S]{0,80}?catch\s*(?:\([^)]*\))?\s*\{\s*(?:\/\/[^\n]*\s*)?\}/i,
      /try\s*\{(?:(?!\})[\s\S]){0,200}?(?:signature|assinatura|hmac|token|jwt)(?:(?!\})[\s\S]){0,200}?\}\s*catch\s*(?:\([^)]*\))?\s*\{\s*\}/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'EXC_003',
    title: 'Stack trace ou detalhe interno de erro enviado ao cliente',
    category: 'Condições Excepcionais',
    severity: 'medium',
    confidence: 'high',
    description:
      'Handler de erro que devolve err.stack, err.message bruto ou o objeto de erro completo no corpo da resposta HTTP.',
    impact:
      'Vaza caminhos absolutos do servidor, versões de dependências, estrutura interna e, em erros de banco, fragmentos de query — material de reconhecimento que acelera a exploração (e às vezes revela credenciais).',
    attackScenarioDefensive:
      'O atacante envia entradas malformadas até provocar exceção; a resposta traz o stack com o caminho /home/app/src/... e o erro do driver SQL, revelando a estrutura da query e confirmando um ponto de injeção.',
    remediation:
      'Devolva uma mensagem genérica com um identificador de correlação e registre o detalhe apenas no log do servidor. Nunca exponha stack/mensagem interna em produção.',
    safeExample:
      "app.use((err, req, res, _next) => {\n  const ref = crypto.randomUUID();\n  logger.error({ err, ref, path: req.path });\n  res.status(err.status ?? 500).json({ error: 'Erro interno', reference: ref });\n});",
    testSuggestion:
      'Provoque um erro 500 em produção e confirme que a resposta não contém stack, caminho de arquivo nem mensagem do driver de banco.',
    reference: 'OWASP A10:2025; CWE-209 - Information Exposure Through an Error Message',
    patterns: [
      /res\.(?:json|send)\s*\(\s*\{[^}]{0,120}\b(?:stack)\s*:\s*(?:err|error|e)\b/i,
      /res\.(?:json|send)\s*\(\s*\{[^}]{0,120}\berror\s*:\s*(?:err|error)\.(?:message|stack)/i,
      /res\.(?:json|send)\s*\(\s*(?:err|error)\s*\)/,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'EXC_004',
    title: 'Operações de escrita encadeadas sem transação',
    category: 'Condições Excepcionais',
    severity: 'medium',
    confidence: 'low',
    description:
      'Duas ou mais operações de escrita dependentes executadas em sequência (débito/crédito, criar/atualizar) sem transação que garanta atomicidade.',
    impact:
      'Se a segunda operação falhar, a primeira permanece aplicada e o sistema fica em estado inconsistente — dinheiro debitado sem crédito, pedido criado sem baixa de estoque.',
    attackScenarioDefensive:
      'O atacante interrompe a conexão logo após o débito ser confirmado; o crédito nunca executa e, sem transação, não há rollback — o saldo simplesmente desaparece (ou é duplicado no sentido inverso).',
    remediation:
      'Envolva as operações dependentes numa transação ($transaction, BEGIN/COMMIT) para que sejam aplicadas por completo ou revertidas por completo.',
    safeExample:
      "await prisma.$transaction([\n  prisma.conta.update({ where: { id: origem }, data: { saldo: { decrement: valor } } }),\n  prisma.conta.update({ where: { id: destino }, data: { saldo: { increment: valor } } }),\n]);",
    testSuggestion:
      'Force uma falha na segunda operação e confirme que a primeira foi revertida (estado final inalterado).',
    reference: 'OWASP A10:2025; CWE-460 - Improper Cleanup on Thrown Exception',
    patterns: [
      /await\s+[\w.]*(?:debit|debito|withdraw|decrement|subtract)\w*\s*\([^)]*\)\s*;[\s\S]{0,120}?await\s+[\w.]*(?:credit|credito|deposit|increment|add)\w*\s*\(/i,
    ],
    suppressIfProjectMatches: /\$transaction|startTransaction|BEGIN\s+TRANSACTION|\.transaction\s*\(/i,
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
];
