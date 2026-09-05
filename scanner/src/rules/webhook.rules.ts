import { FileRule } from '../types';

/**
 * Regras de segurança de webhooks de pagamento.
 *
 * Origem: cadeia de ataque demonstrada no vídeo "Hackeei uma IA de paquera".
 * O atacante burlou todo o fluxo de assinatura sem pagar nada:
 *  1. Descobriu o endpoint de webhook por fuzzing (wordlist).
 *  2. O webhook primário (Cacto) exigia um secret -> bloqueou o ataque.
 *  3. Encontrou um webhook LEGADO/redundante (Kirvano) que NÃO validava
 *     assinatura -- exigia apenas um e-mail no corpo.
 *  4. Consultou a documentação do provedor, montou um payload com
 *     status="approved" apontando para o próprio e-mail e recebeu o
 *     acesso Pro de graça.
 *
 * Estas regras detectam, em código do PRÓPRIO projeto, os deslizes que
 * permitem exatamente esse tipo de abuso: webhook sem verificação de
 * assinatura, concessão de acesso a partir de campos controlados pelo
 * cliente, integrações de pagamento legadas/redundantes e ausência de
 * proteção contra replay/idempotência.
 */
export const webhookRules: FileRule[] = [
  {
    id: 'WHOOK_001',
    title: 'Webhook de pagamento sem verificação de assinatura',
    category: 'Webhook/Pagamento',
    severity: 'critical',
    confidence: 'medium',
    description:
      'O projeto expõe um endpoint de webhook de pagamento/assinatura (Stripe, Cacto, Kirvano, Hotmart, Mercado Pago, Pagar.me, Kiwify, etc.) mas nenhum arquivo do projeto realiza verificação de assinatura (HMAC/signature/constructEvent). Um webhook sem autenticação aceita eventos forjados de qualquer origem.',
    impact:
      'Bypass total do fluxo de pagamento: qualquer pessoa que descubra a URL do webhook (por fuzzing ou vazamento) pode enviar um evento falso de "pagamento aprovado" e liberar acesso pago, planos premium ou créditos sem pagar nada.',
    attackScenarioDefensive:
      'O atacante encontra POST /api/webhook por fuzzing, lê a documentação pública do provedor, envia um corpo { "status": "approved", "email": "vitima@ex.com" } e o backend, sem validar a assinatura, ativa a assinatura Pro. Foi exatamente assim que o webhook legado (Kirvano) foi abusado no vídeo.',
    remediation:
      'Verifique SEMPRE a assinatura de cada webhook antes de processá-lo, usando o secret do provedor e comparação de tempo constante. Rejeite (400/401) qualquer evento sem assinatura válida. Nunca confie no corpo do webhook só porque chegou no endpoint certo.',
    safeExample:
      "// Stripe:\nconst sig = req.headers['stripe-signature'];\nlet event;\ntry {\n  event = stripe.webhooks.constructEvent(req.rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);\n} catch {\n  return res.status(400).send('assinatura inválida');\n}\n// Genérico (HMAC):\nconst esperado = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET)\n  .update(req.rawBody).digest('hex');\nif (!crypto.timingSafeEqual(Buffer.from(esperado), Buffer.from(req.headers['x-signature'] || ''))) {\n  return res.status(401).end();\n}",
    testSuggestion:
      'Envie um POST ao endpoint de webhook com um corpo de "pagamento aprovado" e SEM cabeçalho de assinatura (ou com assinatura inválida). O servidor deve responder 400/401 e NÃO conceder nenhum acesso.',
    reference: 'OWASP API Security API2:2023 - Broken Authentication; CWE-345 (Insufficient Verification of Data Authenticity)',
    // Gatilho: existe um handler de webhook de pagamento no projeto.
    requireContent: /webhook|web[\s_-]?hook|kirvano|cacto|hotmart|kiwify|pagarme|pagar\.me|mercadopago|mercado[\s_-]?pago/i,
    patterns: [
      /(?:router|app|fastify|server)\.(?:post|all)\s*\(\s*["'`][^"'`]*(?:webhook|hook|kirvano|cacto|hotmart|kiwify|pagarme|mercadopago|payment|pagamento|billing|checkout)[^"'`]*["'`]/i,
      /(?:export\s+(?:async\s+)?function\s+POST|app\.post)[\s\S]{0,80}(?:webhook|hook)/i,
    ],
    // Se QUALQUER arquivo do projeto já verifica assinatura de webhook, a
    // postura está coberta e a regra é suprimida (evita falso-positivo).
    suppressIfProjectMatches:
      /constructEvent|verif(?:y|ica)[A-Za-z]*(?:Signature|Assinatura|Webhook)|createHmac|timingSafeEqual|svix|Webhook\.verify|x-signature|stripe-signature|WEBHOOK_SECRET|SIGNING_SECRET/i,
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'],
  },
  {
    id: 'WHOOK_002',
    title: 'Acesso/assinatura concedido a partir de status do corpo do webhook',
    category: 'Webhook/Pagamento',
    severity: 'high',
    confidence: 'medium',
    description:
      'O código libera acesso pago (plano pro/premium, is_active, subscription, créditos) diretamente a partir de um campo de status vindo do corpo da requisição (status === "approved"/"paid"/"aprovado"/"pago") sem antes validar a autenticidade do evento.',
    impact:
      'Se o status é lido do corpo antes/sem verificação de assinatura, o cliente controla totalmente esse valor. Basta enviar status="approved" para ativar a conta paga — o núcleo do bypass de pagamento demonstrado no vídeo.',
    attackScenarioDefensive:
      'O atacante replica o payload documentado pelo provedor trocando apenas o e-mail pelo dele e o status para "approved". O handler faz `if (body.status === "approved") ativarPro(body.email)` e concede o plano sem cobrança.',
    remediation:
      'Trate o status como dado não confiável até a assinatura ser validada. Fluxo correto: (1) validar assinatura do provedor; (2) buscar a transação na API oficial do provedor pelo id do evento (source of truth); (3) só então atualizar a entitlement. Nunca conceda acesso apenas porque o corpo diz "approved".',
    safeExample:
      "// 1) valida assinatura -> 2) confirma na fonte oficial -> 3) concede\nconst event = verifyWebhook(req); // lança se inválido\nconst pago = await provider.payments.retrieve(event.data.id); // fonte de verdade\nif (pago.status === 'paid') {\n  await ativarAssinatura(pago.customerId, { idempotencyKey: event.id });\n}",
    testSuggestion:
      'Envie um webhook forjado com status="approved" sem assinatura válida e confirme que nenhuma assinatura/entitlement é ativada.',
    reference: 'OWASP A06:2025 - Insecure Design; CWE-807 (Reliance on Untrusted Inputs in a Security Decision)',
    requireContent:
      /webhook|assinatura|subscription|premium|\bpro\b|plano|entitle|is_?active|upgrade|billing/i,
    patterns: [
      /(?:status|payment_status|paymentStatus|event|type|situacao)\s*(?:===?|==)\s*["'`](?:approved|paid|completed|complete|active|success|succeeded|aprovado|pago|ativo|confirmado)["'`]/i,
      /(?:req|request|payload|body|data)\.(?:body\.)?(?:status|payment_status|situacao)\s*(?:===?|==)\s*["'`](?:approved|paid|aprovado|pago)["'`]/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.py'],
  },
  {
    id: 'WHOOK_003',
    title: 'Webhook identifica o comprador apenas por e-mail/id do corpo',
    category: 'Webhook/Pagamento',
    severity: 'high',
    confidence: 'low',
    description:
      'O handler de webhook localiza/atualiza a conta a ser beneficiada usando um e-mail ou identificador arbitrário lido do corpo da requisição, sem vincular esse dado a uma transação real e verificada do provedor.',
    impact:
      'Mesmo que a assinatura exista, confiar em um e-mail livre do corpo permite direcionar o "pagamento" para qualquer conta. Sem assinatura, é o bypass direto: aponte o evento para o seu e-mail e ganhe o plano.',
    attackScenarioDefensive:
      'O webhook legado exigia apenas um e-mail. O atacante colocou o e-mail da própria conta, enviou o evento e o backend ativou o Pro nessa conta. O e-mail era o único "controle" — e era controlado pelo atacante.',
    remediation:
      'Resolva o beneficiário a partir do id da transação/cliente retornado pela API oficial do provedor após validar a assinatura, não de um e-mail solto no corpo. Cruze o e-mail do evento com o cliente registrado na transação.',
    safeExample:
      "const event = verifyWebhook(req);\nconst tx = await provider.transactions.retrieve(event.data.transactionId);\nconst usuario = await db.user.findFirst({ where: { providerCustomerId: tx.customerId } });\nif (usuario) await ativarPlano(usuario.id, tx.plan, { idempotencyKey: event.id });",
    testSuggestion:
      'Envie um webhook (mesmo válido de teste) apontando para o e-mail de outra conta e confirme que o acesso não é concedido sem uma transação real associada.',
    reference: 'OWASP API1:2023 - Broken Object Level Authorization; CWE-345',
    requireContent: /webhook|hook|assinatura|subscription|plano|entitle/i,
    patterns: [
      /findFirst?\s*\(\s*\{\s*where\s*:\s*\{\s*email\s*:\s*(?:req|request|payload|body|data)\.[A-Za-z0-9_.]*email/i,
      /(?:findByEmail|getUserByEmail|activate|ativar[A-Za-z]*|upgrade[A-Za-z]*)\s*\(\s*(?:req|request|payload|body|data)\.[A-Za-z0-9_.]*email/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.py'],
  },
  {
    id: 'WHOOK_004',
    title: 'Múltiplas integrações de pagamento (endpoints legados/redundantes)',
    category: 'Webhook/Pagamento',
    severity: 'medium',
    confidence: 'low',
    description:
      'O projeto referencia mais de um provedor de pagamento (ex.: Cacto e Kirvano, Stripe e Hotmart). Integrações de teste, antigas ou redundantes frequentemente ficam com verificação mais fraca ou esquecida, ampliando a superfície de ataque.',
    impact:
      'O atacante não precisa quebrar o gateway bem configurado: basta achar o webhook legado/redundante com validação fraca. No vídeo, o webhook secundário (Kirvano) foi a porta de entrada porque não validava assinatura como o principal (Cacto).',
    attackScenarioDefensive:
      'Depois de o webhook principal recusar por falta de secret, o atacante fez uma nova wordlist, encontrou o webhook do provedor secundário e esse aceitou o evento forjado. Uma integração esquecida derrubou toda a proteção do gateway principal.',
    remediation:
      'Inventarie todos os endpoints de pagamento/webhook. Desative e remova integrações de teste/legadas. Garanta que TODOS os webhooks ativos validem assinatura com o mesmo rigor. Documente quais provedores estão realmente em produção.',
    safeExample:
      '// Mantenha um único caminho de webhook por provedor ATIVO, todos com verificação:\n// /webhooks/stripe  -> verifica stripe-signature\n// Remova rotas antigas: /webhook, /api/pay-callback, /kirvano, etc.',
    testSuggestion:
      'Liste todas as rotas *webhook*/*callback*/*payment* do backend e confirme que cada uma está em uso e valida assinatura; remova as que não estiverem.',
    reference: 'OWASP API9:2023 - Improper Inventory Management; CWE-1059',
    // Dispara quando o MESMO arquivo cita dois provedores distintos — sinal de
    // integrações concorrentes/legadas.
    patterns: [
      /kirvano[\s\S]{0,600}(?:cacto|stripe|hotmart|kiwify|mercadopago|pagarme)/i,
      /cacto[\s\S]{0,600}(?:kirvano|stripe|hotmart|kiwify|mercadopago|pagarme)/i,
      /stripe[\s\S]{0,600}(?:kirvano|cacto|hotmart|kiwify|mercadopago|pagarme)/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.py', '.env', '.json'],
  },
  {
    id: 'WHOOK_005',
    title: 'Webhook sem idempotência/proteção contra replay',
    category: 'Webhook/Pagamento',
    severity: 'medium',
    confidence: 'low',
    description:
      'Handler de webhook que atualiza estado (ativa plano, credita saldo) sem registrar/checar o id do evento para evitar reprocessamento. Sem idempotência, o mesmo evento pode ser reenviado várias vezes.',
    impact:
      'Um evento legítimo (ou forjado) capturado pode ser reenviado repetidamente para acumular créditos, estender assinaturas ou disparar efeitos colaterais múltiplos (replay).',
    attackScenarioDefensive:
      'O atacante captura um webhook de "compra de créditos" e o reenvia N vezes; sem checagem de id de evento já processado, cada reenvio adiciona créditos.',
    remediation:
      'Registre o id único do evento do provedor e ignore eventos já processados (chave de idempotência/UNIQUE no banco). Rejeite eventos com timestamp muito antigo para mitigar replay.',
    safeExample:
      "const jaProcessado = await db.webhookEvent.findUnique({ where: { eventId: event.id } });\nif (jaProcessado) return res.status(200).end(); // idempotente\nawait db.webhookEvent.create({ data: { eventId: event.id } });\nawait aplicarEfeito(event);",
    testSuggestion:
      'Reenvie o mesmo evento de webhook duas vezes e confirme que o efeito (crédito/plano) é aplicado apenas uma vez.',
    reference: 'OWASP A06:2025 - Insecure Design; CWE-294 (Authentication Bypass by Capture-replay)',
    requireContent:
      /webhook|hook|stripe|kirvano|cacto|hotmart|kiwify|mercadopago|pagarme/i,
    patterns: [
      /(?:router|app|fastify)\.(?:post|all)\s*\(\s*["'`][^"'`]*(?:webhook|hook|callback)[^"'`]*["'`][\s\S]{0,400}\.(?:update|create|increment|credit)\s*\((?![\s\S]{0,200}(?:idempot|eventId|event_id|processed|jaProcessado))/i,
    ],
    suppressIfProjectMatches: /idempoten|eventId|event_id|processedEvents|webhookEvent/i,
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'WHOOK_006',
    title: 'Assinatura de webhook comparada de forma insegura (== / ===)',
    category: 'Webhook/Pagamento',
    severity: 'medium',
    confidence: 'medium',
    description:
      'A assinatura/secret do webhook é comparada com == ou === (comparação curto-circuito, sensível a timing) em vez de comparação de tempo constante.',
    impact:
      'Comparações não constantes vazam informação por timing e, quando o "secret" é comparado como string simples, abrem espaço para bypass/forja da verificação de autenticidade.',
    attackScenarioDefensive:
      'O handler faz `if (req.headers["x-signature"] === assinaturaCalculada)`. Um atacante explora diferenças de timing ou aproveita comparações frágeis para contornar a checagem.',
    remediation:
      'Use crypto.timingSafeEqual (ou equivalente) para comparar assinaturas/HMAC. Garanta buffers de mesmo tamanho antes de comparar.',
    safeExample:
      "const a = Buffer.from(assinaturaCalculada);\nconst b = Buffer.from(req.headers['x-signature'] || '');\nif (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).end();",
    testSuggestion:
      'Revise o handler e confirme que a comparação de assinatura usa timingSafeEqual e não == / ===.',
    reference: 'CWE-208 (Observable Timing Discrepancy); OWASP A04:2025',
    requireContent: /signature|assinatura|hmac|webhook/i,
    patterns: [
      /(?:signature|assinatura|hmac|digest|hash)\s*(?:===?|==)\s*(?:req|request|headers)\.[A-Za-z0-9_.\[\]'"`-]+/i,
      /(?:req|request|headers)\.[A-Za-z0-9_.\[\]'"`-]*(?:signature|assinatura)[A-Za-z0-9_.\[\]'"`-]*\s*(?:===?|==)\s*[A-Za-z0-9_.]/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
];
