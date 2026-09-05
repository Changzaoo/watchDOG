import { FileRule } from '../types';

/**
 * Falhas específicas de framework (Next.js, Express, Vite, Nest).
 *
 * Complementa as regras genéricas cobrindo armadilhas de arquitetura que
 * só existem em um framework — como autorização feita apenas no middleware
 * do Next.js (contornável pelo header x-middleware-subrequest, CVE-2025-29927)
 * ou trust proxy mal configurado no Express (spoof de IP e bypass de rate limit).
 */
export const frameworkRules: FileRule[] = [
  {
    id: 'FRAME_001',
    title: 'Autorização feita apenas no middleware do Next.js',
    category: 'Framework',
    severity: 'high',
    confidence: 'medium',
    description:
      'O middleware do Next.js (middleware.ts/.js) é o único ponto que verifica autenticação/role e redireciona não autorizados, sem revalidação dentro das rotas, route handlers ou server actions.',
    impact:
      'O middleware é uma camada de borda, não um controle de acesso confiável. A CVE-2025-29927 permitiu pular o middleware inteiro apenas enviando o header x-middleware-subrequest; qualquer falha semelhante expõe todas as rotas "protegidas" de uma vez.',
    attackScenarioDefensive:
      'O atacante envia a requisição para /admin com o header x-middleware-subrequest; o middleware é ignorado e, como a página e a API não revalidam a sessão, ele acessa o painel administrativo sem autenticação.',
    remediation:
      'Trate o middleware como otimização de UX, nunca como fronteira de segurança. Revalide sessão e permissão dentro de cada route handler, server action e server component que acesse dados sensíveis. Mantenha o Next.js atualizado (>= 14.2.25 / >= 15.2.3).',
    safeExample:
      "// app/admin/page.tsx — valida de novo no servidor, alem do middleware\nconst session = await auth();\nif (!session || session.user.role !== 'admin') redirect('/login');\n\n// app/api/admin/route.ts\nexport async function GET() {\n  const session = await auth();\n  if (session?.user.role !== 'admin') {\n    return NextResponse.json({ error: 'forbidden' }, { status: 403 });\n  }\n}",
    testSuggestion:
      'Envie uma requisição a uma rota protegida com o header x-middleware-subrequest preenchido e confirme que ela continua exigindo autenticação.',
    reference: 'CVE-2025-29927; OWASP A01:2025 - Broken Access Control; CWE-306',
    fileNamePatterns: [/(?:^|\/)middleware\.(?:ts|js|mjs)$/],
    patterns: [
      /NextResponse\.redirect\s*\([^)]*(?:login|signin|auth)/i,
      /export\s+(?:async\s+)?function\s+middleware\s*\([\s\S]{0,400}?(?:token|session|cookies\(\)|getToken|auth)/i,
    ],
    fileExtensions: ['.ts', '.js', '.mjs'],
  },
  {
    id: 'FRAME_002',
    title: 'Header x-middleware-subrequest confiável (CVE-2025-29927)',
    category: 'Framework',
    severity: 'critical',
    confidence: 'high',
    description:
      'O código lê ou confia no header interno x-middleware-subrequest do Next.js, usado pelo framework para evitar loops de middleware — e explorado para pular o middleware por completo.',
    impact:
      'Um header controlável pelo cliente decide se o middleware roda. Isso permite bypass total de autenticação, autorização e qualquer proteção implementada nessa camada.',
    attackScenarioDefensive:
      'O atacante adiciona x-middleware-subrequest: middleware na requisição; o Next.js considera que a chamada é interna, pula o middleware de auth e serve a rota protegida.',
    remediation:
      'Atualize o Next.js para uma versão corrigida (>= 15.2.3, >= 14.2.25, >= 13.5.9). Bloqueie o header x-middleware-subrequest na borda (CDN/WAF/proxy) e nunca o utilize em lógica própria.',
    safeExample:
      "// Na borda (nginx/Cloudflare), remova o header vindo de fora:\n// proxy_set_header x-middleware-subrequest \"\";\n// E revalide a sessao dentro de cada rota protegida.",
    testSuggestion:
      'Faça a mesma requisição com e sem o header x-middleware-subrequest e confirme que o resultado de autorização é idêntico.',
    reference: 'CVE-2025-29927 - Next.js Middleware Authorization Bypass; CWE-290',
    patterns: [
      /x-middleware-subrequest/i,
    ],
    fileExtensions: ['.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx', '.conf', '.yml', '.yaml'],
  },
  {
    id: 'FRAME_003',
    title: 'Express com trust proxy irrestrito',
    category: 'Framework',
    severity: 'medium',
    confidence: 'high',
    description:
      "Configuração app.set('trust proxy', true) — ou enable('trust proxy') — que faz o Express confiar no header X-Forwarded-For de qualquer origem.",
    impact:
      'Com trust proxy irrestrito, o cliente pode forjar X-Forwarded-For e alterar o IP visto pela aplicação, contornando rate limiting por IP, allowlists de acesso e envenenando logs e trilhas de auditoria.',
    attackScenarioDefensive:
      'O atacante envia X-Forwarded-For: 1.2.3.4 diferente a cada requisição; o express-rate-limit conta cada uma como um IP distinto e o limite de tentativas de login nunca é atingido, viabilizando força bruta.',
    remediation:
      "Confie apenas nos proxies reais: use um número de saltos (app.set('trust proxy', 1)) ou a lista de IPs/sub-redes do seu load balancer, em vez de true.",
    safeExample:
      "// Atras de exatamente um proxy (ex.: Cloudflare -> app)\napp.set('trust proxy', 1);\n// Ou por sub-rede confiavel:\napp.set('trust proxy', ['10.0.0.0/8', 'loopback']);",
    testSuggestion:
      'Envie X-Forwarded-For forjado e confirme que o rate limiting continua contando pelo IP real da conexão.',
    reference: 'OWASP A02:2025 - Security Misconfiguration; CWE-348',
    patterns: [
      /\.set\s*\(\s*["'`]trust proxy["'`]\s*,\s*true\s*\)/i,
      /\.enable\s*\(\s*["'`]trust proxy["'`]\s*\)/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'FRAME_004',
    title: 'Server Action / route handler sem verificação de sessão',
    category: 'Framework',
    severity: 'high',
    confidence: 'low',
    description:
      "Server Action do Next.js ('use server') que executa escrita/mutação sem verificar a sessão do usuário no início da função.",
    impact:
      'Server Actions são endpoints HTTP públicos gerados automaticamente. Sem verificação própria, qualquer pessoa pode invocá-las diretamente, ignorando totalmente a interface e suas validações.',
    attackScenarioDefensive:
      'O atacante inspeciona o bundle, descobre o identificador da Server Action de exclusão e a invoca por POST direto, apagando registros de outro usuário sem nunca passar pela tela protegida.',
    remediation:
      'Trate cada Server Action como um endpoint público: valide a sessão, a permissão e os dados de entrada (schema) logo na primeira linha, antes de qualquer efeito.',
    safeExample:
      "'use server';\nexport async function excluirPost(id: string) {\n  const session = await auth();\n  if (!session) throw new Error('nao autenticado');\n  const post = await db.post.findFirst({ where: { id, autorId: session.user.id } });\n  if (!post) throw new Error('nao autorizado');\n  await db.post.delete({ where: { id } });\n}",
    testSuggestion:
      'Invoque a Server Action por requisição HTTP direta, sem sessão válida, e confirme que ela é recusada.',
    reference: 'OWASP A01:2025 - Broken Access Control; CWE-306',
    requireContent: /['"`]use server['"`]/,
    patterns: [
      /['"`]use server['"`][\s\S]{0,600}?export\s+async\s+function\s+\w+\s*\([^)]*\)\s*\{(?:(?!auth\(|getSession|currentUser|session|verifyToken|requireUser)[\s\S]){0,300}?(?:prisma|db)\.\w+\.(?:delete|update|create|upsert)/,
    ],
    fileExtensions: ['.ts', '.tsx', '.js', '.jsx'],
  },
  {
    id: 'FRAME_005',
    title: 'Variável de ambiente sensível exposta ao cliente (Vite/CRA)',
    category: 'Framework',
    severity: 'critical',
    confidence: 'medium',
    description:
      'Segredo com nome sensível (SECRET, PRIVATE, TOKEN, PASSWORD, SERVICE_ROLE) declarado com prefixo público (VITE_, REACT_APP_, PUBLIC_, NUXT_PUBLIC_), que embute o valor no bundle do navegador.',
    impact:
      'Tudo que tem prefixo público é compilado no JavaScript entregue ao usuário. O segredo fica legível para qualquer visitante no DevTools, permitindo uso direto das credenciais.',
    attackScenarioDefensive:
      'O desenvolvedor renomeia SUPABASE_SERVICE_ROLE_KEY para VITE_SUPABASE_SERVICE_ROLE_KEY para "resolver" um erro de build; a chave de admin passa a ser servida no bundle e qualquer visitante lê o banco inteiro.',
    remediation:
      'Nunca use prefixo público em segredos. Mantenha-os sem prefixo (só no servidor) e exponha ao cliente apenas valores realmente públicos, acessando os segredos por meio de um endpoint backend.',
    safeExample:
      "# .env (servidor, sem prefixo publico)\nSUPABASE_SERVICE_ROLE_KEY=...\nSTRIPE_SECRET_KEY=...\n\n# .env (cliente, apenas valores publicos)\nVITE_SUPABASE_URL=https://xxx.supabase.co\nVITE_SUPABASE_ANON_KEY=eyJ...",
    testSuggestion:
      'Rode o build de produção e faça grep no bundle pelos valores dos segredos: nenhum deve aparecer.',
    reference: 'OWASP A04:2025; CWE-200; CWE-798',
    patterns: [
      /(?:VITE_|REACT_APP_|NEXT_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD|CLIENT_SECRET)[A-Z0-9_]*\s*=/,
      /(?:VITE_|REACT_APP_|NEXT_PUBLIC_|PUBLIC_)[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|CLIENT_SECRET)[A-Z0-9_]*/,
    ],
    fileExtensions: ['.env', '.js', '.ts', '.jsx', '.tsx', '.mjs'],
  },
  {
    id: 'FRAME_006',
    title: 'Servidor de desenvolvimento Vite exposto na rede',
    category: 'Framework',
    severity: 'medium',
    confidence: 'medium',
    description:
      'Configuração do Vite com server.host habilitado (0.0.0.0/true) e/ou allowedHosts permissivo, expondo o dev server para fora da máquina local.',
    impact:
      'O dev server serve o código-fonte, o .env carregado e o filesystem do projeto sem autenticação. Exposto na rede, entrega segredos e código a qualquer um que alcance a porta.',
    attackScenarioDefensive:
      'Com o dev server em 0.0.0.0, alguém na mesma rede (ou via túnel exposto) acessa /@fs/ e lê arquivos arbitrários do projeto, incluindo o .env com as chaves de produção.',
    remediation:
      'Mantenha o dev server em localhost. Se precisar expor para testar em outro dispositivo, restrinja allowedHosts, use um túnel autenticado e nunca carregue segredos de produção em desenvolvimento.',
    safeExample:
      "export default defineConfig({\n  server: {\n    host: 'localhost',\n    fs: { strict: true },\n  },\n});",
    testSuggestion:
      'De outra máquina na mesma rede, tente acessar a porta do dev server e confirme que a conexão é recusada.',
    reference: 'OWASP A02:2025 - Security Misconfiguration; CWE-668',
    fileNamePatterns: [/vite\.config\.(?:ts|js|mjs)$/],
    patterns: [
      /host\s*:\s*(?:true|["'`]0\.0\.0\.0["'`])/,
      /allowedHosts\s*:\s*(?:true|\[\s*["'`]\s*\.?\s*all\s*["'`])/i,
    ],
    fileExtensions: ['.ts', '.js', '.mjs'],
  },
];
