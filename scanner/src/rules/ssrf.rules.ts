import { FileRule } from '../types';

export const ssrfRules: FileRule[] = [
  {
    id: 'SSRF_001',
    title: 'Requisição HTTP server-side com URL controlada (SSRF)',
    category: 'SSRF',
    severity: 'high',
    confidence: 'medium',
    description: 'fetch/axios/https.get/requests recebendo diretamente req.body/query/params como URL, ou interpolando esses valores na URL.',
    impact: 'Server-Side Request Forgery: o servidor faz requisições a destinos arbitrários, permitindo acesso a serviços internos e metadados de nuvem.',
    attackScenarioDefensive: 'Atacante envia url=http://169.254.169.254/latest/meta-data/ e o servidor busca e devolve credenciais do provedor de nuvem.',
    remediation: 'Valide a URL contra uma allowlist de hosts permitidos, bloqueie IPs privados/link-local (169.254.169.254, 10.0.0.0/8, 127.0.0.0/8) e use redirect: "error".',
    safeExample: "const ALLOW = new Set(['api.parceiro.com']);\nconst u = new URL(req.body.url);\nif (!ALLOW.has(u.hostname)) return res.sendStatus(400);\nawait fetch(u, { redirect: 'error' });",
    testSuggestion: 'Enviar URLs apontando para 169.254.169.254, localhost e IPs privados e confirmar que são bloqueadas.',
    reference: 'OWASP A01:2025 - Broken Access Control (SSRF); CWE-918',
    patterns: [
      /(?:fetch|axios(?:\.get|\.post)?|https?\.get|requests\.(?:get|post))\s*\(\s*(?:req\.(?:body|query|params)|`[^`]*\$\{[^}]*req\.(?:body|query|params))/i,
    ],
    fileExtensions: ['.js', '.ts', '.py', '.mjs'],
  },
  {
    id: 'SSRF_002',
    title: 'Endpoint de metadados de nuvem referenciado no código',
    category: 'SSRF',
    severity: 'high',
    confidence: 'high',
    description:
      'O código referencia o IP link-local de metadados de instância (169.254.169.254) ou os endpoints de metadados de GCP/Azure — alvos clássicos de exfiltração de credenciais via SSRF.',
    impact:
      'O serviço de metadados entrega credenciais temporárias da role da instância (AWS IMDS), tokens de service account (GCP) ou tokens do Azure AD. Com elas o atacante acessa recursos da nuvem diretamente.',
    attackScenarioDefensive:
      'Explorando um SSRF, o atacante força o servidor a buscar http://169.254.169.254/latest/meta-data/iam/security-credentials/ e recebe AccessKeyId/SecretAccessKey da role, assumindo os privilégios da aplicação na AWS.',
    remediation:
      'Exija IMDSv2 (tokens obrigatórios, hop limit 1) nas instâncias EC2, bloqueie 169.254.0.0/16 no egress da aplicação e nunca permita que URLs controladas pelo usuário alcancem esse range.',
    safeExample:
      '# Terraform: força IMDSv2 e impede acesso via SSRF em containers\nmetadata_options {\n  http_tokens                 = "required"\n  http_put_response_hop_limit = 1\n  http_endpoint               = "enabled"\n}',
    testSuggestion:
      'A partir de um endpoint que aceita URL, tente alcançar 169.254.169.254 e confirme que a requisição é bloqueada.',
    reference: 'OWASP A01:2025 - Broken Access Control (SSRF); CWE-918; AWS IMDSv2',
    patterns: [
      /169\.254\.169\.254/,
      /metadata\.google\.internal/i,
      /metadata\.azure\.com|169\.254\.169\.254\/metadata\/identity/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.py', '.tf', '.yml', '.yaml', '.json', '.env'],
  },
  {
    id: 'SSRF_003',
    title: 'Requisição server-side seguindo redirects sem restrição',
    category: 'SSRF',
    severity: 'medium',
    confidence: 'low',
    description:
      'Requisição HTTP server-side com URL de origem externa que segue redirects automaticamente (comportamento padrão), sem redirect: "error"/maxRedirects: 0.',
    impact:
      'Mesmo com allowlist no host inicial, um destino externo pode responder 302 apontando para 169.254.169.254 ou para a rede interna, contornando a validação (SSRF via redirect).',
    attackScenarioDefensive:
      'O atacante informa uma URL de domínio permitido que ele controla; o servidor valida o host, faz a requisição e é redirecionado para o serviço de metadados interno, vazando credenciais.',
    remediation:
      'Desative o follow automático (redirect: "error" no fetch, maxRedirects: 0 no axios) ou revalide o destino contra a allowlist a cada salto de redirect.',
    safeExample:
      "const resp = await fetch(urlValidada, { redirect: 'error' });\n// axios: await axios.get(url, { maxRedirects: 0 });",
    testSuggestion:
      'Aponte para um servidor que responde 302 para um IP interno e confirme que a aplicação não segue o redirect.',
    reference: 'OWASP A01:2025 - Broken Access Control (SSRF); CWE-918',
    patterns: [
      /(?:fetch|axios\.get|axios\s*\()\s*\(?[^;\n]{0,80}(?:userUrl|targetUrl|remoteUrl|webhookUrl|callbackUrl|imageUrl|avatarUrl)[^;\n]{0,80}\)/i,
    ],
    suppressIfProjectMatches: /redirect\s*:\s*["'`]error["'`]|maxRedirects\s*:\s*0|followRedirect\s*:\s*false/i,
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'SSRF_004',
    title: 'URL de webhook/callback definida pelo usuário sem validação',
    category: 'SSRF',
    severity: 'high',
    confidence: 'medium',
    description:
      'A aplicação aceita uma URL de webhook/callback do usuário e a persiste ou invoca sem validar esquema, host e faixa de IP.',
    impact:
      'Transforma a aplicação em proxy para a rede interna: o atacante cadastra um webhook apontando para serviços internos (Redis, Elasticsearch, painéis admin) e usa o servidor para alcançá-los.',
    attackScenarioDefensive:
      'O atacante cadastra o webhook http://127.0.0.1:9200/_search; quando o evento dispara, o servidor consulta o Elasticsearch interno e o conteúdo aparece nos logs de entrega do webhook.',
    remediation:
      'Valide o esquema (apenas https), resolva o DNS e rejeite IPs privados/link-local/loopback antes de salvar E antes de cada envio (o DNS pode mudar — DNS rebinding). Prefira egress por proxy dedicado.',
    safeExample:
      "import dns from 'node:dns/promises';\nimport ipaddr from 'ipaddr.js';\nconst u = new URL(destino);\nif (u.protocol !== 'https:') throw new Error('apenas https');\nconst { address } = await dns.lookup(u.hostname);\nif (ipaddr.parse(address).range() !== 'unicast') throw new Error('IP interno bloqueado');",
    testSuggestion:
      'Cadastre webhooks para http://localhost, 127.0.0.1, 10.0.0.1 e 169.254.169.254 e confirme que todos são recusados.',
    reference: 'OWASP A01:2025 - Broken Access Control (SSRF); CWE-918',
    patterns: [
      /(?:webhookUrl|webhook_url|callbackUrl|callback_url|notifyUrl|notify_url)\s*[:=]\s*req\.(?:body|query|params)\./i,
      /(?:create|update|save)\s*\(\s*\{[^}]{0,160}(?:webhook|callback)Url\s*:\s*req\.(?:body|query)\./i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'SSRF_005',
    title: 'Renderização/download de URL do usuário (PDF, imagem, preview)',
    category: 'SSRF',
    severity: 'high',
    confidence: 'medium',
    description:
      'Headless browser (Puppeteer/Playwright), gerador de PDF ou processador de imagem recebendo URL/HTML controlado pelo usuário.',
    impact:
      'O navegador headless roda no servidor e alcança a rede interna: além de SSRF, pode ler arquivos locais via file:// e exfiltrar o conteúdo dentro do PDF/imagem gerado.',
    attackScenarioDefensive:
      'O atacante pede um PDF de "https://meusite" mas envia file:///etc/passwd ou http://169.254.169.254/...; o conteúdo interno é renderizado no PDF que ele mesmo baixa.',
    remediation:
      'Valide a URL contra allowlist, bloqueie esquemas file://, gopher:// e data:, execute o browser em rede isolada (sem rota para a VPC/metadados) e com usuário sem privilégios.',
    safeExample:
      "const u = new URL(entrada);\nif (u.protocol !== 'https:') throw new Error('esquema invalido');\nif (!HOSTS_PERMITIDOS.has(u.hostname)) throw new Error('host nao permitido');\nawait page.goto(u.toString(), { waitUntil: 'networkidle0', timeout: 10_000 });",
    testSuggestion:
      'Solicite a renderização de file:///etc/passwd e de um IP interno e confirme que ambas falham.',
    reference: 'OWASP A01:2025 - Broken Access Control (SSRF); CWE-918; CWE-73',
    patterns: [
      /page\.(?:goto|setContent)\s*\(\s*(?:req\.(?:body|query|params)\.|`[^`]*\$\{[^}]*req\.(?:body|query|params))/i,
      /(?:pdf|screenshot|render)\w*\s*\([^)]{0,80}(?:req\.(?:body|query)\.(?:url|html)|userUrl|targetUrl)/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
];
