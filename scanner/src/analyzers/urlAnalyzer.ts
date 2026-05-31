import { Finding, ScanLog, TechStack } from '@sentinelscope/shared';
import { UrlScanOptions, ScanResultRaw } from '../types';
import { safeGet, checkPath } from '../utils/safeHttpClient';
import { headersRules } from '../rules/headers.rules';

const SAFE_PATHS_TO_CHECK = [
  '/robots.txt',
  '/sitemap.xml',
  '/.well-known/security.txt',
  '/api',
  '/api/health',
  '/swagger',
  '/api-docs',
  '/swagger-ui.html',
  '/graphql',
  '/admin',
  '/debug',
  '/.env',
  '/server-status',
  '/phpinfo.php',
  '/wp-login.php',
  '/wp-admin',
];

const STEPS = [
  { label: 'Verificando conectividade e HTTPS', progress: 10 },
  { label: 'Analisando headers de segurança', progress: 30 },
  { label: 'Verificando CORS', progress: 45 },
  { label: 'Verificando caminhos comuns', progress: 60 },
  { label: 'Verificando certificado TLS', progress: 75 },
  { label: 'Verificando tecnologias expostas', progress: 85 },
  { label: 'Gerando relatório', progress: 95 },
];

export async function analyzeUrl(opts: UrlScanOptions): Promise<ScanResultRaw> {
  const { url, scanId, onEvent, customHeaders = {}, depth = 'normal' } = opts;
  const findings: Array<Omit<Finding, 'id' | 'createdAt'>> = [];
  const logs: Array<Omit<ScanLog, 'id' | 'createdAt'>> = [];
  const techStack: TechStack[] = [];

  function log(level: 'info' | 'warn' | 'error', message: string) {
    logs.push({ scanId, level, message });
    onEvent({ type: 'log', level, message });
  }

  function progress(step: string, pct: number) {
    onEvent({ type: 'progress', step, progress: pct });
  }

  function addFinding(
    ruleId: string,
    title: string,
    category: string,
    severity: Finding['severity'],
    description: string,
    impact: string,
    remediation: string,
    evidence?: string,
    safeExample?: string,
    reference?: string
  ) {
    findings.push({
      scanId,
      ruleId,
      title,
      category,
      severity,
      url,
      evidenceMasked: evidence,
      description,
      impact,
      remediation,
      safeExample,
      reference,
      confidence: 'medium',
      status: 'open',
      occurrences: 1,
    });
    onEvent({ type: 'finding', finding: findings[findings.length - 1] });
  }

  log('info', `Iniciando análise da URL: ${url}`);

  // STEP 1: Connectivity & HTTPS
  progress(STEPS[0].label, STEPS[0].progress);
  log('info', STEPS[0].label);

  const mainResponse = await safeGet(url, customHeaders);

  if (mainResponse.error) {
    log('error', `Falha ao conectar: ${mainResponse.error}`);
    return { findings, techStack, logs };
  }

  log('info', `Status HTTP: ${mainResponse.statusCode} | Redirects: ${mainResponse.redirectChain.length}`);

  // Check HTTPS
  if (!url.startsWith('https://')) {
    addFinding(
      'URL_001', 'HTTPS não utilizado', 'Headers HTTP', 'high',
      'A URL não usa HTTPS, transmitindo dados em texto puro.',
      'Dados em trânsito podem ser interceptados.',
      'Configure HTTPS com certificado válido e redirecione HTTP para HTTPS.',
      'http://',
      'https://meudominio.com',
      'OWASP A02:2021 - Cryptographic Failures'
    );
  }

  // Check HTTP -> HTTPS redirect
  if (url.startsWith('https://')) {
    const httpUrl = url.replace('https://', 'http://');
    const httpResp = await safeGet(httpUrl);
    const redirectedToHttps = httpResp.finalUrl?.startsWith('https://') ||
      httpResp.redirectChain.some(r => r.startsWith('https://'));
    if (httpResp.statusCode > 0 && !redirectedToHttps) {
      addFinding(
        'URL_002', 'HTTP não redireciona para HTTPS', 'Headers HTTP', 'medium',
        'Acessar via HTTP não redireciona para HTTPS.',
        'Usuários que digitam a URL sem https:// ficam em conexão insegura.',
        'Configure redirect 301 de HTTP para HTTPS no servidor web.',
        undefined,
        'location: https://meudominio.com/',
        'OWASP A02:2021'
      );
    }
  }

  // STEP 2: Headers analysis
  progress(STEPS[1].label, STEPS[1].progress);
  log('info', STEPS[1].label);

  const headers = mainResponse.headers;

  for (const rule of headersRules) {
    if (rule.check(headers, mainResponse.body)) {
      addFinding(
        rule.id,
        rule.title,
        rule.category,
        rule.severity,
        rule.description,
        rule.impact,
        rule.remediation,
        headers[rule.id.toLowerCase()] || undefined,
        rule.safeExample,
        rule.reference
      );
    }
  }

  // Check for sensitive header info
  if (headers['server'] && /\d/.test(headers['server'])) {
    log('warn', `Server header revela versão: ${headers['server']}`);
  }

  if (headers['x-powered-by']) {
    log('warn', `X-Powered-By: ${headers['x-powered-by']}`);
  }

  // Detect technology from headers
  if (headers['x-powered-by']) {
    const tech = headers['x-powered-by'];
    if (tech.toLowerCase().includes('next')) techStack.push({ name: 'Next.js', category: 'frontend' });
    else if (tech.toLowerCase().includes('express')) techStack.push({ name: 'Express', category: 'backend' });
    else if (tech.toLowerCase().includes('php')) techStack.push({ name: 'PHP', category: 'backend' });
  }

  if (headers['server']) {
    const s = headers['server'].toLowerCase();
    if (s.includes('nginx')) techStack.push({ name: 'nginx', category: 'devops' });
    if (s.includes('apache')) techStack.push({ name: 'Apache', category: 'devops' });
    if (s.includes('cloudflare')) techStack.push({ name: 'Cloudflare', category: 'devops' });
  }

  // STEP 3: CORS
  progress(STEPS[2].label, STEPS[2].progress);
  log('info', STEPS[2].label);

  const corsOrigin = headers['access-control-allow-origin'];
  const corsCredentials = headers['access-control-allow-credentials'];

  if (corsOrigin === '*') {
    addFinding(
      'CORS_001', 'CORS configurado com wildcard (*)', 'CORS', 'high',
      'Access-Control-Allow-Origin: * permite qualquer origem.',
      'Qualquer site pode fazer requisições à sua API.',
      'Defina uma whitelist de origens específicas.',
      'Access-Control-Allow-Origin: *',
      "cors({ origin: ['https://app.com'] })",
      'OWASP A05:2021'
    );
  }

  if (corsOrigin === '*' && corsCredentials === 'true') {
    addFinding(
      'CORS_009', 'CORS wildcard com credentials=true', 'CORS', 'critical',
      'Combinação inválida e perigosa de CORS.',
      'Pode permitir ataques CSRF em alguns cenários.',
      'Nunca combine Allow-Origin: * com credentials: true.',
      `Origin: * | Credentials: true`,
      undefined,
      'OWASP A05:2021'
    );
  }

  // STEP 4: Check common paths (only in normal/deep mode)
  progress(STEPS[3].label, STEPS[3].progress);
  log('info', STEPS[3].label);

  const pathsToCheck = depth === 'quick' ? SAFE_PATHS_TO_CHECK.slice(0, 5) : SAFE_PATHS_TO_CHECK;

  for (const checkPathStr of pathsToCheck) {
    const resp = await checkPath(url, checkPathStr);

    if (resp.statusCode === 200) {
      log('info', `Caminho acessível: ${checkPathStr} (${resp.statusCode})`);

      if (checkPathStr === '/swagger' || checkPathStr === '/api-docs') {
        addFinding(
          'API_001', 'Swagger/API docs público', 'API', 'low',
          'Documentação da API está publicamente acessível.',
          'Facilita reconhecimento por atacantes.',
          'Proteja documentação com autenticação em produção.',
          `${url}${checkPathStr}`,
          undefined,
          'OWASP API9:2023'
        );
      }

      if (checkPathStr === '/graphql') {
        addFinding(
          'API_002', 'GraphQL endpoint público', 'API', 'medium',
          'Endpoint GraphQL acessível sem autenticação.',
          'Possível introspection do schema completo.',
          'Restrinja acesso e desabilite introspection em produção.',
          `${url}${checkPathStr}`,
          undefined,
          'OWASP API9:2023'
        );
      }

      if (checkPathStr === '/.env') {
        addFinding(
          'SECRET_004', 'Arquivo .env publicamente acessível', 'Secrets', 'critical',
          'O arquivo .env está acessível publicamente.',
          'Todos os secrets da aplicação estão expostos.',
          'Bloqueie acesso a arquivos .env no servidor web. Nunca sirva arquivos de configuração.',
          `${url}/.env`,
          undefined,
          'OWASP A02:2021'
        );
      }

      if (checkPathStr === '/debug' || checkPathStr === '/server-status') {
        addFinding(
          'API_003', 'Endpoint de debug/diagnóstico público', 'API', 'medium',
          `Endpoint ${checkPathStr} está publicamente acessível.`,
          'Exposição de informações internas da aplicação.',
          'Remova ou proteja endpoints de diagnóstico.',
          `${url}${checkPathStr}`,
          undefined,
          'OWASP A05:2021'
        );
      }

      if (checkPathStr === '/admin') {
        addFinding(
          'AUTHZ_001', 'Painel admin acessível', 'Autorização', 'medium',
          'Painel administrativo retornou status 200.',
          'Painel admin pode estar acessível sem autenticação.',
          'Verifique se o painel exige autenticação. Restrinja por IP se possível.',
          `${url}/admin`,
          undefined,
          'OWASP A01:2021'
        );
      }
    }
  }

  // STEP 5: TLS Certificate
  progress(STEPS[4].label, STEPS[4].progress);
  log('info', STEPS[4].label);

  if (mainResponse.tlsExpiry) {
    const daysToExpiry = Math.floor((mainResponse.tlsExpiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    if (daysToExpiry < 30) {
      addFinding(
        'TLS_001', `Certificado TLS expira em ${daysToExpiry} dias`, 'TLS/HTTPS', 'high',
        `O certificado TLS expira em ${mainResponse.tlsExpiry.toISOString().split('T')[0]}.`,
        'Certificado expirado causa erros nos browsers e possibilita MITM.',
        'Renove o certificado com antecedência. Use certbot para renovação automática.',
        `Expira: ${mainResponse.tlsExpiry.toDateString()}`,
        undefined,
        'OWASP A02:2021'
      );
    }

    if (!mainResponse.tlsValid) {
      addFinding(
        'TLS_002', 'Certificado TLS inválido', 'TLS/HTTPS', 'critical',
        'O certificado TLS não é válido (pode ser auto-assinado ou incorreto).',
        'Usuários recebem avisos de segurança. Conexão vulnerável a MITM.',
        'Use certificado de CA confiável (Let\'s Encrypt, DigiCert, etc.).',
        undefined,
        undefined,
        'OWASP A02:2021'
      );
    }
  }

  // STEP 6: Detect technologies
  progress(STEPS[5].label, STEPS[5].progress);
  log('info', STEPS[5].label);

  const body = mainResponse.body;
  if (body.includes('__NEXT_DATA__')) techStack.push({ name: 'Next.js', category: 'frontend' });
  if (body.includes('react-root') || body.includes('__reactFiber')) techStack.push({ name: 'React', category: 'frontend' });
  if (body.includes('wp-content') || body.includes('wp-includes')) techStack.push({ name: 'WordPress', category: 'backend' });
  if (body.includes('__nuxt')) techStack.push({ name: 'Nuxt.js', category: 'frontend' });

  progress(STEPS[6].label, STEPS[6].progress);
  log('info', `Análise de URL concluída. ${findings.length} achados encontrados.`);

  return { findings, techStack, logs };
}
