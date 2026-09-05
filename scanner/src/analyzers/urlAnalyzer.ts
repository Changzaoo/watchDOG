import { Finding, ScanLog, TechStack } from '@sentinelscope/shared';
import { UrlScanOptions, ScanResultRaw } from '../types';
import { safeGet, checkPath } from '../utils/safeHttpClient';
import { headersRules } from '../rules/headers.rules';
import { dosHeadersRules } from '../rules/dosHeaders.rules';
import { secretsRules } from '../rules/secrets.rules';
import { analyzeDns } from './dnsAnalyzer';
import { scanJsLibraries } from './jsLibScanner';
import { maskLine } from '../utils/maskSecret';

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

// Paths adicionais de exposição/reconhecimento sondados em depth normal/deep.
const EXTRA_PATHS_TO_CHECK = [
  '/.git/HEAD',
  '/actuator/health',
  '/.well-known/openid-configuration',
];

// Caminhos comuns de webhook de pagamento. Sondados APENAS com GET (passivo,
// sem enviar nenhum payload de evento). O objetivo é puramente defensivo:
// alertar o dono de que o endpoint é descobrível — como no vídeo, em que o
// atacante achou o webhook por fuzzing — para que ele garanta verificação de
// assinatura. O watchDOG NUNCA envia um POST de "pagamento aprovado".
const WEBHOOK_PATHS_TO_CHECK = [
  '/api/webhook',
  '/api/webhooks',
  '/webhook',
  '/webhooks',
  '/api/webhook/stripe',
  '/api/webhook/kirvano',
  '/api/webhook/cacto',
  '/api/payment/webhook',
  '/api/billing/webhook',
];

// Arquivos de backup/artefatos que nunca deveriam estar publicados.
// Sondados apenas com GET em depth deep (lista curta e educada).
const LEAK_PATHS_TO_CHECK = [
  '/.DS_Store',
  '/.env.local',
  '/.env.production',
  '/config.json.bak',
  '/backup.sql',
  '/.npmrc',
  '/.git/config',
  '/docker-compose.yml',
  '/web.config',
  '/.htpasswd',
];

// Endpoints do Spring Boot Actuator que realmente vazam dados sensíveis.
// Sondados em normal/deep (GET; heapdump usa maxBodyBytes=0 para não baixar o dump).
const ACTUATOR_PATHS: Array<{ path: string; severity: Finding['severity']; label: string; headOnly?: boolean }> = [
  { path: '/actuator/env', severity: 'critical', label: 'variáveis de ambiente (credenciais, secrets)' },
  { path: '/actuator/heapdump', severity: 'critical', label: 'dump de memória (secrets em runtime)', headOnly: true },
  { path: '/actuator/mappings', severity: 'high', label: 'mapa de rotas internas' },
  { path: '/actuator/beans', severity: 'high', label: 'grafo de beans/estrutura interna' },
  { path: '/actuator/configprops', severity: 'high', label: 'propriedades de configuração' },
  { path: '/actuator/loggers', severity: 'medium', label: 'configuração de logging (mutável via POST)' },
];

// Painéis administrativos e ferramentas de dev que nunca deveriam estar públicos.
// Fingerprint por título/corpo, não só status 200 (evita falso-positivo de SPA).
const ADMIN_TOOL_PATHS: Array<{ path: string; tool: string; signature: RegExp; severity: Finding['severity'] }> = [
  { path: '/phpmyadmin/', tool: 'phpMyAdmin', signature: /phpMyAdmin|pma_username/i, severity: 'high' },
  { path: '/adminer.php', tool: 'Adminer', signature: /Adminer|Login - Adminer/i, severity: 'high' },
  { path: '/telescope/requests', tool: 'Laravel Telescope', signature: /Telescope|laravel-telescope/i, severity: 'high' },
  { path: '/_profiler/', tool: 'Symfony Profiler', signature: /Symfony Profiler|sf-toolbar/i, severity: 'high' },
  { path: '/grafana/login', tool: 'Grafana', signature: /Grafana|grafana-app/i, severity: 'medium' },
  { path: '/app/kibana', tool: 'Kibana', signature: /kibana|kbn-injected-metadata/i, severity: 'medium' },
  { path: '/_cat/indices', tool: 'Elasticsearch', signature: /green\s+open|yellow\s+open|health\s+status\s+index/i, severity: 'high' },
];

// Assinaturas de páginas de erro verbosas / debug ligado em produção (OWASP 2025 A10).
const DEBUG_SIGNATURES: Array<{ id: string; tech: string; pattern: RegExp; severity: Finding['severity']; note: string }> = [
  { id: 'DEBUG_001', tech: 'Laravel (Ignition)', pattern: /Ignition|Illuminate\\|APP_DEBUG|laravel\/framework|\/vendor\/laravel/i, severity: 'critical', note: 'Ignition < 2.5.2 permite RCE (CVE-2021-3129). Exposição de .env e stack trace.' },
  { id: 'DEBUG_002', tech: 'Django (DEBUG=True)', pattern: /Traceback \(most recent call last\)|You're seeing this error because you have <code>DEBUG = True|DisallowedHost at|django\.core\.exceptions/i, severity: 'critical', note: 'DEBUG=True expõe settings, variáveis locais e SQL. Nunca use em produção.' },
  { id: 'DEBUG_003', tech: 'Spring Boot (Whitelabel)', pattern: /Whitelabel Error Page|There was an unexpected error \(type=/i, severity: 'medium', note: 'Whitelabel revela que é Spring Boot; com trace=true expõe stack completo.' },
  { id: 'DEBUG_004', tech: 'Ruby on Rails', pattern: /Action Controller: Exception caught|ActionController::RoutingError|<title>Action Controller/i, severity: 'high', note: 'Página de exceção do Rails com detalhes internos (config.consider_all_requests_local).' },
  { id: 'DEBUG_005', tech: 'ASP.NET', pattern: /Server Error in '\/' Application|<b>Stack Trace:<\/b>|<b>Version Information:<\/b>|\[HttpException/i, severity: 'high', note: 'customErrors deveria estar em "On"/"RemoteOnly" para não vazar stack trace.' },
  { id: 'DEBUG_006', tech: 'Express/Node', pattern: /at Layer\.handle|at Router\.|\/node_modules\/express\/lib|Error:.*\n\s+at .+\(\/.*\.js:\d+:\d+\)/i, severity: 'high', note: 'Express em ambiente non-production imprime stack trace (NODE_ENV != production).' },
  { id: 'DEBUG_007', tech: 'PHP', pattern: /<b>(?:Warning|Fatal error|Notice|Parse error)<\/b>:.*on line <b>\d+|Uncaught \w+Exception/i, severity: 'high', note: 'display_errors ligado expõe caminhos absolutos e detalhes do servidor.' },
  { id: 'DEBUG_008', tech: 'Flask/Werkzeug', pattern: /Werkzeug Debugger|The debugger caught an exception|__traceback_hide__|console-locked/i, severity: 'critical', note: 'Werkzeug debugger interativo permite execução de código via console (com PIN, mas crítico).' },
];

/**
 * Fingerprints de subdomain takeover: quando um CNAME aponta para um serviço
 * onde o recurso não existe mais, o provedor devolve uma página de erro
 * característica. Se um atacante registrar aquele recurso, ele passa a servir
 * conteúdo no SEU domínio (cookies, phishing, bypass de CSP/CORS).
 * Detecção 100% passiva: procuramos a assinatura no corpo da resposta.
 */
const TAKEOVER_FINGERPRINTS: Array<{ service: string; pattern: RegExp }> = [
  { service: 'AWS S3', pattern: /NoSuchBucket|The specified bucket does not exist/i },
  { service: 'GitHub Pages', pattern: /There isn't a GitHub Pages site here/i },
  { service: 'Heroku', pattern: /No such app\b|herokucdn\.com\/error-pages\/no-such-app/i },
  { service: 'Azure', pattern: /Web Site not found|404 Web Site not found/i },
  { service: 'Netlify', pattern: /Not Found - Request ID|Netlify.*page not found/i },
  { service: 'Vercel', pattern: /DEPLOYMENT_NOT_FOUND|The deployment could not be found/i },
  { service: 'Shopify', pattern: /Sorry, this shop is currently unavailable/i },
  { service: 'Fastly', pattern: /Fastly error: unknown domain/i },
  { service: 'Bitbucket', pattern: /Repository not found/i },
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
  const base = url.replace(/\/$/, '');
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
    reference?: string,
    confidence: Finding['confidence'] = 'medium'
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
      confidence,
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
    // Não retorna vazio: registra um achado explicativo para o usuário entender
    // por que "não veio nada" (alvo inacessível, anti-bot/WAF, rate limit, etc.).
    log('error', `Não foi possível obter uma resposta analisável de ${url}: ${mainResponse.error}`);
    addFinding(
      'SCAN_001', 'Alvo inacessível ou bloqueou o scanner', 'Conectividade', 'info',
      `O watchDOG não recebeu uma resposta HTTP analisável de ${url}. Motivo reportado: ${mainResponse.error}.`,
      'Sites grandes ou bem protegidos costumam bloquear scanners automatizados (WAF, anti-bot, rate limiting) — o que, em si, é um sinal positivo de postura defensiva, mas impede a análise passiva de headers a partir desta origem.',
      'Confirme conectividade e resolução de DNS; rode o watchDOG a partir de uma origem autorizada; reduza a profundidade do scan; ou audite o projeto localmente. Não aumente a taxa de requisições para "forçar" — isso caracteriza abuso.',
      mainResponse.error,
      undefined,
      undefined,
      'high'
    );
    return { findings, techStack, logs };
  }

  // Guardas anti-falso-positivo para sondagem de caminhos:
  //  - redirectedAway: o alvo respondeu 3xx e o salto final caiu em OUTRO path
  //    (ex.: /.env -> /). Seguir o redirect e ver a home em 200 NÃO é "acessível".
  //  - isSpaFallback: SPA devolve o index.html (200) para qualquer rota.
  const homeBody = mainResponse.body;
  const isSpaFallback = (body: string) =>
    /<!doctype html|<html/i.test(body) && (body === homeBody || Math.abs(body.length - homeBody.length) < 64);
  const redirectedAway = (resp: { redirectChain: string[]; finalUrl?: string }, pathStr: string) => {
    if (resp.redirectChain.length === 0) return false;
    try {
      const finalPath = new URL(resp.finalUrl || '').pathname.replace(/\/$/, '');
      return finalPath !== pathStr.replace(/\/$/, '');
    } catch { return true; }
  };

  log('info', `Status HTTP: ${mainResponse.statusCode} | Redirects: ${mainResponse.redirectChain.length}${mainResponse.truncated ? ' | corpo truncado' : ''}`);

  // Sinal de postura: o alvo aplica anti-abuso/WAF/limite a requisições automatizadas.
  if ([401, 403, 429, 503].includes(mainResponse.statusCode)) {
    log('warn', `Alvo respondeu ${mainResponse.statusCode} — possível anti-bot/WAF/rate limit.`);
    addFinding(
      'POSTURE_001', 'Alvo aplica proteção anti-abuso a requisições automatizadas', 'Resiliência', 'info',
      `A página principal respondeu HTTP ${mainResponse.statusCode} a uma requisição automatizada, indicando WAF, anti-bot ou rate limiting na borda.`,
      'Proteção anti-abuso é desejável: dificulta scraping, brute force e DoS. A análise de headers segue possível, mas alguns recursos podem não ser sondáveis de forma passiva.',
      'Mantenha a proteção. Para auditar internamente, execute a análise a partir de uma origem permitida (allowlist) ou em ambiente de homologação.',
      `HTTP ${mainResponse.statusCode}`,
      undefined,
      undefined,
      'medium'
    );
  }

  // Check HTTPS
  if (!url.startsWith('https://')) {
    addFinding(
      'URL_001', 'HTTPS não utilizado', 'Headers HTTP', 'high',
      'A URL não usa HTTPS, transmitindo dados em texto puro.',
      'Dados em trânsito podem ser interceptados.',
      'Configure HTTPS com certificado válido e redirecione HTTP para HTTPS.',
      'http://',
      'https://meudominio.com',
      'OWASP A04:2025 - Cryptographic Failures'
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
        'OWASP A04:2025'
      );
    }
  }

  // STEP 2: Headers analysis
  progress(STEPS[1].label, STEPS[1].progress);
  log('info', STEPS[1].label);

  const headers = mainResponse.headers;

  // Garante que set-cookie seja uma string única (algumas libs HTTP retornam
  // array de cookies). Reconstrói com '\n' entre cookies para que as regras
  // COOKIE_* consigam inspecionar cada diretiva. safeGet já une com ', ',
  // então normalizamos esses separadores para '\n'.
  if (headers['set-cookie'] && headers['set-cookie'].includes(', ')) {
    headers['set-cookie'] = headers['set-cookie']
      .split(/,\s*(?=[A-Za-z0-9_.-]+=)/)
      .join('\n');
  }

  // Mapeia uma confiança coerente por regra HTTP: regras que apenas detectam
  // ausência de header têm confiança alta; heurísticas de postura (WAF/CDN,
  // rate-limit) são informativas e usam confiança baixa.
  function confidenceForHttpRule(ruleId: string): Finding['confidence'] {
    if (ruleId.startsWith('DOSH_')) return 'low';
    if (ruleId.startsWith('COOKIE_') || ruleId.startsWith('CORS_')) return 'high';
    return 'medium';
  }

  // Regras de headers de segurança (presença/qualidade de CSP, HSTS, cookies,
  // COOP/CORP, CORS, cache) e regras de postura DDoS/WAF/CDN/rate-limit.
  for (const rule of [...headersRules, ...dosHeadersRules]) {
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
        rule.reference,
        confidenceForHttpRule(rule.id)
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
      'OWASP A02:2025'
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
      'OWASP A02:2025'
    );
  }

  // Sondagem CORS ATIVA-SEGURA: o bug clássico de reflexão de origem só aparece
  // quando enviamos um header Origin. Mandamos uma origem inventada (.invalid,
  // jamais resolvível) e a origem null, e observamos se o servidor as ecoa.
  // Nenhuma credencial real é enviada; é só 1-2 requisições GET à própria home.
  try {
    const evilOrigin = 'https://watchdog-probe.invalid';
    const corsProbe = await safeGet(url, { ...customHeaders, Origin: evilOrigin }, [], { noFollow: true });
    const acao = (corsProbe.headers['access-control-allow-origin'] || '').trim();
    const acac = (corsProbe.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';

    if (acao.toLowerCase() === evilOrigin.toLowerCase()) {
      addFinding(
        acac ? 'CORS_010' : 'CORS_012',
        acac ? 'CORS reflete qualquer Origin COM credenciais' : 'CORS reflete qualquer Origin enviada',
        'CORS', acac ? 'critical' : 'high',
        `O servidor refletiu de volta a Origin arbitrária "${evilOrigin}" em Access-Control-Allow-Origin${acac ? ', junto com Allow-Credentials: true' : ''}.`,
        acac
          ? 'Refletir a Origin com credenciais permite que QUALQUER site malicioso faça requisições autenticadas em nome da vítima e leia as respostas, vazando dados privados e sessões.'
          : 'Refletir qualquer Origin remove a proteção de mesma-origem para respostas legíveis; combinado com credenciais no futuro, vira exfiltração total.',
        'Nunca reflita a Origin recebida. Valide contra uma allowlist estática de origens confiáveis e responda apenas com origens explicitamente permitidas.',
        `Origin: ${evilOrigin} -> Access-Control-Allow-Origin: ${acao}${acac ? ' | Allow-Credentials: true' : ''}`,
        "cors({ origin: ['https://app.seudominio.com'], credentials: true })",
        'OWASP A02:2025 - Security Misconfiguration (CORS); PortSwigger CORS',
        'high'
      );
    }

    // Teste do "null origin" (sandboxed iframe / redirect): confiar em null é explorável.
    const nullProbe = await safeGet(url, { ...customHeaders, Origin: 'null' }, [], { noFollow: true });
    const nullAcao = (nullProbe.headers['access-control-allow-origin'] || '').trim().toLowerCase();
    if (nullAcao === 'null') {
      addFinding(
        'CORS_011', 'CORS confia na Origin "null"', 'CORS', 'high',
        'O servidor respondeu Access-Control-Allow-Origin: null. A origem "null" pode ser forjada por um iframe sandbox ou redirect, então confiar nela equivale a um wildcard explorável.',
        'Um atacante em um iframe com sandbox consegue a origem null e passa a ler respostas cross-origin, contornando a política de mesma-origem.',
        'Remova "null" de qualquer allowlist de CORS. null nunca deve aparecer em produção.',
        'Origin: null -> Access-Control-Allow-Origin: null',
        "// valide a Origin contra uma lista fixa; jamais inclua 'null'",
        'OWASP A02:2025 - Security Misconfiguration (CORS); PortSwigger CORS null origin',
        'high'
      );
    }
  } catch {
    // Falha na sondagem CORS não interrompe o scan.
  }

  // STEP 4: Check common paths (only in normal/deep mode)
  progress(STEPS[3].label, STEPS[3].progress);
  log('info', STEPS[3].label);

  const pathsToCheck = depth === 'quick'
    ? SAFE_PATHS_TO_CHECK.slice(0, 5)
    : [...SAFE_PATHS_TO_CHECK, ...EXTRA_PATHS_TO_CHECK];

  // Breaker educado: se o alvo passar a bloquear/limitar, interrompe a sondagem
  // para não sobrecarregá-lo nem parecer um ataque.
  let consecutiveBlocks = 0;

  for (const checkPathStr of pathsToCheck) {
    const resp = await checkPath(url, checkPathStr);

    if (resp.error || [403, 429, 503].includes(resp.statusCode)) {
      consecutiveBlocks++;
      if (consecutiveBlocks >= 3) {
        log('warn', 'Sondagem de caminhos interrompida: o alvo começou a bloquear/limitar. O watchDOG recua para não sobrecarregar nem caracterizar abuso.');
        break;
      }
      continue;
    }
    consecutiveBlocks = 0;

    if (resp.statusCode === 200 && redirectedAway(resp, checkPathStr)) {
      log('info', `Caminho ${checkPathStr} redireciona para ${resp.finalUrl} — não considerado acessível.`);
      continue;
    }
    if (resp.statusCode === 200 && isSpaFallback(resp.body)) {
      log('info', `Caminho ${checkPathStr} devolveu o index.html (fallback de SPA) — não considerado acessível.`);
      continue;
    }

    if (resp.statusCode === 200) {
      log('info', `Caminho acessível: ${checkPathStr} (${resp.statusCode})`);

      if ((checkPathStr === '/swagger' || checkPathStr === '/api-docs') && /swagger|openapi|redoc/i.test(resp.body)) {
        addFinding(
          'API_001', 'Swagger/API docs público', 'API', 'low',
          'Documentação da API está publicamente acessível.',
          'Facilita reconhecimento por atacantes.',
          'Proteja documentação com autenticação em produção.',
          `${base}${checkPathStr}`,
          undefined,
          'OWASP API9:2023'
        );
      }

      if (checkPathStr === '/graphql' && /graphql|"errors"|"data"|query/i.test(resp.body)) {
        addFinding(
          'API_002', 'GraphQL endpoint público', 'API', 'medium',
          'Endpoint GraphQL acessível sem autenticação.',
          'Possível introspection do schema completo.',
          'Restrinja acesso e desabilite introspection em produção.',
          `${base}${checkPathStr}`,
          undefined,
          'OWASP API9:2023'
        );
      }

      if (checkPathStr === '/.env' && /^[A-Z][A-Z0-9_]*s*=/m.test(resp.body) && !/<html|<!doctype/i.test(resp.body)) {
        addFinding(
          'SECRET_004', 'Arquivo .env publicamente acessível', 'Secrets', 'critical',
          'O arquivo .env está acessível publicamente.',
          'Todos os secrets da aplicação estão expostos.',
          'Bloqueie acesso a arquivos .env no servidor web. Nunca sirva arquivos de configuração.',
          `${base}/.env`,
          undefined,
          'OWASP A04:2025'
        );
      }

      if (checkPathStr === '/debug' || checkPathStr === '/server-status') {
        addFinding(
          'API_003', 'Endpoint de debug/diagnóstico público', 'API', 'medium',
          `Endpoint ${checkPathStr} está publicamente acessível.`,
          'Exposição de informações internas da aplicação.',
          'Remova ou proteja endpoints de diagnóstico.',
          `${base}${checkPathStr}`,
          undefined,
          'OWASP A02:2025'
        );
      }

      if (checkPathStr === '/admin') {
        addFinding(
          'AUTHZ_001', 'Painel admin acessível', 'Autorização', 'medium',
          'Painel administrativo retornou status 200.',
          'Painel admin pode estar acessível sem autenticação.',
          'Verifique se o painel exige autenticação. Restrinja por IP se possível.',
          `${base}/admin`,
          undefined,
          'OWASP A01:2025'
        );
      }

      if (checkPathStr === '/.git/HEAD' && /ref:\s|^[0-9a-f]{40}/m.test(resp.body)) {
        addFinding(
          'EXPOSE_001', 'Diretório .git exposto publicamente', 'Exposição', 'high',
          'O arquivo /.git/HEAD está acessível, indicando que o diretório .git foi publicado junto com a aplicação.',
          'Atacantes podem reconstruir todo o histórico do repositório (código-fonte, secrets commitados, credenciais) baixando os objetos do .git.',
          'Bloqueie o acesso a /.git no servidor web (deny all em /.git/) e nunca faça deploy do diretório de versionamento.',
          `${base}/.git/HEAD`,
          'location /.git { deny all; return 404; }',
          'OWASP A02:2025 - Security Misconfiguration',
          'high'
        );
      }

      if (checkPathStr === '/actuator/health' && /"status"s*:/.test(resp.body)) {
        addFinding(
          'EXPOSE_002', 'Spring Boot Actuator exposto', 'Exposição', 'medium',
          'O endpoint /actuator/health respondeu 200, indicando endpoints de gestão Spring Boot Actuator acessíveis.',
          'Endpoints Actuator podem vazar variáveis de ambiente (/actuator/env), heap dumps e métricas internas, facilitando reconhecimento e exposição de secrets.',
          'Restrinja os endpoints Actuator a uma porta de gestão interna e exija autenticação (management.endpoints.web.exposure.include mínimo).',
          `${base}/actuator/health`,
          'management.endpoints.web.exposure.include=health',
          'OWASP A02:2025 - Security Misconfiguration'
        );
      }

      if (checkPathStr === '/.well-known/openid-configuration' && /"issuer"s*:/.test(resp.body)) {
        addFinding(
          'EXPOSE_003', 'Metadados OpenID Connect públicos', 'Exposição', 'info',
          'O documento de descoberta OpenID Connect está publicamente acessível, expondo endpoints de autorização, token, JWKS e escopos suportados.',
          'Expor a configuração do provedor de identidade é normal para OIDC, mas revela superfície de ataque (endpoints, algoritmos aceitos) útil em reconhecimento.',
          'Mantenha apenas os endpoints necessários expostos e garanta que algoritmos fracos (ex.: none, HS256 com segredo compartilhado) não estejam habilitados.',
          `${base}/.well-known/openid-configuration`,
          undefined,
          'OWASP A07:2025 - Authentication Failures',
          'high'
        );
      }
    }
  }

  // Sondagem passiva de webhooks de pagamento (apenas GET, sem payload).
  // Se um caminho de webhook responde a GET com algo diferente de 404 (ex.: 405
  // Method Not Allowed, 400, 401), o endpoint existe e é descobrível — o mesmo
  // ponto que o atacante do vídeo achou por fuzzing. Alertamos de forma
  // defensiva para o dono garantir verificação de assinatura no handler.
  if (depth !== 'quick') {
    // Baseline: como o alvo responde a um path inexistente na raiz e sob /api/?
    // Se um path de webhook responder com o MESMO status do baseline (ex.: 401
    // para qualquer /api/*), isso é o portão genérico, não prova de endpoint.
    const rnd = Math.random().toString(36).slice(2, 8);
    const rootBaseline = (await checkPath(url, `/watchdog-probe-${rnd}`)).statusCode;
    const apiBaseline = (await checkPath(url, `/api/watchdog-probe-${rnd}`)).statusCode;

    let webhookBlocks = 0;
    for (const whPath of WEBHOOK_PATHS_TO_CHECK) {
      const resp = await checkPath(url, whPath);

      if (resp.error || [429, 503].includes(resp.statusCode)) {
        webhookBlocks++;
        if (webhookBlocks >= 3) break; // recua para não sobrecarregar o alvo
        continue;
      }
      webhookBlocks = 0;

      // 404/403 => rota não exposta a GET; qualquer outro status "vivo" indica
      // que o endpoint de webhook existe.
      const fakeOk = resp.statusCode === 200 && (redirectedAway(resp, whPath) || isSpaFallback(resp.body));
      const genericGate = resp.statusCode === (whPath.startsWith('/api/') ? apiBaseline : rootBaseline);
      if (!fakeOk && !genericGate && [200, 400, 401, 405, 415, 422, 500].includes(resp.statusCode)) {
        addFinding(
          'WHOOK_007', 'Endpoint de webhook de pagamento descobrível', 'Webhook/Pagamento', 'medium',
          `O caminho ${whPath} respondeu HTTP ${resp.statusCode} a uma requisição GET, indicando que existe um endpoint de webhook publicamente descobrível (sem enviar nenhum evento de pagamento).`,
          'Webhooks de pagamento são o alvo clássico de bypass de assinatura: se o handler não validar a assinatura do provedor, um evento forjado de "pagamento aprovado" pode liberar acesso pago. No vídeo, o webhook foi achado exatamente assim, por fuzzing.',
          'Garanta que o handler valide a assinatura do provedor (HMAC/constructEvent) em tempo constante e confirme a transação na API oficial antes de conceder qualquer acesso. Considere um caminho de webhook não previsível e restrição por IP do provedor. Remova endpoints de webhook legados/redundantes.',
          `${base}${whPath} -> HTTP ${resp.statusCode}`,
          "// event = stripe.webhooks.constructEvent(rawBody, sig, WEBHOOK_SECRET)\n// -> valida assinatura ANTES de processar o evento",
          'OWASP API2:2023 - Broken Authentication; CWE-345',
          'low'
        );
        // Um endpoint confirmado já basta para o alerta; evita ruído/varredura.
        break;
      }
    }
  }

  // Subdomain takeover: assinatura de "recurso não existe" de um provedor
  // conhecido servida no domínio do alvo (detecção passiva, só corpo da resposta).
  for (const { service, pattern } of TAKEOVER_FINGERPRINTS) {
    if (pattern.test(mainResponse.body)) {
      addFinding(
        'TAKEOVER_001', `Possível subdomain takeover (${service})`, 'Exposição', 'critical',
        `A resposta do domínio contém a assinatura de recurso inexistente do serviço ${service}, indicando que o DNS ainda aponta para um recurso que foi removido (dangling DNS).`,
        'Se o recurso órfão puder ser reivindicado, um atacante passa a servir conteúdo no SEU domínio: rouba cookies de sessão do domínio principal, aplica phishing com URL legítima e contorna políticas de CSP/CORS baseadas em domínio.',
        `Remova o registro DNS órfão imediatamente OU reivindique novamente o recurso no ${service}. Audite periodicamente registros CNAME apontando para serviços externos e remova os que não têm mais recurso ativo.`,
        `Assinatura de ${service} encontrada no corpo da resposta`,
        '# Remova o CNAME orfao:\n# sub.exemplo.com. CNAME recurso-removido.provedor.com.  <-- apagar',
        'OWASP A02:2025 - Security Misconfiguration; CWE-350',
        'medium'
      );
      break;
    }
  }

  // Ausência de security.txt: canal padronizado para receber relatos de
  // vulnerabilidade. Não é falha, mas sua presença é sinal de maturidade.
  const securityTxt = await checkPath(url, '/.well-known/security.txt');
  if (securityTxt.statusCode === 404 || securityTxt.statusCode === 0) {
    addFinding(
      'EXPOSE_004', 'security.txt ausente (sem canal de divulgação)', 'Exposição', 'info',
      'O arquivo /.well-known/security.txt não foi encontrado. Ele documenta como pesquisadores devem reportar vulnerabilidades encontradas na sua aplicação.',
      'Sem um canal claro de contato, quem encontra uma falha de boa-fé pode não conseguir reportá-la — aumentando a chance de a vulnerabilidade ser divulgada publicamente ou explorada antes da correção.',
      'Publique /.well-known/security.txt com um contato de segurança, política de divulgação e prazo de expiração, conforme a RFC 9116.',
      `${base}/.well-known/security.txt -> HTTP ${securityTxt.statusCode || 'sem resposta'}`,
      'Contact: mailto:security@seudominio.com\nExpires: 2027-01-01T00:00:00.000Z\nPreferred-Languages: pt, en',
      'RFC 9116 - A File Format to Aid in Security Vulnerability Disclosure',
      'high'
    );
  }

  // Source maps expostos: entregam o código-fonte original (pré-minificação),
  // incluindo comentários, rotas internas e às vezes segredos embutidos.
  if (depth !== 'quick') {
    const bundleRefs = Array.from(
      mainResponse.body.matchAll(/(?:src|href)=["']([^"']+\.js)["']/gi)
    )
      .map(m => m[1])
      .filter(src => !/^https?:\/\//i.test(src) || src.includes(new URL(url).hostname))
      .slice(0, 3);

    for (const ref of bundleRefs) {
      const mapPath = (ref.startsWith('http') ? new URL(ref).pathname : ref) + '.map';
      const mapResp = await checkPath(url, mapPath.startsWith('/') ? mapPath : `/${mapPath}`);

      if (
        mapResp.statusCode === 200 &&
        /"sourcesContent"|"version"\s*:\s*3|"mappings"\s*:/.test(mapResp.body)
      ) {
        addFinding(
          'EXPOSE_005', 'Source map exposto em produção', 'Exposição', 'medium',
          `O source map ${mapPath} está acessível publicamente e contém o mapeamento para o código-fonte original da aplicação.`,
          'Source maps reconstroem o código-fonte antes da minificação: revelam nomes de variáveis, comentários, lógica de negócio, rotas internas de API e, com frequência, chaves ou endpoints que o desenvolvedor achava ocultos pela minificação.',
          'Desative a geração de source maps no build de produção (build.sourcemap: false no Vite, productionBrowserSourceMaps: false no Next.js) ou restrinja o acesso a eles no servidor/CDN.',
          `${base}${mapPath} -> HTTP 200 com "mappings"`,
          '// vite.config.ts\nexport default defineConfig({ build: { sourcemap: false } });',
          'OWASP A02:2025 - Security Misconfiguration; CWE-540',
          'high'
        );
        break;
      }
    }
  }

  // Artefatos/backups publicados por engano (somente em depth deep).
  if (depth === 'deep') {
    let leakBlocks = 0;
    for (const leakPath of LEAK_PATHS_TO_CHECK) {
      const resp = await checkPath(url, leakPath);

      if (resp.error || [429, 503].includes(resp.statusCode)) {
        leakBlocks++;
        if (leakBlocks >= 3) break;
        continue;
      }
      leakBlocks = 0;

      // Exige corpo não-vazio e que não seja a SPA devolvendo index.html em 200.
      const looksLikeHtmlFallback = /<!doctype html|<html/i.test(resp.body);
      if (resp.statusCode === 200 && resp.body.length > 0 && !looksLikeHtmlFallback) {
        addFinding(
          'EXPOSE_006', `Arquivo sensível acessível: ${leakPath}`, 'Exposição', 'high',
          `O caminho ${leakPath} respondeu HTTP 200 com conteúdo, indicando um artefato de configuração ou backup publicado junto com a aplicação.`,
          'Arquivos de backup e configuração costumam conter credenciais de banco, tokens de API e estrutura interna — material suficiente para comprometer a aplicação inteira sem precisar de nenhuma outra falha.',
          'Remova o arquivo do diretório publicado, bloqueie o padrão no servidor web/CDN e revogue imediatamente qualquer credencial que ele possa ter exposto.',
          `${base}${leakPath} -> HTTP 200 (${resp.body.length} bytes)`,
          'location ~ /\\.(env|npmrc|git|DS_Store)|\\.(bak|old|sql|swp)$ { deny all; return 404; }',
          'OWASP A02:2025 - Security Misconfiguration; CWE-530',
          'medium'
        );
      }
    }
  }

  // GraphQL introspection probe (leve): envia uma query mínima e, se o endpoint
  // responder com o schema, sinaliza introspection habilitada (cruza AUTHZ_003).
  if (depth !== 'quick') {
    // safeGet só executa GET; usamos GraphQL-over-GET (suportado pela maioria
    // dos servidores) passando a query mínima via query-string.
    const introspectionQuery = '{__typename __schema{queryType{name}}}';
    const graphqlUrl =
      url.replace(/\/$/, '') + '/graphql?query=' + encodeURIComponent(introspectionQuery);
    const gqlResp = await safeGet(graphqlUrl, {
      ...customHeaders,
      'Accept': 'application/json',
    });

    if (
      gqlResp.statusCode === 200 &&
      /"__schema"\s*:/.test(gqlResp.body) &&
      /"queryType"/.test(gqlResp.body)
    ) {
      addFinding(
        'AUTHZ_003', 'GraphQL introspection habilitada em produção', 'API', 'medium',
        'O endpoint /graphql respondeu a uma query de introspection (__schema), expondo o schema completo da API.',
        'Introspection habilitada permite que atacantes enumerem todos os tipos, queries e mutations, acelerando a descoberta de operações sensíveis e dados expostos.',
        'Desabilite introspection em produção (introspection: false) e restrinja o GraphiQL/playground a ambientes de desenvolvimento.',
        `${graphqlUrl} respondeu __schema/queryType`,
        'new ApolloServer({ introspection: process.env.NODE_ENV !== "production" })',
        'OWASP API9:2023 - Improper Inventory Management',
        'high'
      );
    } else if (gqlResp.statusCode === 200 && /"data"\s*:/.test(gqlResp.body)) {
      addFinding(
        'API_002', 'GraphQL endpoint público', 'API', 'medium',
        'Endpoint GraphQL acessível e respondendo a queries sem autenticação.',
        'Endpoint GraphQL aberto amplia a superfície de ataque e pode permitir abuso de queries pesadas (DoS) ou acesso a dados não autorizados.',
        'Exija autenticação no endpoint GraphQL, aplique limites de profundidade/complexidade de query e rate limiting.',
        `${graphqlUrl}`,
        undefined,
        'OWASP API9:2023 - Improper Inventory Management'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Debug mode / stack trace em produção (OWASP 2025 A10 - Mishandling of
  // Exceptional Conditions). 1 request a um path aleatório inexistente para
  // provocar uma página de erro; analisa a assinatura sem enviar payload.
  // ---------------------------------------------------------------------------
  try {
    const probePath = `/watchdog-probe-${Math.random().toString(36).slice(2, 10)}`;
    const errResp = await checkPath(url, probePath);
    const errBody = errResp.body || '';
    // Também consideramos o corpo da home (alguns frameworks vazam na 200).
    const haystack = errBody + '\n' + mainResponse.body.slice(0, 20000);
    for (const sig of DEBUG_SIGNATURES) {
      if (sig.pattern.test(haystack)) {
        addFinding(
          sig.id, `Modo debug / stack trace exposto (${sig.tech})`, 'Exposição', sig.severity,
          `A aplicação retornou uma página de erro verbosa característica de ${sig.tech} ao acessar um caminho inexistente, indicando modo debug ligado em produção.`,
          `${sig.note} Stack traces revelam caminhos internos, versões, trechos de configuração e a estrutura do código — reconhecimento pronto para o atacante.`,
          `Desligue o modo debug em produção (APP_DEBUG=false / DEBUG=False / NODE_ENV=production / customErrors On) e sirva páginas de erro genéricas.`,
          `${base}${probePath} -> assinatura de ${sig.tech}`,
          undefined,
          'OWASP A10:2025 - Mishandling of Exceptional Conditions; CWE-209',
          'high'
        );
        break; // uma assinatura basta
      }
    }
    // Directory listing (Index of /) — misconfiguration clássica.
    if (/<title>Index of \/|<h1>Index of \//i.test(mainResponse.body)) {
      addFinding(
        'EXPOSE_008', 'Directory listing habilitado', 'Exposição', 'medium',
        'O servidor está listando o conteúdo de diretórios (autoindex), expondo a estrutura de arquivos publicados.',
        'Listagem de diretórios entrega ao atacante nomes de arquivos, backups e artefatos que de outra forma não seriam descobertos.',
        'Desabilite o autoindex (Options -Indexes no Apache; autoindex off no nginx).',
        `${url} -> "Index of /"`,
        'autoindex off;',
        'OWASP A02:2025 - Security Misconfiguration; CWE-548'
      );
    }
  } catch { /* probe de debug é best-effort */ }

  // ---------------------------------------------------------------------------
  // Spring Boot Actuator: endpoints que vazam dados (env/heapdump são críticos).
  // ---------------------------------------------------------------------------
  if (depth !== 'quick') {
    let actBlocks = 0;
    for (const act of ACTUATOR_PATHS) {
      const resp = await checkPath(url, act.path, act.headOnly ? { method: 'HEAD', maxBodyBytes: 0 } : {});
      if (resp.error || [429, 503].includes(resp.statusCode)) {
        if (++actBlocks >= 3) break;
        continue;
      }
      actBlocks = 0;
      const looksActuator = resp.statusCode === 200 && !redirectedAway(resp, act.path) &&
        (act.headOnly || /["']\w+["']\s*:|propertySources|activeProfiles|contexts|_links/.test(resp.body) ||
          (resp.headers['content-type'] || '').includes('application/vnd.spring-boot') ||
          (resp.headers['content-type'] || '').includes('application/octet-stream'));
      if (looksActuator) {
        addFinding(
          'EXPOSE_009', `Spring Boot Actuator exposto: ${act.path}`, 'Exposição', act.severity,
          `O endpoint ${act.path} respondeu 200 sem autenticação, expondo ${act.label}.`,
          'Endpoints Actuator sensíveis vazam variáveis de ambiente, dumps de memória com secrets e a estrutura interna da aplicação, e alguns permitem alteração de estado (loggers, shutdown).',
          'Restrinja os endpoints Actuator a uma porta de gestão interna e exija autenticação (management.endpoints.web.exposure.include mínimo; nunca exponha env/heapdump publicamente).',
          `${base}${act.path} -> HTTP ${resp.statusCode}`,
          'management.endpoints.web.exposure.include=health\nmanagement.endpoint.env.enabled=false',
          'OWASP A02:2025 - Security Misconfiguration; CWE-215',
          'high'
        );
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Painéis administrativos / ferramentas de dev expostas.
  // ---------------------------------------------------------------------------
  if (depth !== 'quick') {
    let adminBlocks = 0;
    for (const t of ADMIN_TOOL_PATHS) {
      const resp = await checkPath(url, t.path);
      if (resp.error || [429, 503].includes(resp.statusCode)) {
        if (++adminBlocks >= 3) break;
        continue;
      }
      adminBlocks = 0;
      if (resp.statusCode === 200 && !redirectedAway(resp, t.path) && t.signature.test(resp.body)) {
        addFinding(
          'EXPOSE_010', `Ferramenta administrativa exposta: ${t.tool}`, 'Exposição', t.severity,
          `${t.tool} está publicamente acessível em ${t.path} e respondeu com sua interface característica.`,
          `Ferramentas como ${t.tool} dão acesso direto a dados/infraestrutura e frequentemente vêm com credenciais padrão ou sem autenticação, sendo alvo automático de scanners.`,
          `Restrinja o acesso a ${t.tool} por IP/VPN, exija autenticação forte e troque credenciais padrão. Idealmente, não exponha essa ferramenta à internet.`,
          `${base}${t.path} -> ${t.tool}`,
          undefined,
          'OWASP A02:2025 - Security Misconfiguration',
          'medium'
        );
      }
    }
  }

  // ---------------------------------------------------------------------------
  // WordPress: enumeração de usuários (REST) e XML-RPC habilitado.
  // Só quando o WordPress foi detectado no fingerprint.
  // ---------------------------------------------------------------------------
  const isWordPress = /wp-content|wp-includes|wp-json/.test(mainResponse.body);
  if (isWordPress && depth !== 'quick') {
    const usersResp = await checkPath(url, '/wp-json/wp/v2/users');
    if (usersResp.statusCode === 200 && !redirectedAway(usersResp, '/wp-json/wp/v2/users') && /"slug"\s*:|"id"\s*:\s*\d+/.test(usersResp.body)) {
      addFinding(
        'WP_001', 'WordPress: enumeração de usuários via REST API', 'API', 'medium',
        'O endpoint /wp-json/wp/v2/users retornou a lista de usuários (id, slug, nome) sem autenticação.',
        'Enumerar usuários entrega nomes de login válidos para ataques de força bruta direcionados e engenharia social.',
        'Bloqueie ou restrinja o endpoint /wp-json/wp/v2/users a usuários autenticados (plugin de hardening ou filtro rest_endpoints).',
        `${base}/wp-json/wp/v2/users -> 200 com usuários`,
        undefined,
        'OWASP A01:2025 - Broken Access Control',
        'high'
      );
    }
    const xmlrpcResp = await checkPath(url, '/xmlrpc.php');
    if (/XML-RPC server accepts POST requests only/i.test(xmlrpcResp.body) || xmlrpcResp.statusCode === 405) {
      addFinding(
        'WP_002', 'WordPress: XML-RPC habilitado', 'API', 'high',
        'O arquivo /xmlrpc.php está ativo. Ele suporta system.multicall (centenas de senhas por requisição) e pingback.ping.',
        'system.multicall amplifica ataques de força bruta; pingback.ping pode ser abusado para SSRF e amplificação de DDoS contra terceiros a partir do seu servidor.',
        'Desabilite o XML-RPC se não for usado (bloqueio no servidor web ou filtro xmlrpc_enabled) ou restrinja pingback e multicall.',
        `${base}/xmlrpc.php -> XML-RPC ativo`,
        'location = /xmlrpc.php { deny all; }',
        'OWASP A02:2025 - Security Misconfiguration; CWE-799',
        'high'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Auditoria de métodos HTTP (1 request OPTIONS): TRACE/TRACK e WebDAV.
  // ---------------------------------------------------------------------------
  if (depth !== 'quick') {
    try {
      const optResp = await safeGet(url, customHeaders, [], { method: 'OPTIONS', maxBodyBytes: 0, noFollow: true });
      const allow = ((optResp.headers['allow'] || '') + ' ' + (optResp.headers['access-control-allow-methods'] || '')).toUpperCase();
      if (/\bTRACE\b|\bTRACK\b/.test(allow)) {
        addFinding(
          'HTTP_001', 'Método HTTP TRACE/TRACK habilitado', 'Headers HTTP', 'low',
          `O servidor anuncia suporte a TRACE/TRACK no header Allow (${allow.trim()}).`,
          'TRACE ecoa a requisição de volta (incluindo cookies e headers de autenticação), viabilizando Cross-Site Tracing (XST). O PCI DSS exige que esses métodos estejam desabilitados.',
          'Desabilite TRACE/TRACK no servidor web (TraceEnable off no Apache; bloqueio de método no nginx).',
          `Allow: ${allow.trim()}`,
          'TraceEnable off;',
          'OWASP WSTG - Test HTTP Methods; CWE-693',
          'high'
        );
      }
      if (/\bPUT\b|\bDELETE\b|\bPROPFIND\b|\bMKCOL\b|\bCOPY\b|\bMOVE\b/.test(allow)) {
        addFinding(
          'HTTP_002', 'Métodos HTTP de escrita/WebDAV expostos', 'Headers HTTP', 'medium',
          `O servidor anuncia métodos de escrita/WebDAV no Allow (${allow.trim()}).`,
          'Métodos como PUT, DELETE e os verbos WebDAV podem permitir upload, remoção ou movimentação de arquivos no servidor caso não estejam devidamente restritos.',
          'Desabilite métodos não utilizados e garanta autenticação/autorização estrita nos que forem necessários.',
          `Allow: ${allow.trim()}`,
          '# Permita apenas GET, HEAD, POST, OPTIONS',
          'OWASP WSTG - Test HTTP Methods; CWE-650',
          'medium'
        );
      }
    } catch { /* OPTIONS best-effort */ }
  }

  // ---------------------------------------------------------------------------
  // Secrets e bibliotecas JS vulneráveis em bundles servidos em produção.
  // Reusa os patterns de secretsRules e o jsLibScanner sobre o conteúdo dos
  // bundles referenciados na home (até 5 maiores). Também varre a própria home.
  // ---------------------------------------------------------------------------
  if (depth !== 'quick') {
    const scriptRefs = Array.from(
      mainResponse.body.matchAll(/<script[^>]+src=["']([^"']+\.js)["']/gi)
    )
      .map(m => m[1])
      .filter(src => !/^https?:\/\//i.test(src) || (() => { try { return src.includes(new URL(url).hostname); } catch { return false; } })())
      .slice(0, 5);

    const secretPatterns = secretsRules.flatMap(r =>
      r.patterns.map(p => ({ ruleId: r.id, title: r.title, severity: r.severity, re: new RegExp(p.source, p.flags.replace('g', '')) }))
    );
    const reportedSecrets = new Set<string>();
    const reportedLibs = new Set<string>();

    const scanText = (text: string, sourceLabel: string) => {
      // Secrets
      for (const line of text.split('\n')) {
        if (line.length > 4000) continue; // linhas minificadas gigantes: pula (evita ReDoS/tempo)
        for (const sp of secretPatterns) {
          if (sp.re.test(line)) {
            const key = `${sp.ruleId}:${sourceLabel}`;
            if (reportedSecrets.has(key)) continue;
            reportedSecrets.add(key);
            addFinding(
              'EXPOSE_007', `Secret exposto em bundle JS (${sp.title})`, 'Secrets', sp.severity === 'critical' ? 'critical' : 'high',
              `Um valor com o formato de "${sp.title}" foi encontrado no bundle público ${sourceLabel}. Qualquer visitante baixa esse arquivo e extrai a credencial.`,
              'Secrets em código client-side são coletados por bots em minutos e usados diretamente do atacante. Chaves privadas/service-role dão acesso total ao backend.',
              'Remova o secret do frontend, revogue-o imediatamente e mova-o para o backend/variável de ambiente. Chaves que precisam ir ao cliente devem ser restritas por domínio/escopo.',
              maskLine(line.trim().slice(0, 200)),
              undefined,
              'OWASP A04:2025 - Cryptographic Failures; CWE-615',
              'high'
            );
          }
        }
      }
      // Libs JS vulneráveis
      for (const hit of scanJsLibraries(text)) {
        const key = `${hit.library}@${hit.version}`;
        if (reportedLibs.has(key)) continue;
        reportedLibs.add(key);
        addFinding(
          hit.vuln === 'eol' ? 'JSLIB_002' : 'JSLIB_001',
          `Biblioteca JS vulnerável: ${hit.library} ${hit.version}`, 'Supply Chain', hit.vuln === 'eol' ? 'medium' : 'high',
          `A página carrega ${hit.library} ${hit.version}, que tem vulnerabilidade conhecida. ${hit.detail}`,
          'Bibliotecas de frontend desatualizadas com CVE conhecido são exploradas por payloads públicos (XSS, prototype pollution, ReDoS) e detectadas por scanners automatizados.',
          `Atualize ${hit.library} para a versão corrigida mais recente e ative Subresource Integrity (SRI) nos scripts de CDN.`,
          `${sourceLabel}: ${hit.library} ${hit.version}`,
          undefined,
          `OWASP A03:2025 - Software Supply Chain Failures; ${hit.reference}`,
          'high'
        );
      }
    };

    scanText(mainResponse.body, 'HTML da página inicial');
    for (const ref of scriptRefs) {
      try {
        const bundlePath = ref.startsWith('http') ? new URL(ref).pathname : (ref.startsWith('/') ? ref : `/${ref}`);
        const bundleResp = await checkPath(url, bundlePath);
        if (bundleResp.statusCode === 200 && bundleResp.body) {
          scanText(bundleResp.body, bundlePath);
        }
      } catch { /* bundle individual best-effort */ }
    }
  }

  // ---------------------------------------------------------------------------
  // Sinal passivo de web cache poisoning: enviamos um X-Forwarded-Host inventado
  // (.invalid, nunca resolvível) e vemos se aparece refletido no corpo/Location.
  // Não repetimos para não envenenar o cache real do alvo.
  // ---------------------------------------------------------------------------
  if (depth === 'deep') {
    try {
      const marker = 'watchdog-cache-probe.invalid';
      const cacheResp = await safeGet(url, { ...customHeaders, 'X-Forwarded-Host': marker }, [], { noFollow: true });
      const reflected = (cacheResp.body || '').includes(marker) ||
        (cacheResp.headers['location'] || '').includes(marker) ||
        (cacheResp.headers['link'] || '').includes(marker);
      if (reflected) {
        const cacheable = /public|max-age=[1-9]/.test(cacheResp.headers['cache-control'] || '') ||
          !!cacheResp.headers['x-cache'] || !!cacheResp.headers['cf-cache-status'];
        addFinding(
          'CACHE_001', 'Header não-chaveado (X-Forwarded-Host) refletido na resposta', 'Exposição',
          cacheable ? 'high' : 'medium',
          `O valor de X-Forwarded-Host foi refletido no corpo/headers da resposta. ${cacheable ? 'A resposta aparenta ser cacheável, o que abre caminho para web cache poisoning.' : 'A resposta não aparenta ser cacheável, mas a reflexão ainda habilita host header injection.'}`,
          'Se um input não-chaveado (X-Forwarded-Host) influencia a resposta e ela é cacheada, um atacante envenena a versão em cache para todos os usuários (scripts maliciosos, links de reset de senha sequestrados).',
          'Não gere URLs/links a partir de headers de Host controláveis pelo cliente. Use um host canônico fixo e inclua no cache key qualquer header que afete a resposta.',
          `X-Forwarded-Host: ${marker} refletido`,
          undefined,
          'OWASP WSTG - Host Header Injection; PortSwigger Web Cache Poisoning; CWE-444',
          'medium'
        );
      }
    } catch { /* cache probe best-effort */ }
  }

  // ---------------------------------------------------------------------------
  // Postura de DNS e e-mail do domínio (SPF/DMARC/DKIM/MTA-STS/CAA/DNSSEC),
  // CNAME pendurado e subdomínios em Certificate Transparency. 100% passivo.
  // ---------------------------------------------------------------------------
  try {
    log('info', 'Analisando postura de DNS e e-mail do domínio');
    const dnsFindings = await analyzeDns(url, scanId);
    for (const f of dnsFindings) {
      findings.push(f);
      onEvent({ type: 'finding', finding: f });
    }
    if (dnsFindings.length) log('info', `DNS/e-mail: ${dnsFindings.length} achado(s).`);
  } catch (e: any) {
    log('warn', `Análise de DNS falhou: ${e?.message || e}`);
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
        'OWASP A04:2025'
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
        'OWASP A04:2025'
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
