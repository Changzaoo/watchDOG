import { HttpRule } from '../types';

export const headersRules: HttpRule[] = [
  {
    id: 'HEAD_001',
    title: 'Header HSTS ausente',
    category: 'Headers HTTP',
    severity: 'medium',
    description: 'O header Strict-Transport-Security não está presente.',
    impact: 'Sem HSTS, usuários podem ser forçados a conexões HTTP inseguras (SSL stripping).',
    remediation: 'Adicione HSTS com max-age de pelo menos 1 ano e includeSubDomains.',
    safeExample: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (headers) => !headers['strict-transport-security'],
  },
  {
    id: 'HEAD_002',
    title: 'Content-Security-Policy ausente',
    category: 'Headers HTTP',
    severity: 'medium',
    description: 'O header Content-Security-Policy não está configurado.',
    impact: 'Sem CSP, ataques XSS podem executar scripts de qualquer origem.',
    remediation: 'Configure uma CSP restritiva. Comece com default-src \'self\'.',
    safeExample: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
    reference: 'OWASP A03:2021 - Injection (XSS)',
    check: (headers) => !headers['content-security-policy'],
  },
  {
    id: 'HEAD_003',
    title: 'X-Frame-Options ausente',
    category: 'Headers HTTP',
    severity: 'medium',
    description: 'O header X-Frame-Options não está presente.',
    impact: 'A página pode ser embutida em iframes de outros sites (Clickjacking).',
    remediation: 'Adicione X-Frame-Options: DENY ou SAMEORIGIN.',
    safeExample: 'X-Frame-Options: DENY',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (headers) => !headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors'),
  },
  {
    id: 'HEAD_004',
    title: 'X-Content-Type-Options ausente',
    category: 'Headers HTTP',
    severity: 'low',
    description: 'O header X-Content-Type-Options: nosniff não está presente.',
    impact: 'O navegador pode fazer MIME type sniffing e executar arquivos com tipo errado.',
    remediation: 'Adicione X-Content-Type-Options: nosniff.',
    safeExample: 'X-Content-Type-Options: nosniff',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (headers) => headers['x-content-type-options'] !== 'nosniff',
  },
  {
    id: 'HEAD_005',
    title: 'Referrer-Policy ausente ou permissivo',
    category: 'Headers HTTP',
    severity: 'low',
    description: 'O header Referrer-Policy não está configurado ou é permissivo.',
    impact: 'URLs com dados sensíveis podem ser vazados via header Referer para sites terceiros.',
    remediation: 'Configure Referrer-Policy: strict-origin-when-cross-origin ou no-referrer.',
    safeExample: 'Referrer-Policy: strict-origin-when-cross-origin',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (headers) => !headers['referrer-policy'],
  },
  {
    id: 'HEAD_006',
    title: 'X-Powered-By expondo tecnologia',
    category: 'Headers HTTP',
    severity: 'info',
    description: 'O header X-Powered-By está expondo a tecnologia do backend (ex: Express, PHP).',
    impact: 'Informação útil para atacantes na fase de reconhecimento.',
    remediation: 'Remova o header X-Powered-By ou substitua por valor neutro.',
    safeExample: "app.disable('x-powered-by'); // Express\n// ou via Helmet: helmet() remove automaticamente",
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (headers) => !!headers['x-powered-by'],
  },
  {
    id: 'HEAD_007',
    title: 'Server header expondo versão',
    category: 'Headers HTTP',
    severity: 'info',
    description: 'O header Server está expondo a versão do software do servidor.',
    impact: 'Permite identificação de versões vulneráveis específicas.',
    remediation: 'Configure o servidor para não expor a versão no header Server.',
    safeExample: '# nginx.conf:\nserver_tokens off;\n# Apache:\nServerTokens Prod\nServerSignature Off',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (headers) => {
      const server = headers['server'] || '';
      return /\d+\.\d+/.test(server);
    },
  },
  {
    id: 'HEAD_008',
    title: 'Permissions-Policy ausente',
    category: 'Headers HTTP',
    severity: 'low',
    description: 'O header Permissions-Policy não está configurado.',
    impact: 'Sem restrição de features do navegador: câmera, microfone, geolocalização podem ser acessados por iframes.',
    remediation: 'Configure Permissions-Policy para restringir features não utilizadas.',
    safeExample: "Permissions-Policy: camera=(), microphone=(), geolocation=(self), payment=()",
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (headers) => !headers['permissions-policy'],
  },
  {
    id: 'HEAD_009',
    title: 'CORS permissivo com credentials',
    category: 'Headers HTTP',
    severity: 'high',
    description: 'CORS configurado com Access-Control-Allow-Origin: * e Access-Control-Allow-Credentials: true.',
    impact: 'Configuração inválida que pode levar a comportamento inesperado ou vulnerabilidades em algumas versões de browsers.',
    remediation: 'Nunca combine Allow-Origin: * com Allow-Credentials: true. Use origens específicas.',
    safeExample: 'Access-Control-Allow-Origin: https://meuapp.com\nAccess-Control-Allow-Credentials: true',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (headers) =>
      headers['access-control-allow-origin'] === '*' &&
      headers['access-control-allow-credentials'] === 'true',
  },
  {
    id: 'COOKIE_001',
    title: 'Cookie de sessão sem flag HttpOnly',
    category: 'Headers HTTP',
    severity: 'medium',
    description: 'Um cookie aparentemente de sessão/autenticação (sid, session, token, auth, jwt, connect.sid) é definido sem a flag HttpOnly.',
    impact: 'Sem HttpOnly, o cookie fica acessível via document.cookie no JavaScript. Um XSS consegue ler o token de sessão e sequestrar a conta do usuário.',
    remediation: 'Defina todos os cookies de sessão/autenticação com a flag HttpOnly para que não sejam acessíveis por scripts do lado do cliente.',
    safeExample: 'Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/',
    reference: 'OWASP A05:2021 - Security Misconfiguration (Session Management)',
    check: (h) => {
      const sc = (h['set-cookie'] || '').toLowerCase();
      if (!sc) return false;
      return /(sid|session|token|auth|jwt|connect\.sid)=/.test(sc) && !/httponly/.test(sc);
    },
  },
  {
    id: 'COOKIE_002',
    title: 'Cookie de sessão sem flag Secure',
    category: 'Headers HTTP',
    severity: 'medium',
    description: 'Um cookie aparentemente de sessão/autenticação (sid, session, token, auth, jwt) é definido sem a flag Secure.',
    impact: 'Sem a flag Secure, o cookie pode ser enviado em conexões HTTP não criptografadas, permitindo interceptação do token de sessão por um atacante na rede (MITM/SSL stripping).',
    remediation: 'Adicione a flag Secure a todos os cookies sensíveis para que sejam transmitidos apenas via HTTPS.',
    safeExample: 'Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/',
    reference: 'OWASP A05:2021 - Security Misconfiguration (Session Management)',
    check: (h) => {
      const sc = (h['set-cookie'] || '').toLowerCase();
      if (!sc) return false;
      return /(sid|session|token|auth|jwt)=/.test(sc) && !/;\s*secure/.test(sc);
    },
  },
  {
    id: 'COOKIE_003',
    title: 'Cookie sem SameSite (ou SameSite=None sem Secure)',
    category: 'Headers HTTP',
    severity: 'medium',
    description: 'Um cookie é definido sem o atributo SameSite, ou com SameSite=None sem a flag Secure acompanhante.',
    impact: 'Sem SameSite, o cookie é enviado em requisições cross-site, abrindo espaço para ataques CSRF. SameSite=None sem Secure é rejeitado por navegadores modernos e expõe o cookie em conexões inseguras.',
    remediation: 'Defina SameSite=Strict ou SameSite=Lax para cookies de sessão. Use SameSite=None somente quando necessário e sempre acompanhado de Secure.',
    safeExample: 'Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/',
    reference: 'OWASP A01:2021 - Broken Access Control (CSRF)',
    check: (h) => {
      const sc = (h['set-cookie'] || '').toLowerCase();
      if (!sc) return false;
      if (!/samesite=/.test(sc)) return true;
      return /samesite=none/.test(sc) && !/;\s*secure/.test(sc);
    },
  },
  {
    id: 'HEAD_CSP_001',
    title: 'Content-Security-Policy fraca',
    category: 'Headers HTTP',
    severity: 'medium',
    description: "A CSP presente contém diretivas inseguras: 'unsafe-inline', 'unsafe-eval', curingas (*), data: ou http: em script-src, ou um default-src amplo (*).",
    impact: 'Uma CSP fraca falha em mitigar XSS: scripts inline ou de origens arbitrárias ainda podem ser executados, anulando o propósito principal da política.',
    remediation: "Remova 'unsafe-inline' e 'unsafe-eval'. Use nonces ou hashes para scripts inline necessários e restrinja script-src/default-src a 'self' e origens confiáveis específicas.",
    safeExample: "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; base-uri 'self'",
    reference: 'OWASP A03:2021 - Injection (XSS)',
    check: (h) => {
      const csp = (h['content-security-policy'] || '').toLowerCase();
      if (!csp) return false;
      const weak = /unsafe-inline|unsafe-eval/.test(csp);
      const scriptSrc = (csp.match(/script-src[^;]*/) || [''])[0];
      const wideScript = /\*|data:|http:/.test(scriptSrc);
      const wideDefault = /default-src[^;]*\*/.test(csp);
      return weak || wideScript || wideDefault;
    },
  },
  {
    id: 'HEAD_HSTS_001',
    title: 'HSTS de baixa qualidade',
    category: 'Headers HTTP',
    severity: 'low',
    description: 'O header Strict-Transport-Security está presente, mas com max-age inferior a 1 ano (31536000s) ou sem includeSubDomains.',
    impact: 'Um max-age curto encurta a janela de proteção contra SSL stripping; sem includeSubDomains, subdomínios permanecem vulneráveis a downgrade de conexão.',
    remediation: 'Configure HSTS com max-age de pelo menos 1 ano e inclua includeSubDomains (e preload, se elegível).',
    safeExample: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (h) => {
      const v = (h['strict-transport-security'] || '').toLowerCase();
      if (!v) return false;
      const m = v.match(/max-age\s*=\s*(\d+)/);
      const maxAge = m ? parseInt(m[1], 10) : 0;
      return maxAge < 31536000 || !/includesubdomains/.test(v);
    },
  },
  {
    id: 'HEAD_COOP_001',
    title: 'Cross-Origin-Opener-Policy ausente ou permissivo',
    category: 'Headers HTTP',
    severity: 'low',
    description: 'O header Cross-Origin-Opener-Policy não está configurado como same-origin ou same-origin-allow-popups.',
    impact: 'Sem COOP, a janela pode compartilhar o browsing context group com janelas cross-origin, facilitando ataques de side-channel (Spectre) e cross-window scripting.',
    remediation: 'Defina Cross-Origin-Opener-Policy: same-origin para isolar o browsing context.',
    safeExample: 'Cross-Origin-Opener-Policy: same-origin',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (h) => {
      const v = (h['cross-origin-opener-policy'] || '').toLowerCase();
      return v !== 'same-origin' && v !== 'same-origin-allow-popups';
    },
  },
  {
    id: 'HEAD_CORP_001',
    title: 'Cross-Origin-Resource-Policy / COEP ausentes',
    category: 'Headers HTTP',
    severity: 'info',
    description: 'Nem Cross-Origin-Resource-Policy nem Cross-Origin-Embedder-Policy estão presentes.',
    impact: 'Sem CORP/COEP, recursos podem ser embutidos por origens arbitrárias e o isolamento cross-origin necessário para features sensíveis (ex.: SharedArrayBuffer) não é garantido.',
    remediation: 'Defina Cross-Origin-Resource-Policy: same-origin e, quando aplicável, Cross-Origin-Embedder-Policy: require-corp.',
    safeExample: 'Cross-Origin-Resource-Policy: same-origin\nCross-Origin-Embedder-Policy: require-corp',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (h) => !h['cross-origin-resource-policy'] && !h['cross-origin-embedder-policy'],
  },
  {
    id: 'CORS_RESP_001',
    title: 'CORS refletindo Origin/null com credenciais',
    category: 'Headers HTTP',
    severity: 'high',
    description: 'Access-Control-Allow-Origin reflete a Origin da requisição (ou retorna null/*) em conjunto com Access-Control-Allow-Credentials: true.',
    impact: 'Refletir a Origin com credenciais habilitadas permite que qualquer site malicioso faça requisições autenticadas em nome da vítima e leia as respostas, vazando dados sensíveis.',
    remediation: 'Nunca reflita a Origin de forma dinâmica nem use null/* com credenciais. Valide a Origin contra uma allowlist e responda apenas com origens explicitamente confiáveis.',
    safeExample: 'Access-Control-Allow-Origin: https://meuapp.com\nAccess-Control-Allow-Credentials: true',
    reference: 'OWASP A05:2021 - Security Misconfiguration (CORS)',
    check: (h) => {
      const acao = (h['access-control-allow-origin'] || '').trim().toLowerCase();
      const acac = (h['access-control-allow-credentials'] || '').toLowerCase() === 'true';
      const reqOrigin = (h['origin'] || '').trim().toLowerCase();
      if (!acao) return false;
      if (acac && acao === '*') return true;
      if (acao === 'null') return true;
      if (acac && reqOrigin && acao === reqOrigin) return true;
      return false;
    },
  },
  {
    id: 'HEAD_CACHE_001',
    title: 'Cache-Control ausente/permissivo em resposta sensível',
    category: 'Headers HTTP',
    severity: 'low',
    description: 'Uma resposta sensível (com Set-Cookie ou Content-Type application/json) não define Cache-Control restritivo (no-store, private ou no-cache).',
    impact: 'Respostas sensíveis sem diretiva de cache restritiva podem ser armazenadas por proxies, CDNs ou pelo navegador, expondo dados privados a outros usuários do mesmo cache compartilhado.',
    remediation: 'Defina Cache-Control: no-store (ou private/no-cache) em respostas que contenham dados sensíveis ou cookies de sessão.',
    safeExample: 'Cache-Control: no-store, private\nPragma: no-cache',
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    check: (h) => {
      const cc = (h['cache-control'] || '').toLowerCase();
      const sensitive = !!h['set-cookie'] || /application\/json/.test((h['content-type'] || '').toLowerCase());
      if (!sensitive) return false;
      if (!cc) return true;
      return !/(no-store|private|no-cache)/.test(cc);
    },
  },
];
