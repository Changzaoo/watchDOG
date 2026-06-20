import { HttpRule } from '../types';

export const dosHeadersRules: HttpRule[] = [
  {
    id: 'DOSH_001',
    title: 'WAF/CDN não detectado',
    category: 'Negação de Serviço (DoS)',
    severity: 'low',
    description: 'Nenhum indício de WAF, CDN ou camada de borda (Cloudflare, CloudFront, Fastly, Akamai, Incapsula, Sucuri, Vercel, Netlify, Azure Front Door) foi identificado nos headers de resposta.',
    impact: 'Sem uma camada de borda, a origem recebe tráfego malicioso diretamente, ficando mais exposta a ataques volumétricos (DDoS), brute force e varreduras automatizadas.',
    remediation: 'Posicione um WAF/CDN à frente da aplicação para absorver tráfego volumétrico, filtrar requisições maliciosas e ocultar o IP de origem.',
    safeExample: 'Sirva a aplicação atrás de Cloudflare, AWS CloudFront + WAF, Fastly, Akamai ou Azure Front Door, mantendo a origem acessível apenas pela borda.',
    reference: 'OWASP A05:2021 - Security Misconfiguration; CWE-693',
    check: (headers) => {
      const h = headers;
      const server = (h['server'] || '').toLowerCase();
      const via = (h['via'] || '').toLowerCase();
      const xcache = (h['x-cache'] || '').toLowerCase();
      const hasWaf =
        !!h['cf-ray'] || server.includes('cloudflare') ||
        !!h['x-amz-cf-id'] || !!h['x-amz-cf-pop'] || via.includes('cloudfront') ||
        !!h['x-fastly-request-id'] || !!h['x-served-by'] || server.includes('fastly') ||
        !!h['x-akamai-transformed'] || !!h['akamai-grn'] || !!h['x-akamai-request-id'] ||
        !!h['x-iinfo'] || (h['x-cdn'] || '').toLowerCase().includes('incapsula') ||
        !!h['x-sucuri-id'] || !!h['x-sucuri-cache'] ||
        server.includes('vercel') || !!h['x-vercel-id'] ||
        !!h['x-nf-request-id'] || server.includes('netlify') ||
        !!h['x-azure-ref'] || !!h['x-msedge-ref'] ||
        xcache.includes('hit') || (xcache.includes('miss') && !!via);
      return !hasWaf;
    },
  },
  {
    id: 'DOSH_002',
    title: 'WAF/CDN detectado',
    category: 'Negação de Serviço (DoS)',
    severity: 'info',
    description: 'Os headers de resposta indicam a presença de uma camada de WAF/CDN (Cloudflare, CloudFront, Fastly, Akamai, Incapsula, Sucuri, Vercel, Netlify ou Azure Front Door).',
    impact: 'Postura de segurança positiva: a camada de borda ajuda a absorver tráfego volumétrico, filtrar requisições maliciosas e ocultar a origem. Este achado é informativo.',
    remediation: 'Mantenha as regras do WAF e os limites de rate limiting da borda atualizados e garanta que a origem só seja acessível através da camada de borda.',
    safeExample: 'Cloudflare/CloudFront/Fastly/Akamai/Azure Front Door ativos, com regras de WAF e rate limiting configuradas e origem protegida.',
    reference: 'OWASP A05:2021 - Security Misconfiguration; CWE-693',
    check: (headers) => {
      const h = headers; const server = (h['server'] || '').toLowerCase(); const via = (h['via'] || '').toLowerCase();
      return !!h['cf-ray'] || server.includes('cloudflare') ||
        !!h['x-amz-cf-id'] || via.includes('cloudfront') ||
        !!h['x-served-by'] || !!h['x-fastly-request-id'] || server.includes('fastly') ||
        !!h['x-akamai-request-id'] || !!h['akamai-grn'] ||
        !!h['x-iinfo'] || !!h['x-sucuri-id'] ||
        !!h['x-vercel-id'] || !!h['x-nf-request-id'] || !!h['x-azure-ref'];
    },
  },
  {
    id: 'DOSH_003',
    title: 'Ausência de headers de rate limiting',
    category: 'Negação de Serviço (DoS)',
    severity: 'low',
    description: 'A resposta não expõe nenhum header de rate limiting (RateLimit-Limit/Remaining/Reset, X-RateLimit-*, X-Rate-Limit-Limit ou Retry-After).',
    impact: 'A ausência desses headers sugere que pode não haver limitação de requisições, deixando a API mais exposta a brute force, scraping e DoS na camada de aplicação.',
    remediation: 'Implemente rate limiting e exponha os headers padronizados (RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset) e Retry-After ao exceder o limite.',
    safeExample: 'RateLimit-Limit: 100\nRateLimit-Remaining: 87\nRateLimit-Reset: 60\nRetry-After: 60',
    reference: 'OWASP API4:2023 - Unrestricted Resource Consumption; CWE-770',
    check: (headers) => {
      const h = headers;
      return !(
        h['ratelimit-limit'] || h['ratelimit-remaining'] || h['ratelimit-reset'] ||
        h['x-ratelimit-limit'] || h['x-ratelimit-remaining'] || h['x-rate-limit-limit'] ||
        h['retry-after']);
    },
  },
  {
    id: 'DOSH_004',
    title: 'Origem expõe IP/infra real sem edge',
    category: 'Negação de Serviço (DoS)',
    severity: 'low',
    description: 'A resposta vaza informação de infraestrutura da origem (X-Powered-By ou versão no header Server) e não há indício de uma camada de borda (CDN/WAF) à frente.',
    impact: 'Expor a stack e a versão da origem, sem proteção de borda, facilita a fingerprinting e o direcionamento de ataques (DDoS e exploração de versões vulneráveis) diretamente contra o servidor.',
    remediation: 'Remova X-Powered-By e a versão do header Server, e posicione um CDN/WAF à frente para ocultar e proteger a origem.',
    safeExample: "// Em Express:\napp.disable('x-powered-by');\n// e sirva a aplicação atrás de um CDN/WAF, sem versão no header Server.",
    reference: 'OWASP A05:2021 - Security Misconfiguration; CWE-200',
    check: (headers) => {
      const h = headers;
      const hasEdge = !!h['cf-ray'] || !!h['x-amz-cf-id'] || !!h['x-served-by'] ||
        !!h['x-vercel-id'] || !!h['x-nf-request-id'] || !!h['x-akamai-request-id'];
      const leaksOrigin = !!h['x-powered-by'] || /\d+\.\d+/.test(h['server'] || '');
      return leaksOrigin && !hasEdge;
    },
  },
];
