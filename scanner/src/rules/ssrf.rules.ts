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
    reference: 'OWASP A10:2021 SSRF; CWE-918',
    patterns: [
      /(?:fetch|axios(?:\.get|\.post)?|https?\.get|requests\.(?:get|post))\s*\(\s*(?:req\.(?:body|query|params)|`[^`]*\$\{[^}]*req\.(?:body|query|params))/i,
    ],
    fileExtensions: ['.js', '.ts', '.py', '.mjs'],
  },
];
