import { FileRule } from '../types';

export const corsRules: FileRule[] = [
  {
    id: 'CORS_001',
    title: 'CORS aberto com wildcard na API',
    category: 'CORS',
    severity: 'high',
    description: 'API configurada com Access-Control-Allow-Origin: * em rota autenticada.',
    impact: 'Qualquer site pode fazer requisições à API. Se houver cookies ou tokens, pode facilitar ataques CSRF.',
    remediation: 'Defina uma whitelist de origens permitidas.',
    safeExample: "cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') ?? [] })",
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    patterns: [
      /res\.setHeader\(["'`]Access-Control-Allow-Origin["'`],\s*["'`]\*["'`]\)/,
      /["'`]Access-Control-Allow-Origin["'`]\s*:\s*["'`]\*["'`]/,
    ],
    fileExtensions: ['.js', '.ts'],
  },
  {
    id: 'CORS_002',
    title: 'Origem refletida sem whitelist',
    category: 'CORS',
    severity: 'high',
    description: 'A origem da requisição está sendo refletida diretamente no header CORS sem validação.',
    impact: 'Qualquer origem pode fazer requisições autenticadas.',
    remediation: 'Valide a origem contra uma whitelist antes de refletir.',
    safeExample: "const allowedOrigins = ['https://app.com'];\nconst origin = req.headers.origin;\nif (allowedOrigins.includes(origin)) {\n  res.setHeader('Access-Control-Allow-Origin', origin);\n}",
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    patterns: [
      /res\.setHeader\(["'`]Access-Control-Allow-Origin["'`],\s*req\.headers\.origin/,
      /origin\s*:\s*\(origin,\s*callback\)\s*=>\s*callback\(null,\s*origin\)/,
    ],
    fileExtensions: ['.js', '.ts'],
  },
  {
    id: 'CORS_003',
    title: 'Métodos HTTP excessivos no CORS',
    category: 'CORS',
    severity: 'low',
    description: 'CORS configurado para permitir métodos HTTP excessivos como TRACE, CONNECT.',
    impact: 'Expõe métodos que podem ser explorados para reconhecimento ou ataques.',
    remediation: 'Permita apenas os métodos HTTP necessários (GET, POST, PUT, DELETE, PATCH).',
    safeExample: "cors({ methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] })",
    reference: 'OWASP A05:2021 - Security Misconfiguration',
    patterns: [
      /methods\s*:\s*\[[^\]]*(?:TRACE|CONNECT)[^\]]*\]/i,
    ],
    fileExtensions: ['.js', '.ts'],
  },
];
