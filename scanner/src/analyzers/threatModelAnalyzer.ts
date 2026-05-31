import { Finding, TechStack, ThreatModelData, ThreatGap } from '@sentinelscope/shared';

const ASSET_RULES: Array<{ condition: (f: Finding[], t: TechStack[]) => boolean; asset: string }> = [
  { condition: (_, t) => t.some(x => x.category === 'database'), asset: 'Banco de dados' },
  { condition: (_, t) => t.some(x => x.name.includes('Supabase') || x.name.includes('Firebase')), asset: 'Banco de dados em nuvem (Supabase/Firebase)' },
  { condition: (f) => f.some(x => x.category === 'Autenticação'), asset: 'Sessões e tokens de autenticação' },
  { condition: (_, t) => t.some(x => x.category === 'web3'), asset: 'Smart contracts e wallets crypto' },
  { condition: (f) => f.some(x => x.category === 'Upload'), asset: 'Arquivos e uploads de usuário' },
  { condition: (f) => f.some(x => x.ruleId.startsWith('API_')), asset: 'Endpoints de API' },
  { condition: (f) => f.some(x => x.category === 'Secrets'), asset: 'Chaves de API, tokens e credenciais' },
  { condition: (_, t) => t.some(x => x.category === 'devops'), asset: 'Pipeline de CI/CD e deploy' },
  { condition: (f) => f.some(x => x.ruleId.startsWith('SUPA_') || x.ruleId.startsWith('FIRE_')), asset: 'Regras de autorização do banco (RLS/Firestore Rules)' },
  { condition: () => true, asset: 'Dados pessoais de usuários (LGPD)' },
  { condition: () => true, asset: 'Painel administrativo' },
  { condition: () => true, asset: 'Código-fonte do repositório' },
];

const ATTACKER_PROFILES = [
  'Visitante anônimo não autenticado',
  'Usuário autenticado tentando acessar dados de outros usuários (IDOR)',
  'Bot automatizado (brute force, scraping, credential stuffing)',
  'Atacante externo explorando vulnerabilidades públicas',
  'Funcionário interno mal-intencionado ou com credencial comprometida',
  'Dependência npm comprometida na supply chain',
  'Serviço terceiro comprometido (webhook, OAuth provider)',
];

const ATTACK_SURFACES: Array<{ condition: (f: Finding[], t: TechStack[]) => boolean; surface: string }> = [
  { condition: (f) => f.some(x => x.ruleId.startsWith('AUTH_')), surface: 'Endpoints de autenticação (login, registro, reset de senha)' },
  { condition: (f) => f.some(x => x.ruleId.startsWith('UPLOAD_')), surface: 'Sistema de upload de arquivos' },
  { condition: (f) => f.some(x => x.ruleId.startsWith('API_')), surface: 'API REST / GraphQL pública ou semi-pública' },
  { condition: (f) => f.some(x => x.ruleId.startsWith('AUTHZ_')), surface: 'Rotas administrativas e operações privilegiadas' },
  { condition: (_, t) => t.some(x => x.name.includes('Docker')), surface: 'Infraestrutura Docker/container' },
  { condition: (_, t) => t.some(x => x.name.includes('GitHub Actions')), surface: 'Pipeline de CI/CD (GitHub Actions)' },
  { condition: (_, t) => t.some(x => x.category === 'web3'), surface: 'Smart contracts e transações blockchain' },
  { condition: (f) => f.some(x => x.ruleId.startsWith('SUPA_') || x.ruleId.startsWith('FIRE_')), surface: 'Banco de dados em nuvem (Supabase/Firebase) acessível pelo cliente' },
  { condition: () => true, surface: 'Frontend público (XSS, CSRF, clickjacking)' },
  { condition: () => true, surface: 'Variáveis de ambiente e gestão de secrets' },
];

const EXPECTED_CONTROLS = [
  'Autenticação forte (senha + hash bcrypt/argon2)',
  'Autorização no backend (não apenas no frontend)',
  'Rate limiting em rotas sensíveis',
  'Validação e sanitização de input com Zod/Joi',
  'Headers de segurança (Helmet, CSP, HSTS)',
  'CORS restrito a origens específicas',
  'Cookies seguros (HttpOnly, Secure, SameSite)',
  'Secrets em variáveis de ambiente (nunca no código)',
  'Logs sem dados sensíveis',
  'RLS ativo no Supabase / Rules restritivas no Firebase',
  'Uploads com validação de MIME type e limite de tamanho',
  'MFA para contas administrativas',
  'Monitoramento e alertas de segurança',
  'Política de retenção e exclusão de dados (LGPD)',
];

export function generateThreatModel(
  findings: Finding[],
  techStack: TechStack[]
): Omit<ThreatModelData, 'id'> {
  const assets = ASSET_RULES
    .filter(r => r.condition(findings, techStack))
    .map(r => r.asset);

  const attackSurfaces = ATTACK_SURFACES
    .filter(r => r.condition(findings, techStack))
    .map(r => r.surface);

  const gaps: ThreatGap[] = findings
    .filter(f => ['critical', 'high'].includes(f.severity))
    .slice(0, 15)
    .map(f => ({
      findingId: f.id,
      ruleId: f.ruleId,
      title: f.title,
      brokenControl: deriveControl(f),
      risk: f.impact,
      fix: f.remediation,
    }));

  return {
    scanId: findings[0]?.scanId || '',
    assets: [...new Set(assets)],
    attackers: ATTACKER_PROFILES,
    attackSurfaces: [...new Set(attackSurfaces)],
    controls: EXPECTED_CONTROLS,
    gaps,
  };
}

function deriveControl(f: Finding): string {
  const category = f.category.toLowerCase();
  if (category.includes('secret') || category.includes('credencial')) return 'Gestão segura de secrets';
  if (category.includes('auth')) return 'Autenticação e gestão de sessão';
  if (category.includes('autoriz')) return 'Controle de acesso baseado em papéis';
  if (category.includes('cors')) return 'Política de CORS';
  if (category.includes('header')) return 'Headers de segurança HTTP';
  if (category.includes('upload')) return 'Validação de uploads';
  if (category.includes('docker')) return 'Hardening de containers';
  if (category.includes('ci') || category.includes('cicd')) return 'Segurança de pipeline CI/CD';
  if (category.includes('web3')) return 'Segurança de smart contracts';
  if (category.includes('supabase') || category.includes('firebase')) return 'Regras de autorização do banco';
  if (category.includes('log')) return 'Mascaramento de dados em logs';
  if (category.includes('privacidade') || category.includes('lgpd')) return 'Compliance de privacidade (LGPD)';
  return 'Controle de segurança geral';
}
