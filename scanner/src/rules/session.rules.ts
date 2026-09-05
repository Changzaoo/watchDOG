import { FileRule } from '../types';

/**
 * Gestão de sessão e identidade (OWASP A07:2025).
 *
 * Complementa auth.rules/jwt.rules cobrindo o CICLO DE VIDA da sessão:
 * criação (fixation), expiração, invalidação no logout, proteção do
 * segredo de sessão e fluxos de recuperação de senha.
 */
export const sessionRules: FileRule[] = [
  {
    id: 'SESS_001',
    title: 'Segredo de sessão hardcoded ou com fallback fraco',
    category: 'Sessão',
    severity: 'critical',
    confidence: 'medium',
    description:
      'O segredo usado para assinar a sessão/cookie está escrito no código ou usa um fallback previsível quando a variável de ambiente não existe (ex.: process.env.SECRET || "dev").',
    impact:
      'Conhecendo o segredo, um atacante forja cookies de sessão válidos para qualquer usuário — inclusive administradores — sem precisar de senha.',
    attackScenarioDefensive:
      'O segredo "keyboard-cat" (ou o fallback de desenvolvimento) vaza no repositório público; o atacante assina localmente um cookie com userId de admin e acessa o painel como administrador.',
    remediation:
      'Carregue o segredo exclusivamente de variável de ambiente e falhe na inicialização se ele não existir. Use um valor aleatório de 32+ bytes e rotacione-o em caso de suspeita de vazamento.',
    safeExample:
      "const SESSION_SECRET = process.env.SESSION_SECRET;\nif (!SESSION_SECRET) throw new Error('SESSION_SECRET obrigatorio');\napp.use(session({ secret: SESSION_SECRET, /* ... */ }));",
    testSuggestion:
      'Suba a aplicação sem a variável de ambiente do segredo e confirme que ela se recusa a iniciar em vez de usar um padrão.',
    reference: 'OWASP A07:2025 - Authentication Failures; CWE-798',
    patterns: [
      /(?:session|cookieSession|cookieParser)\s*\(\s*\{[^}]{0,200}?secret\s*:\s*["'`][^"'`]{3,}["'`]/i,
      /secret\s*:\s*process\.env\.[A-Z_]+\s*\|\|\s*["'`][^"'`]+["'`]/,
      /(?:SESSION_SECRET|COOKIE_SECRET|JWT_SECRET)\s*=\s*["'`](?:secret|dev|test|change[-_ ]?me|keyboard[-_ ]?cat|123|password)[^"'`]*["'`]/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.env'],
  },
  {
    id: 'SESS_002',
    title: 'Sessão sem renovação de ID após login (session fixation)',
    category: 'Sessão',
    severity: 'medium',
    confidence: 'low',
    description:
      'O handler de login grava dados do usuário na sessão existente sem regenerar o identificador (req.session.regenerate / session.cycleKey).',
    impact:
      'Session fixation: um identificador de sessão conhecido pelo atacante antes do login continua válido depois, permitindo que ele assuma a sessão autenticada da vítima.',
    attackScenarioDefensive:
      'O atacante induz a vítima a acessar a aplicação com um session id que ele mesmo definiu; quando ela faz login, o id não muda e ele passa a ter uma sessão autenticada como a vítima.',
    remediation:
      'Chame req.session.regenerate() (ou equivalente) imediatamente após autenticar, antes de gravar os dados do usuário na sessão.',
    safeExample:
      "req.session.regenerate(err => {\n  if (err) return next(err);\n  req.session.userId = usuario.id;\n  req.session.save(() => res.json({ ok: true }));\n});",
    testSuggestion:
      'Anote o cookie de sessão antes do login e compare depois: o identificador deve ter mudado.',
    reference: 'OWASP A07:2025; CWE-384 - Session Fixation',
    patterns: [
      /req\.session\.(?:userId|user|uid|isAuth|authenticated|loggedIn)\s*=/i,
    ],
    suppressIfProjectMatches: /session\.regenerate|cycleKey|regenerateSession|rotateSession/i,
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'SESS_003',
    title: 'Sessão/cookie sem expiração definida',
    category: 'Sessão',
    severity: 'medium',
    confidence: 'low',
    description:
      'Configuração de sessão ou cookie de autenticação sem maxAge/expires, criando sessões que permanecem válidas indefinidamente.',
    impact:
      'Sessões eternas ampliam a janela de exploração de um token roubado: um cookie capturado em máquina compartilhada continua funcionando meses depois.',
    attackScenarioDefensive:
      'O atacante obtém um cookie antigo do backup do navegador da vítima em um computador compartilhado e, como a sessão nunca expira, acessa a conta normalmente.',
    remediation:
      'Defina maxAge compatível com o risco (ex.: 30 min a 8 h para apps sensíveis), com expiração absoluta e por inatividade, além de renovação explícita.',
    safeExample:
      "app.use(session({\n  secret: process.env.SESSION_SECRET,\n  rolling: true,\n  cookie: { maxAge: 1000 * 60 * 30, httpOnly: true, secure: true, sameSite: 'strict' },\n}));",
    testSuggestion:
      'Autentique, aguarde além do tempo configurado e confirme que a sessão foi recusada.',
    reference: 'OWASP A07:2025; CWE-613 - Insufficient Session Expiration',
    patterns: [
      /session\s*\(\s*\{(?:(?!maxAge|expires)[\s\S]){0,300}?\}\s*\)/,
      /res\.cookie\s*\(\s*["'`](?:session|sid|token|auth|jwt)[^"'`]*["'`][^)]*\{(?:(?!maxAge|expires)[\s\S]){0,150}?\}\s*\)/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'SESS_004',
    title: 'Logout que não invalida a sessão no servidor',
    category: 'Sessão',
    severity: 'medium',
    confidence: 'low',
    description:
      'Rota de logout que apenas limpa o cookie no cliente (clearCookie) sem destruir a sessão no servidor nem revogar o token.',
    impact:
      'O token continua válido após o "logout": quem tiver uma cópia dele (log, proxy, dispositivo compartilhado) mantém acesso à conta mesmo depois de o usuário sair.',
    attackScenarioDefensive:
      'A vítima faz logout num computador público, mas o atacante que capturou o cookie antes continua autenticado, pois o servidor nunca invalidou a sessão.',
    remediation:
      'Destrua a sessão no servidor (req.session.destroy) e/ou revogue o token numa denylist/tabela de sessões, além de limpar o cookie no cliente.',
    safeExample:
      "req.session.destroy(() => {\n  res.clearCookie('sid', { httpOnly: true, secure: true, sameSite: 'strict', path: '/' });\n  res.json({ ok: true });\n});\n// Para JWT: registre o jti numa denylist ate expirar.",
    testSuggestion:
      'Salve o cookie, faça logout e reenvie o cookie salvo: o servidor deve responder 401.',
    reference: 'OWASP A07:2025; CWE-613',
    patterns: [
      /(?:router|app)\.(?:post|get)\s*\(\s*["'`][^"'`]*logout[^"'`]*["'`][\s\S]{0,300}?res\.clearCookie(?![\s\S]{0,300}?(?:session\.destroy|revoke|denylist|blacklist|invalidate))/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'SESS_005',
    title: 'Token de reset de senha fraco ou sem expiração',
    category: 'Sessão',
    severity: 'high',
    confidence: 'low',
    description:
      'Token de recuperação de senha gerado com baixa entropia (Date.now, incremento, UUID v1) ou armazenado sem prazo de validade.',
    impact:
      'Tokens previsíveis ou eternos permitem que um atacante gere/adivinhe o link de reset de outra conta e tome posse dela sem conhecer a senha atual.',
    attackScenarioDefensive:
      'O token é derivado de Date.now(); o atacante solicita um reset para a vítima, estima o timestamp e itera poucas centenas de valores até acertar o link válido.',
    remediation:
      'Gere o token com crypto.randomBytes(32), armazene apenas o hash dele, defina expiração curta (15-60 min) e invalide-o após o primeiro uso.',
    safeExample:
      "const token = crypto.randomBytes(32).toString('hex');\nconst tokenHash = crypto.createHash('sha256').update(token).digest('hex');\nawait db.resetToken.create({ data: {\n  userId, tokenHash, expiresAt: new Date(Date.now() + 30 * 60_000),\n}});\n// envie 'token' por e-mail; compare pelo hash e apague apos o uso",
    testSuggestion:
      'Peça dois resets seguidos e compare os tokens (devem ser imprevisíveis); use um token expirado e confirme a recusa.',
    reference: 'OWASP A07:2025; CWE-640; CWE-330',
    patterns: [
      /(?:resetToken|reset_token|recoveryToken|passwordToken|confirmToken)\s*[:=][^;\n]{0,80}(?:Date\.now\s*\(|new\s+Date\s*\(|uuidv1\s*\(|Math\.random)/i,
      /(?:resetToken|reset_token|recoveryToken)\s*[:=][^;\n]{0,60}(?:toString\s*\(\s*36|\+\+)/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'SESS_006',
    title: 'Enumeração de usuários em login/recuperação',
    category: 'Sessão',
    severity: 'low',
    confidence: 'low',
    description:
      'Mensagens de erro distintas para "usuário não encontrado" e "senha incorreta", revelando quais e-mails existem na base.',
    impact:
      'Permite enumerar contas válidas e concentrar ataques de força bruta, phishing e credential stuffing nos e-mails que realmente existem.',
    attackScenarioDefensive:
      'O atacante submete uma lista de e-mails ao login e separa os que retornam "senha incorreta" dos que retornam "usuário não encontrado", montando uma lista de alvos reais.',
    remediation:
      'Use uma mensagem genérica idêntica para ambos os casos ("E-mail ou senha inválidos") e mantenha tempos de resposta semelhantes. No fluxo de recuperação, responda sempre a mesma coisa.',
    safeExample:
      "const generico = { error: 'E-mail ou senha invalidos.' };\nif (!usuario) return res.status(401).json(generico);\nif (!(await verificarSenha(senha, usuario.hash))) return res.status(401).json(generico);",
    testSuggestion:
      'Tente logar com um e-mail inexistente e com um existente e senha errada: resposta, status e tempo devem ser equivalentes.',
    reference: 'OWASP A07:2025; CWE-204 - Observable Response Discrepancy',
    patterns: [
      /(?:usuario|user|email)\s+(?:nao|não)\s+(?:encontrado|existe|cadastrado)|user\s+not\s+found|email\s+not\s+(?:found|registered)/i,
      /(?:senha|password)\s+(?:incorreta|invalida|inválida|errada)|(?:wrong|incorrect|invalid)\s+password/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
];
