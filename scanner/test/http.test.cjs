'use strict';
// Testes do cliente HTTP seguro (correção do corpo grande) e da resiliência do URL analyzer.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');

const { performRequest } = require('../dist/utils/safeHttpClient.js');
const { analyzeUrl } = require('../dist/index.js');

// Sobe um servidor HTTP local efêmero e retorna { port, close }.
function startServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ port: server.address().port, close: () => server.close() }));
  });
}
const validationFor = (port, path = '/') => ({
  valid: true,
  normalizedUrl: `http://127.0.0.1:${port}${path}`,
  address: '127.0.0.1',
  family: 4,
});

// O bug que zerava o YouTube: corpo > MAX_BODY_SIZE fazia req.destroy() e o
// 'error' descartava headers/status. Agora deve resolver com truncated=true.
test('corpo grande NÃO vira erro: mantém status 200 + headers + truncated', async () => {
  const big = 'A'.repeat(2 * 1024 * 1024); // 2MB, acima do teto
  const srv = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'x-test': 'sim', 'strict-transport-security': 'max-age=10' });
    res.end(big);
  });
  try {
    const r = await performRequest(validationFor(srv.port), {}, [], `http://127.0.0.1:${srv.port}/`);
    assert.equal(r.error, undefined, `não deveria haver erro, veio: ${r.error}`);
    assert.equal(r.statusCode, 200);
    assert.equal(r.truncated, true, 'deveria marcar truncated');
    assert.equal(r.headers['x-test'], 'sim', 'headers preservados');
    assert.ok(r.body.length > 0 && r.body.length < big.length, 'corpo truncado mas presente');
  } finally { srv.close(); }
});

test('corpo pequeno: body completo, sem truncamento', async () => {
  const srv = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });
  try {
    const r = await performRequest(validationFor(srv.port), {}, [], `http://127.0.0.1:${srv.port}/`);
    assert.equal(r.statusCode, 200);
    assert.ok(!r.truncated);
    assert.equal(r.body, '{"ok":true}');
  } finally { srv.close(); }
});

test('redirect: retorna redirectLocation sem baixar corpo', async () => {
  const srv = await startServer((req, res) => {
    res.writeHead(302, { location: 'https://exemplo.com/destino' });
    res.end('ignorado');
  });
  try {
    const r = await performRequest(validationFor(srv.port), {}, [], `http://127.0.0.1:${srv.port}/`);
    assert.equal(r.statusCode, 302);
    assert.equal(r.redirectLocation, 'https://exemplo.com/destino');
    assert.equal(r.body, '');
  } finally { srv.close(); }
});

// Resiliência do analyzer: alvo inacessível/bloqueado NÃO retorna vazio — emite SCAN_001.
// Usa um IP privado: o gate SSRF do safeGet bloqueia → mainResponse.error → SCAN_001.
test('analyzeUrl: alvo bloqueado gera achado SCAN_001 (não retorna vazio)', async () => {
  const res = await analyzeUrl({ url: 'http://10.0.0.1/', scanId: 't', depth: 'quick', onEvent: () => {} });
  assert.ok(res.findings.some(f => f.ruleId === 'SCAN_001'), 'esperava SCAN_001 ao falhar a conexão');
});
