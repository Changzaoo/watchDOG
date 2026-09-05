'use strict';
// Testes do guard da tela de resultado — runner nativo do Node (node:test).
// Rodam contra o TS compilado para CJS na hora, sem dependência nova.
// Execute via: npm run test --workspace=frontend
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

// Compila só o módulo do guard (é TS puro, sem JSX nem imports de app).
// Chama o tsc.js pelo próprio node: no Windows, spawnSync em `npx.cmd` dá EINVAL.
const src = path.join(__dirname, '..', 'src', 'lib', 'scanGuard.ts');
const outDir = path.join(__dirname, '.tmp');
fs.mkdirSync(outDir, { recursive: true });
const tsc = require.resolve('typescript/bin/tsc');
execFileSync(
  process.execPath,
  [tsc, src, '--outDir', outDir, '--module', 'commonjs', '--target', 'es2019'],
  { stdio: 'pipe' }
);
// O package.json do frontend é "type": "module", então um .js solto aqui seria
// lido como ESM e o output CommonJS do tsc quebraria. Este marcador local
// devolve a pasta para CommonJS.
fs.writeFileSync(path.join(outDir, 'package.json'), '{"type":"commonjs"}\n');
const { shouldRedirectToUrlScan } = require(path.join(outDir, 'scanGuard.js'));

const URL_SCAN = { id: 'scan-1', type: 'url' };
const LOCAL_SCAN = { id: 'scan-1', type: 'local' };

// ---------------------------------------------------------------------------
// A REGRESSÃO: o primeiro scan de URL da sessão era expulso da tela.
test('primeiro scan da sessão (store vazia) NÃO redireciona', () => {
  // Era exatamente este estado que quebrava: currentScan null porque o
  // loadScan() ainda não voltou, e o guard antigo mandava para /scan/url.
  assert.equal(shouldRedirectToUrlScan({
    loading: false,
    backendHealthChecked: true,
    localScansEnabled: false,
    routeId: 'scan-1',
    scan: null,
  }), false);
});

test('enquanto carrega, NÃO redireciona (nem com scan local na store)', () => {
  assert.equal(shouldRedirectToUrlScan({
    loading: true,
    backendHealthChecked: true,
    localScansEnabled: false,
    routeId: 'scan-1',
    scan: LOCAL_SCAN,
  }), false);
});

test('scan de URL carregado NÃO redireciona', () => {
  assert.equal(shouldRedirectToUrlScan({
    loading: false,
    backendHealthChecked: true,
    localScansEnabled: false,
    routeId: 'scan-1',
    scan: URL_SCAN,
  }), false);
});

test('scan da store é de OUTRA tela (id não bate) — NÃO redireciona', () => {
  // Ao trocar de scan, a store global ainda tem o anterior por um render.
  assert.equal(shouldRedirectToUrlScan({
    loading: false,
    backendHealthChecked: true,
    localScansEnabled: false,
    routeId: 'scan-2',
    scan: LOCAL_SCAN,
  }), false);
});

test('antes do /health responder, NÃO redireciona', () => {
  assert.equal(shouldRedirectToUrlScan({
    loading: false,
    backendHealthChecked: false,
    localScansEnabled: false,
    routeId: 'scan-1',
    scan: LOCAL_SCAN,
  }), false);
});

// ---------------------------------------------------------------------------
// O comportamento que o guard EXISTE para garantir continua de pé.
test('scan LOCAL em backend sem scan local: redireciona', () => {
  assert.equal(shouldRedirectToUrlScan({
    loading: false,
    backendHealthChecked: true,
    localScansEnabled: false,
    routeId: 'scan-1',
    scan: LOCAL_SCAN,
  }), true);
});

test('scan LOCAL em backend QUE ACEITA local: não redireciona', () => {
  assert.equal(shouldRedirectToUrlScan({
    loading: false,
    backendHealthChecked: true,
    localScansEnabled: true,
    routeId: 'scan-1',
    scan: LOCAL_SCAN,
  }), false);
});
