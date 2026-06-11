#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const BASE = 'https://api.render.com/v1';
const RENDER_API_KEY = process.env.RENDER_API_KEY;
const SERVICE_NAME = process.argv[2] || process.env.RENDER_SERVICE_NAME || 'watchdog-api';

if (!RENDER_API_KEY) {
  console.error('ERROR: set RENDER_API_KEY in your environment before running this script.');
  console.error('On Windows PowerShell: $env:RENDER_API_KEY = "..."');
  process.exit(1);
}

const YAML_PATH = path.join(__dirname, '..', '..', 'render.yaml');
if (!fs.existsSync(YAML_PATH)) {
  console.error('ERROR: render.yaml not found at', YAML_PATH);
  process.exit(1);
}

const yamlText = fs.readFileSync(YAML_PATH, 'utf8');
const doc = yaml.load(yamlText);
if (!doc || !Array.isArray(doc.services) || doc.services.length === 0) {
  console.error('ERROR: no services found in render.yaml');
  process.exit(1);
}

const yamlService = doc.services.find(s => s.name === SERVICE_NAME) || doc.services[0];
console.log('Using service definition from render.yaml:', yamlService.name);

const fetchWithAuth = (url, opts = {}) => {
  opts.headers = Object.assign({
    Authorization: `Bearer ${RENDER_API_KEY}`,
    Accept: 'application/json',
    'Content-Type': 'application/json'
  }, opts.headers || {});
  return fetch(url, opts);
};

async function findServiceByName(name) {
  const url = `${BASE}/services?name=${encodeURIComponent(name)}&limit=100`;
  const res = await fetchWithAuth(url, { method: 'GET' });
  if (!res.ok) throw new Error(`list services failed: ${res.status} ${await res.text()}`);
  const body = await res.json();
  return body.find(s => s.name === name) || null;
}

function collectEnvVarsFromYaml(svc) {
  const missing = [];
  const envs = [];
  const list = svc.envVars || [];
  for (const e of list) {
    const key = e.key;
    if (Object.prototype.hasOwnProperty.call(e, 'value')) {
      envs.push({ key, value: String(e.value) });
      continue;
    }
    // sensitive / sync:false -> read from runtime env
    const val = process.env[key];
    if (val === undefined) missing.push(key);
    else envs.push({ key, value: String(val) });
  }
  return { envs, missing };
}

async function putEnvVars(serviceId, envs) {
  const url = `${BASE}/services/${serviceId}/env-vars`;
  const res = await fetchWithAuth(url, { method: 'PUT', body: JSON.stringify(envs) });
  if (!res.ok) throw new Error(`update env-vars failed: ${res.status} ${await res.text()}`);
  return res.json();
}

async function triggerDeploy(serviceId) {
  const url = `${BASE}/services/${serviceId}/deploys`;
  const res = await fetchWithAuth(url, { method: 'POST', body: JSON.stringify({}) });
  if (!res.ok) throw new Error(`trigger deploy failed: ${res.status} ${await res.text()}`);
  return res.json();
}

(async () => {
  try {
    console.log('Checking for existing Render service named', SERVICE_NAME);
    const svc = await findServiceByName(SERVICE_NAME);
    if (!svc) {
      console.error(`Service named "${SERVICE_NAME}" not found in your Render account.`);
      console.error('This script only updates env vars/secret files for an existing service.');
      console.error('To create a new service from the blueprint, either:');
      console.error('- Use the Render Dashboard and import the repository/`render.yaml` blueprint');
      console.error('- Or use the Blueprints API. See scripts/render/README.md for instructions.');
      process.exit(2);
    }

    console.log('Found service:', svc.id, svc.name);

    const { envs, missing } = collectEnvVarsFromYaml(yamlService);
    if (missing.length > 0) {
      console.error('ERROR: missing environment values for keys marked as sensitive in render.yaml:');
      for (const k of missing) console.error(' -', k);
      console.error('\nSet these keys in your shell before re-running. Example:');
      console.error('\nPowerShell:');
      console.error(`  $env:KEY_NAME = \"value\"`);
      console.error('\nBash:');
      console.error(`  export KEY_NAME=\"value\"`);
      process.exit(3);
    }

    console.log('Updating environment variables on Render (values taken from your local environment or render.yaml)...');
    await putEnvVars(svc.id, envs);
    console.log('Environment variables updated successfully. Triggering deploy...');
    await triggerDeploy(svc.id);
    console.log('Deploy triggered successfully. Done.');
  } catch (err) {
    console.error('ERROR:', err.message || err);
    process.exit(10);
  }
})();
