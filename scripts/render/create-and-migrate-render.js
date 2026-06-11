#!/usr/bin/env node
// Create a new Render service based on an existing service and migrate env-vars + secret files.
// Usage: RENDER_API_KEY=... node create-and-migrate-render.js <oldServiceName> <newServiceName?>

const fs = require('fs');
const path = require('path');

const BASE = 'https://api.render.com/v1';
const RENDER_API_KEY = process.env.RENDER_API_KEY;
if (!RENDER_API_KEY) {
  console.error('ERROR: set RENDER_API_KEY in your environment before running this script.');
  console.error('PowerShell: $env:RENDER_API_KEY = "<key>"');
  process.exit(1);
}

const oldName = process.argv[2] || 'watchdog-api';
let newName = process.argv[3] || `${oldName}-migrated-${Date.now().toString().slice(-6)}`;

const headersAuth = {
  Authorization: `Bearer ${RENDER_API_KEY}`,
  Accept: 'application/json',
  'Content-Type': 'application/json'
};
const yaml = require('js-yaml');
const cp = require('child_process');

function parseDotEnv(filePath) {
  try {
    const txt = fs.readFileSync(filePath, 'utf8');
    const out = {};
    for (const raw of txt.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const m = line.match(/^([^=]+)=(.*)$/s);
      if (!m) continue;
      const key = m[1].trim();
      let val = m[2];
      // strip surrounding quotes
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      out[key] = val;
    }
    return out;
  } catch (e) {
    return {};
  }
}

function tryDecodeBase64Json(base64) {
  try {
    const buff = Buffer.from(base64, 'base64');
    const txt = buff.toString('utf8');
    try {
      return JSON.parse(txt);
    } catch (e) {
      return txt;
    }
  } catch (e) {
    return null;
  }
}

async function fetchJson(url, opts = {}) {
  opts.headers = Object.assign({}, headersAuth, opts.headers || {});
  const res = await fetch(url, opts);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} - ${text}`);
  return data;
}

async function findServiceByName(name) {
  const url = `${BASE}/services?limit=100&name=${encodeURIComponent(name)}`;
  const body = await fetchJson(url, { method: 'GET' });
  if (Array.isArray(body)) return body.find(s => s.name === name) || null;
  return null;
}

async function getService(id) {
  return fetchJson(`${BASE}/services/${encodeURIComponent(id)}`, { method: 'GET' });
}

async function listEnvVars(serviceId) {
  return fetchJson(`${BASE}/services/${encodeURIComponent(serviceId)}/env-vars`, { method: 'GET' });
}

async function listSecretFiles(serviceId) {
  const list = await fetchJson(`${BASE}/services/${encodeURIComponent(serviceId)}/secret-files`, { method: 'GET' });
  const out = [];
  for (const f of list || []) {
    const file = await fetchJson(`${BASE}/services/${encodeURIComponent(serviceId)}/secret-files/${encodeURIComponent(f.name)}`, { method: 'GET' });
    // API returns { name, content }
    out.push({ name: file.name, content: file.content });
  }
  return out;
}

function pickServiceDetails(oldFull) {
  const sd = oldFull.serviceDetails || oldFull.webServiceDetails || oldFull.privateServiceDetails || {};
  const out = {};
  if (sd.runtime) out.runtime = sd.runtime;
  if (sd.envSpecificDetails) {
    out.envSpecificDetails = {};
    const e = sd.envSpecificDetails;
    if (e.buildCommand) out.envSpecificDetails.buildCommand = e.buildCommand;
    if (e.startCommand) out.envSpecificDetails.startCommand = e.startCommand;
    if (e.preDeployCommand) out.envSpecificDetails.preDeployCommand = e.preDeployCommand;
    if (e.publishPath) out.envSpecificDetails.publishPath = e.publishPath;
  }
  if (sd.healthCheckPath) out.healthCheckPath = sd.healthCheckPath;
  if (sd.preDeployCommand) out.preDeployCommand = sd.preDeployCommand;
  if (sd.numInstances) out.numInstances = sd.numInstances;
  if (sd.plan) out.plan = sd.plan;
  if (sd.region) out.region = sd.region;
  return out;
}

async function createService(payload) {
  return fetchJson(`${BASE}/services`, { method: 'POST', body: JSON.stringify(payload) });
}

async function putEnvVars(serviceId, envs) {
  return fetchJson(`${BASE}/services/${encodeURIComponent(serviceId)}/env-vars`, { method: 'PUT', body: JSON.stringify(envs) });
}

async function createDiskIfNeeded(oldFull, newServiceId) {
  const disk = oldFull.disk || (oldFull.serviceDetails && oldFull.serviceDetails.disk);
  if (!disk || !disk.sizeGB) return null;
  const payload = { name: disk.name || `${newServiceId}-disk`, sizeGB: disk.sizeGB, mountPath: disk.mountPath || '/var/data', serviceId: newServiceId };
  return fetchJson(`${BASE}/disks`, { method: 'POST', body: JSON.stringify(payload) });
}

(async function main() {
  try {
    console.log('Looking up service:', oldName);
    const old = await findServiceByName(oldName);

    if (!old) {
      console.log('Old service not found. Will create new service from render.yaml and migrate env-vars.');

      const YAML_PATH = path.join(__dirname, '..', '..', 'render.yaml');
      if (!fs.existsSync(YAML_PATH)) {
        console.error('render.yaml not found at', YAML_PATH);
        process.exit(4);
      }
      const yamlText = fs.readFileSync(YAML_PATH, 'utf8');
      const doc = yaml.load(yamlText);
      if (!doc || !Array.isArray(doc.services) || doc.services.length === 0) {
        console.error('No services found in render.yaml');
        process.exit(5);
      }
      const yamlService = doc.services.find(s => s.name === oldName) || doc.services[0];

      // Collect env values from local files: backend/.env.example, backend/.env, and process.env
      const envExamplePath = path.join(__dirname, '..', '..', 'backend', '.env.example');
      const envPath = path.join(__dirname, '..', '..', 'backend', '.env');
      const exampleEnv = parseDotEnv(envExamplePath);
      const localEnv = parseDotEnv(envPath);
      const sourceEnv = Object.assign({}, exampleEnv, localEnv, process.env);

      // Special handling: if FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 exists, decode and populate related keys
      if (sourceEnv.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 && !sourceEnv.FIREBASE_SERVICE_ACCOUNT_JSON) {
        const parsed = tryDecodeBase64Json(sourceEnv.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64);
        if (parsed) {
          if (typeof parsed === 'object') {
            sourceEnv.FIREBASE_SERVICE_ACCOUNT_JSON = JSON.stringify(parsed);
            if (parsed.private_key) sourceEnv.FIREBASE_PRIVATE_KEY = parsed.private_key;
          } else if (typeof parsed === 'string') {
            sourceEnv.FIREBASE_SERVICE_ACCOUNT_JSON = parsed;
          }
        }
      }

      const envsToSet = [];
      for (const e of yamlService.envVars || []) {
        const key = e.key;
        if (Object.prototype.hasOwnProperty.call(e, 'value')) {
          envsToSet.push({ key, value: String(e.value) });
          continue;
        }
        const val = sourceEnv[key];
        if (val !== undefined) {
          envsToSet.push({ key, value: String(val) });
        } else {
          // if missing, ask to generate a random strong value to avoid leaving it blank
          const random = Math.random().toString(36).slice(2, 18) + Math.random().toString(36).slice(2, 6);
          envsToSet.push({ key, value: random });
          console.log(`Note: missing value for ${key}. A generated placeholder was used; please update in the dashboard.`);
        }
      }

      // pick ownerId via /owners
      const owners = await fetchJson(`${BASE}/owners`, { method: 'GET' });
      let ownerId = null;
      if (Array.isArray(owners) && owners.length && owners[0].id) ownerId = owners[0].id;
      if (!ownerId && Array.isArray(owners) && owners.length && owners[0].owner && owners[0].owner.id) ownerId = owners[0].owner.id;
      if (!ownerId && owners && owners.id) ownerId = owners.id;
      if (!ownerId && owners && owners.owners && Array.isArray(owners.owners) && owners.owners[0].id) ownerId = owners.owners[0].id;
      if (!ownerId && owners && owners[0] && owners[0].id) ownerId = owners[0].id;
      if (!ownerId) ownerId = process.env.RENDER_OWNER_ID;
      if (!ownerId) {
        console.error('Could not determine ownerId. Response from /owners:');
        console.error(JSON.stringify(owners, null, 2));
        console.error('Provide RENDER_OWNER_ID env var or ensure the API key has workspace access.');
        process.exit(6);
      }

      // Ensure newName is unique
      if (await findServiceByName(newName)) {
        newName = `${newName}-${Date.now().toString().slice(-4)}`;
        console.log('New name exists; using:', newName);
      }

      const typeMap = { web: 'web_service', static: 'static_site', private: 'private_service', background: 'background_worker' };
      const normalizedType = typeMap[yamlService.type] || yamlService.type || 'web_service';

      function detectGitRepo() {
        try {
          const cwd = path.join(__dirname, '..', '..');
          const url = cp.execSync('git remote get-url origin', { cwd, encoding: 'utf8' }).toString().trim();
          let provider = 'github';
          let name = null;
          if (url.startsWith('git@')) {
            const m = url.match(/[:/]([^/:]+\/[^/.]+)(?:\.git)?$/);
            if (m) name = m[1];
          } else {
            try {
              const u = new URL(url);
              const parts = u.pathname.replace(/(^\/|\.git$)/g, '').split('/');
              if (parts.length >= 2) name = `${parts[0]}/${parts[1]}`;
              if (u.hostname.includes('gitlab.com')) provider = 'gitlab';
            } catch (e) {
              // ignore
            }
          }
          if (!name) return null;
          return { provider, name, branch: process.env.RENDER_REPO_BRANCH || 'main' };
        } catch (e) {
          return null;
        }
      }

      const payload = {
        type: normalizedType,
        name: newName,
        ownerId,
        serviceDetails: {
          runtime: yamlService.runtime || (yamlService.serviceDetails && yamlService.serviceDetails.runtime) || 'node',
          envSpecificDetails: {
            buildCommand: yamlService.buildCommand || undefined,
            startCommand: yamlService.startCommand || undefined,
            preDeployCommand: yamlService.preDeployCommand || undefined
          },
          healthCheckPath: yamlService.healthCheckPath || undefined,
          numInstances: yamlService.numInstances || undefined,
          plan: yamlService.plan || undefined,
          region: yamlService.region || undefined
        },
        envVars: envsToSet
      };

      // attach repo info if we can detect a git remote
      const repoInfo = detectGitRepo();
      if (repoInfo && repoInfo.name) {
        const repoUrl = repoInfo.provider === 'github' ? `https://github.com/${repoInfo.name}` : repoInfo.name;
        payload.repo = repoUrl;
        payload.branch = repoInfo.branch;
        console.log('Detected git repo for service creation:', repoInfo.name, 'branch:', repoInfo.branch);
      } else {
        console.log('No git remote detected; creating service without repo. You may need to configure deployment in the Render dashboard.');
      }

      console.log('Creating new service (this will trigger a deploy):', newName);
      console.log('Payload keys:', Object.keys(payload));
      if (Array.isArray(payload.envVars)) console.log('Env var keys:', payload.envVars.map(e => e.key).join(', '), 'count:', payload.envVars.length);
      if (payload.repo) console.log('Repo:', payload.repo.name, 'branch:', payload.repo.branch);
      const created = await createService(payload);
      console.log('Create response received');
      const newServiceId = created.service?.id || created.id || created.serviceId || (created.service && created.service.id);
      if (!newServiceId) {
        console.error('Could not determine new service id. Response:');
        console.error(JSON.stringify(created, null, 2));
        process.exit(3);
      }

      // update env vars explicitly to be safe
      if ((envsToSet || []).length > 0) {
        await putEnvVars(newServiceId, envsToSet.map(e => ({ key: e.key, value: String(e.value) })));
        console.log('Env vars set on new service');
      }

      console.log('Migration complete. New service id:', newServiceId);
      if (created.service && created.service.url) console.log('URL:', created.service.url);
      console.log('Review the new service in the Render dashboard for domains, IP allow-lists and other settings.');
      process.exit(0);
    }
    const oldFull = await getService(old.id);
    console.log('Found:', oldFull.id, oldFull.name);

    const envs = await listEnvVars(oldFull.id);
    console.log('Env vars collected:', (envs || []).length);
    const secretFiles = await listSecretFiles(oldFull.id);
    console.log('Secret files collected:', (secretFiles || []).length);
  } catch (err) {
    console.error('ERROR:', err.message || err);
    process.exit(10);
  }
})();
