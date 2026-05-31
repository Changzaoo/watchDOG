const fs = require('node:fs');
const path = require('node:path');

const BACKEND_ROOT = path.resolve(__dirname, '..');
const PRISMA_DIR = path.join(BACKEND_ROOT, 'prisma');
const RENDER_DATA_DIR = '/var/data';
const RENDER_DATABASE_URL = 'file:/var/data/watchdog.db';
const LOCAL_DATABASE_URL = 'file:./sentinelscope.db';
const TEMP_DATABASE_URL = 'file:/tmp/watchdog.db';

function unquote(value) {
  const trimmed = String(value || '').trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function hasRenderDataDir() {
  try {
    if (!fs.existsSync(RENDER_DATA_DIR) || !fs.statSync(RENDER_DATA_DIR).isDirectory()) {
      return false;
    }
    fs.accessSync(RENDER_DATA_DIR, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function prepareRenderDataDir() {
  if (process.platform === 'win32') return false;
  try {
    if (!fs.existsSync(RENDER_DATA_DIR)) {
      fs.mkdirSync(RENDER_DATA_DIR, { recursive: true });
    }
    if (!fs.statSync(RENDER_DATA_DIR).isDirectory()) return false;
    fs.accessSync(RENDER_DATA_DIR, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function stripSqliteUrlPath(databaseUrl) {
  let sqlitePath = databaseUrl.slice('file:'.length);
  const paramsAt = sqlitePath.search(/[?#]/);
  if (paramsAt >= 0) sqlitePath = sqlitePath.slice(0, paramsAt);
  return sqlitePath;
}

function isMemorySqliteUrl(databaseUrl, sqlitePath) {
  return sqlitePath === ':memory:' || /(?:\?|&)mode=memory(?:&|$)/.test(databaseUrl);
}

function resolveSqlitePath(sqlitePath) {
  if (!sqlitePath) return null;
  if (path.isAbsolute(sqlitePath) || /^[a-zA-Z]:[\\/]/.test(sqlitePath)) {
    return sqlitePath;
  }
  return path.resolve(PRISMA_DIR, sqlitePath);
}

function ensureSqliteDirectory(databaseUrl) {
  if (!databaseUrl.startsWith('file:')) return;

  const sqlitePath = stripSqliteUrlPath(databaseUrl);
  if (isMemorySqliteUrl(databaseUrl, sqlitePath)) return;

  const filesystemPath = resolveSqlitePath(sqlitePath);
  if (!filesystemPath) return;

  const directory = path.dirname(filesystemPath);
  if (directory && directory !== '.' && !fs.existsSync(directory)) {
    fs.mkdirSync(directory, { recursive: true });
  }
}

function fallbackDatabaseUrl() {
  return process.platform === 'win32' ? LOCAL_DATABASE_URL : TEMP_DATABASE_URL;
}

function configureDatabaseUrl() {
  let databaseUrl = unquote(process.env.DATABASE_URL);

  if (!databaseUrl) {
    databaseUrl = hasRenderDataDir() ? RENDER_DATABASE_URL : LOCAL_DATABASE_URL;
  }

  if (databaseUrl.startsWith('file:/var/data/') && !prepareRenderDataDir()) {
    const fallbackUrl = fallbackDatabaseUrl();
    console.warn(
      `DATABASE_URL points to ${RENDER_DATA_DIR}, but that directory is not available. ` +
      `Using ${fallbackUrl} for this process.`
    );
    databaseUrl = fallbackUrl;
  }

  process.env.DATABASE_URL = databaseUrl;
  ensureSqliteDirectory(databaseUrl);
  return databaseUrl;
}

module.exports = {
  configureDatabaseUrl,
};
