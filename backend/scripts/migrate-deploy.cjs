const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { configureDatabaseUrl } = require('./database-url.cjs');

configureDatabaseUrl();

const prismaCli = require.resolve('prisma/build/index.js');
const result = spawnSync(process.execPath, [prismaCli, 'migrate', 'deploy'], {
  cwd: path.resolve(__dirname, '..'),
  env: process.env,
  stdio: 'inherit',
});

process.exit(result.status ?? 1);
