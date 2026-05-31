const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { configureDatabaseUrl } = require('./database-url.cjs');

configureDatabaseUrl();

try {
  const prismaCli = require.resolve('prisma/build/index.js');
  const result = spawnSync(process.execPath, [prismaCli, 'migrate', 'deploy'], {
    cwd: path.resolve(__dirname, '..'),
    env: process.env,
    stdio: 'inherit',
  });

  if (result.status !== 0) {
    console.error('Prisma migrate deploy failed; backend startup aborted.');
    process.exit(result.status || 1);
  }
} catch (error) {
  console.error('Prisma migrate deploy could not run; backend startup aborted.', error);
  process.exit(1);
}

require('../dist/index.js');
