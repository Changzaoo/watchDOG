const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = fs.existsSync('/var/data')
    ? 'file:/var/data/watchdog.db'
    : 'file:./sentinelscope.db';
}

try {
  const prismaCli = require.resolve('prisma/build/index.js');
  const result = spawnSync(process.execPath, [prismaCli, 'migrate', 'deploy'], {
    cwd: path.resolve(__dirname, '..'),
    env: process.env,
    stdio: 'inherit',
  });

  if (result.status !== 0) {
    console.error('Prisma migrate deploy failed; starting backend anyway.');
  }
} catch (error) {
  console.error('Prisma migrate deploy could not run; starting backend anyway.', error);
}

require('../dist/index.js');
