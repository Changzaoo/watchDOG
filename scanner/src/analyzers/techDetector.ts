import fs from 'fs';
import path from 'path';
import { TechStack } from '@sentinelscope/shared';

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

export function detectTechStack(projectPath: string): TechStack[] {
  const techs: TechStack[] = [];

  let pkg: PackageJson = {};
  const pkgPath = path.join(projectPath, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    } catch {}
  }

  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.peerDependencies,
  };

  const fileExists = (name: string) => fs.existsSync(path.join(projectPath, name));

  // Frontend frameworks
  if (allDeps['next']) techs.push({ name: 'Next.js', version: allDeps['next'], category: 'frontend' });
  if (allDeps['react'] && !allDeps['next']) techs.push({ name: 'React', version: allDeps['react'], category: 'frontend' });
  if (allDeps['vue']) techs.push({ name: 'Vue.js', version: allDeps['vue'], category: 'frontend' });
  if (allDeps['svelte']) techs.push({ name: 'Svelte', version: allDeps['svelte'], category: 'frontend' });
  if (allDeps['@angular/core']) techs.push({ name: 'Angular', version: allDeps['@angular/core'], category: 'frontend' });
  if (allDeps['vite']) techs.push({ name: 'Vite', version: allDeps['vite'], category: 'frontend' });
  if (allDeps['nuxt']) techs.push({ name: 'Nuxt.js', version: allDeps['nuxt'], category: 'frontend' });

  // Backend frameworks
  if (allDeps['express']) techs.push({ name: 'Express', version: allDeps['express'], category: 'backend' });
  if (allDeps['fastify']) techs.push({ name: 'Fastify', version: allDeps['fastify'], category: 'backend' });
  if (allDeps['@nestjs/core']) techs.push({ name: 'NestJS', version: allDeps['@nestjs/core'], category: 'backend' });
  if (allDeps['koa']) techs.push({ name: 'Koa', version: allDeps['koa'], category: 'backend' });
  if (allDeps['hapi']) techs.push({ name: 'Hapi', version: allDeps['hapi'], category: 'backend' });

  // TypeScript
  if (allDeps['typescript']) techs.push({ name: 'TypeScript', version: allDeps['typescript'], category: 'other' });

  // Databases/ORMs
  if (allDeps['@prisma/client']) techs.push({ name: 'Prisma', version: allDeps['@prisma/client'], category: 'database' });
  if (allDeps['mongoose']) techs.push({ name: 'MongoDB/Mongoose', version: allDeps['mongoose'], category: 'database' });
  if (allDeps['pg']) techs.push({ name: 'PostgreSQL', version: allDeps['pg'], category: 'database' });
  if (allDeps['mysql2']) techs.push({ name: 'MySQL', version: allDeps['mysql2'], category: 'database' });
  if (allDeps['better-sqlite3'] || allDeps['sqlite3']) techs.push({ name: 'SQLite', category: 'database' });
  if (allDeps['sequelize']) techs.push({ name: 'Sequelize ORM', version: allDeps['sequelize'], category: 'database' });
  if (allDeps['typeorm']) techs.push({ name: 'TypeORM', version: allDeps['typeorm'], category: 'database' });
  if (allDeps['drizzle-orm']) techs.push({ name: 'Drizzle ORM', version: allDeps['drizzle-orm'], category: 'database' });
  if (allDeps['redis'] || allDeps['ioredis']) techs.push({ name: 'Redis', category: 'database' });

  // Cloud/Auth
  if (allDeps['@supabase/supabase-js']) techs.push({ name: 'Supabase', version: allDeps['@supabase/supabase-js'], category: 'other' });
  if (allDeps['firebase'] || allDeps['firebase-admin']) techs.push({ name: 'Firebase', category: 'other' });
  if (allDeps['@aws-sdk/client-s3'] || allDeps['aws-sdk']) techs.push({ name: 'AWS SDK', category: 'devops' });

  // Web3
  if (allDeps['ethers']) techs.push({ name: 'ethers.js', version: allDeps['ethers'], category: 'web3' });
  if (allDeps['web3']) techs.push({ name: 'web3.js', version: allDeps['web3'], category: 'web3' });
  if (allDeps['@solana/web3.js']) techs.push({ name: 'Solana Web3', category: 'web3' });
  if (allDeps['wagmi']) techs.push({ name: 'wagmi', version: allDeps['wagmi'], category: 'web3' });
  if (allDeps['viem']) techs.push({ name: 'viem', version: allDeps['viem'], category: 'web3' });
  if (fileExists('hardhat.config.js') || fileExists('hardhat.config.ts')) techs.push({ name: 'Hardhat', category: 'web3' });
  if (fileExists('foundry.toml')) techs.push({ name: 'Foundry', category: 'web3' });
  if (fileExists('truffle-config.js')) techs.push({ name: 'Truffle', category: 'web3' });

  // Auth
  if (allDeps['jsonwebtoken']) techs.push({ name: 'JSON Web Tokens', category: 'other' });
  if (allDeps['passport']) techs.push({ name: 'Passport.js', category: 'other' });
  if (allDeps['next-auth'] || allDeps['@auth/core']) techs.push({ name: 'NextAuth.js', category: 'other' });

  // DevOps
  if (fileExists('Dockerfile') || fileExists('docker-compose.yml') || fileExists('docker-compose.yaml')) {
    techs.push({ name: 'Docker', category: 'devops' });
  }
  if (fileExists('.github/workflows')) techs.push({ name: 'GitHub Actions', category: 'devops' });
  if (fileExists('k8s') || fileExists('kubernetes') || fileExists('.helmignore')) {
    techs.push({ name: 'Kubernetes', category: 'devops' });
  }

  // Monorepo
  if (fileExists('turbo.json')) techs.push({ name: 'Turborepo', category: 'devops' });
  if (fileExists('nx.json')) techs.push({ name: 'Nx', category: 'devops' });
  if (fileExists('pnpm-workspace.yaml')) techs.push({ name: 'pnpm Workspaces', category: 'devops' });

  // Python
  if (fileExists('requirements.txt') || fileExists('pyproject.toml')) {
    techs.push({ name: 'Python', category: 'backend' });
  }
  if (fileExists('manage.py')) techs.push({ name: 'Django', category: 'backend' });

  // PHP
  if (fileExists('composer.json')) techs.push({ name: 'PHP/Laravel', category: 'backend' });
  if (fileExists('wp-config.php')) techs.push({ name: 'WordPress', category: 'backend' });

  return techs;
}
