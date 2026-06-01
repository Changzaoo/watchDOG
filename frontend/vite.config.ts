import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';

function readBackendPort() {
  const backendEnvPath = path.resolve(__dirname, '../backend/.env');
  try {
    const envFile = fs.readFileSync(backendEnvPath, 'utf8');
    const match = envFile.match(/^\s*PORT\s*=\s*["']?(\d+)["']?\s*$/m);
    return match?.[1] || '3001';
  } catch {
    return '3001';
  }
}

function readFrontendPort() {
  const rawPort = process.env.VITE_DEV_PORT || process.env.FRONTEND_PORT;
  const port = Number(rawPort);
  if (Number.isInteger(port) && port > 0 && port <= 65535) return port;
  return 5173;
}

const backendTarget = process.env.VITE_BACKEND_URL ||
  process.env.BACKEND_URL ||
  `http://localhost:${readBackendPort()}`;
const devHost = process.env.VITE_DEV_HOST;
const strictPort = process.env.VITE_STRICT_PORT === 'true';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@sentinelscope/shared': path.resolve(__dirname, '../shared/src'),
    },
  },
  server: {
    port: readFrontendPort(),
    ...(devHost ? { host: devHost } : {}),
    strictPort,
    proxy: {
      '/api': {
        target: backendTarget,
        changeOrigin: true,
      },
      '/health': {
        target: backendTarget,
        changeOrigin: true,
      },
    },
  },
});
