import fs from 'fs';
import path from 'path';
import { FileWalkResult } from '../types';

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'vendor',
  '.turbo', 'coverage', '__pycache__', '.venv', 'venv',
  '.pytest_cache', '.mypy_cache', 'target', 'out', '.cache',
  '.parcel-cache', 'storybook-static', '.docusaurus',
]);

const IGNORED_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.avif',
  '.mp4', '.mp3', '.avi', '.mov', '.wav', '.ogg',
  '.ttf', '.woff', '.woff2', '.eot',
  '.zip', '.tar', '.gz', '.rar', '.7z',
  '.exe', '.dll', '.so', '.dylib',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.pyc', '.class', '.jar',
  '.map', '.lock',
]);

const MAX_FILE_SIZE = 500 * 1024; // 500KB
const MAX_FILES = 5000;

export async function walkFiles(
  dir: string,
  extensions?: string[],
): Promise<FileWalkResult[]> {
  const results: FileWalkResult[] = [];
  const allowedExts = extensions ? new Set(extensions) : null;
  let fileCount = 0;

  async function walk(currentDir: string): Promise<void> {
    if (fileCount >= MAX_FILES) return;

    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (fileCount >= MAX_FILES) break;

      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          await walk(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (IGNORED_EXTENSIONS.has(ext)) continue;
        if (allowedExts && !allowedExts.has(ext)) continue;

        let stat: fs.Stats;
        try {
          stat = await fs.promises.stat(fullPath);
        } catch {
          continue;
        }

        if (stat.size > MAX_FILE_SIZE) continue;

        let content: string;
        try {
          content = await fs.promises.readFile(fullPath, 'utf-8');
        } catch {
          continue;
        }

        results.push({ path: fullPath, content, size: stat.size });
        fileCount++;
      }
    }
  }

  await walk(dir);
  return results;
}

export function buildFileTree(dir: string, depth = 0, maxDepth = 3): object {
  if (depth > maxDepth) return {};

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return {};
  }

  const tree: Record<string, any> = {};
  for (const entry of entries.slice(0, 50)) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    if (entry.name.startsWith('.') && depth > 0) continue;

    if (entry.isDirectory()) {
      tree[entry.name + '/'] = buildFileTree(path.join(dir, entry.name), depth + 1, maxDepth);
    } else {
      tree[entry.name] = null;
    }
  }
  return tree;
}

export function checkFileExists(dir: string, filename: string): boolean {
  return fs.existsSync(path.join(dir, filename));
}

export function readFileIfExists(dir: string, filename: string): string | null {
  const fullPath = path.join(dir, filename);
  try {
    return fs.readFileSync(fullPath, 'utf-8');
  } catch {
    return null;
  }
}
