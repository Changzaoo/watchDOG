export function findLineNumber(content: string, pattern: RegExp): number | undefined {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      return i + 1;
    }
  }
  return undefined;
}

export function findAllMatches(
  content: string,
  pattern: RegExp,
  fileName: string
): Array<{ line: number; text: string; match: string }> {
  const lines = content.split('\n');
  const results: Array<{ line: number; text: string; match: string }> = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = globalPattern.exec(line)) !== null) {
      results.push({
        line: i + 1,
        text: line.trim(),
        match: m[0],
      });
    }
  }

  return results;
}

// Limite de matches reportados por regra/arquivo (evita explosão em minificados).
const MAX_MATCHES_PER_RULE = 50;
// Linhas patológicas (muito longas) são ignoradas para evitar ReDoS/backtracking caro.
const MAX_LINE_LENGTH = 5000;

// Cache de RegExp já compilados com a flag global, indexado pela RegExp original.
// Pré-compila cada pattern UMA vez (reutilizado entre arquivos).
const globalRegexCache = new WeakMap<RegExp, RegExp>();

/**
 * Compila (uma única vez) uma versão com flag global do pattern e a mantém em cache.
 * Garante que 'g' esteja presente sem duplicar flags.
 */
export function compileGlobal(pattern: RegExp): RegExp {
  const cached = globalRegexCache.get(pattern);
  if (cached) return cached;
  const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
  const compiled = new RegExp(pattern.source, flags);
  globalRegexCache.set(pattern, compiled);
  return compiled;
}

/**
 * Casa um pattern contra o CONTEÚDO COMPLETO do arquivo (suporta regex multi-linha
 * como [\s\S]{0,N}). Calcula o número da linha a partir de match.index, contando
 * os '\n' até o índice via um índice de offsets de início de linha (busca binária).
 *
 * - Reutiliza a versão global pré-compilada do pattern (lastIndex resetado).
 * - Limita o nº de matches por regra (MAX_MATCHES_PER_RULE).
 * - Ignora arquivos cuja maior linha exceda MAX_LINE_LENGTH (anti-ReDoS).
 */
export function findAllMatchesMultiline(
  content: string,
  pattern: RegExp,
  fileName?: string
): Array<{ line: number; text: string; match: string }> {
  const results: Array<{ line: number; text: string; match: string }> = [];

  // Offsets de início de cada linha + guarda contra linhas patológicas.
  const lineStarts: number[] = [0];
  let maxLineLen = 0;
  let prev = 0;
  for (let i = 0; i < content.length; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) {
      const lineLen = i - prev;
      if (lineLen > maxLineLen) maxLineLen = lineLen;
      lineStarts.push(i + 1);
      prev = i + 1;
    }
  }
  const lastLineLen = content.length - prev;
  if (lastLineLen > maxLineLen) maxLineLen = lastLineLen;

  // Arquivo com alguma linha gigantesca (minificado/blob): evita backtracking caro.
  if (maxLineLen > MAX_LINE_LENGTH) return results;

  const re = compileGlobal(pattern);
  re.lastIndex = 0;

  // Converte um offset absoluto em número de linha (1-based) via busca binária.
  const lineForIndex = (index: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };

  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const line = lineForIndex(m.index);
    const start = lineStarts[line - 1];
    let end = content.indexOf('\n', m.index);
    if (end === -1) end = content.length;
    results.push({
      line,
      text: content.slice(start, end).trim().slice(0, 200),
      match: m[0],
    });

    if (results.length >= MAX_MATCHES_PER_RULE) break;
    // Evita loop infinito em matches de largura zero.
    if (m.index === re.lastIndex) re.lastIndex++;
  }

  return results;
}

export function extractContext(content: string, lineNumber: number, context = 2): string {
  const lines = content.split('\n');
  const start = Math.max(0, lineNumber - 1 - context);
  const end = Math.min(lines.length, lineNumber + context);
  return lines.slice(start, end).join('\n');
}

export function truncateLine(line: string, maxLen = 200): string {
  if (line.length <= maxLen) return line;
  return line.slice(0, maxLen) + '...';
}
