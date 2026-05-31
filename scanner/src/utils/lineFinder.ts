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
