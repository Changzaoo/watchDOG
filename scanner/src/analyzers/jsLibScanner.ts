/**
 * Detecção de bibliotecas JavaScript com vulnerabilidades conhecidas (estilo retire.js),
 * porém offline: uma tabela mínima e curada de faixas vulneráveis, sem chamadas de rede.
 *
 * Extrai (biblioteca, versão) do conteúdo de bundles/HTML por fingerprints de regex e
 * compara contra faixas com CVE conhecido. As regex seguem a regra de ouro do projeto:
 * sem quantificador aninhado e sem lookaheads não-limitados.
 */

export interface JsLibHit {
  library: string;
  version: string;
  vuln: 'cve' | 'eol';
  detail: string;
  reference: string;
}

interface LibDef {
  library: string;
  /** Captura a versão no grupo 1. */
  fingerprints: RegExp[];
  /** Retorna motivo se a versão for vulnerável, senão null. */
  isVulnerable: (v: [number, number, number]) => { vuln: 'cve' | 'eol'; detail: string; reference: string } | null;
}

function parseVersion(v: string): [number, number, number] | null {
  const m = v.match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3] || 0)];
}

/** a < b ? */
function lt(a: [number, number, number], b: [number, number, number]): boolean {
  for (let i = 0; i < 3; i++) {
    if (a[i] < b[i]) return true;
    if (a[i] > b[i]) return false;
  }
  return false;
}

const LIBS: LibDef[] = [
  {
    library: 'jQuery',
    fingerprints: [
      /jQuery JavaScript Library v(\d+\.\d+\.\d+)/,
      /jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
      /\bjQuery\.fn\.jquery\s*=\s*["'](\d+\.\d+\.\d+)["']/,
    ],
    isVulnerable: (v) => {
      if (lt(v, [3, 5, 0])) return { vuln: 'cve', detail: 'jQuery < 3.5.0: XSS via htmlPrefilter (CVE-2020-11022 / CVE-2020-11023).', reference: 'CVE-2020-11022; CVE-2020-11023' };
      return null;
    },
  },
  {
    library: 'jQuery UI',
    fingerprints: [
      /jQuery UI - v(\d+\.\d+\.\d+)/,
      /jquery-ui[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    ],
    isVulnerable: (v) => {
      if (lt(v, [1, 13, 2])) return { vuln: 'cve', detail: 'jQuery UI < 1.13.2: XSS no argumento de posição/checkboxradio (CVE-2022-31160).', reference: 'CVE-2022-31160' };
      return null;
    },
  },
  {
    library: 'AngularJS',
    fingerprints: [
      /angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
      /\bangular\.version\s*=\s*\{[^}]*full["']?\s*:\s*["'](\d+\.\d+\.\d+)["']/,
    ],
    isVulnerable: (v) => {
      // AngularJS (1.x) chegou a EOL em jan/2022 — qualquer versão é insegura.
      if (v[0] === 1) return { vuln: 'eol', detail: 'AngularJS 1.x atingiu fim de vida (EOL) em 2022 e não recebe mais correções de segurança. Versões < 1.8.0 também têm XSS conhecido (CVE-2020-7676).', reference: 'AngularJS EOL; CVE-2020-7676' };
      return null;
    },
  },
  {
    library: 'lodash',
    fingerprints: [
      /lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
      /\/\*\*\s*@license\s*Lodash\s*(\d+\.\d+\.\d+)/i,
    ],
    isVulnerable: (v) => {
      if (lt(v, [4, 17, 21])) return { vuln: 'cve', detail: 'lodash < 4.17.21: prototype pollution / ReDoS (CVE-2021-23337 / CVE-2020-28500).', reference: 'CVE-2021-23337; CVE-2020-28500' };
      return null;
    },
  },
  {
    library: 'Bootstrap',
    fingerprints: [
      /Bootstrap v(\d+\.\d+\.\d+)/,
      /bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    ],
    isVulnerable: (v) => {
      if (v[0] === 3 && lt(v, [3, 4, 1])) return { vuln: 'cve', detail: 'Bootstrap 3.x < 3.4.1: XSS em data-target/tooltip (CVE-2019-8331).', reference: 'CVE-2019-8331' };
      if (v[0] === 4 && lt(v, [4, 3, 1])) return { vuln: 'cve', detail: 'Bootstrap 4.x < 4.3.1: XSS em atributos data-* (CVE-2019-8331).', reference: 'CVE-2019-8331' };
      return null;
    },
  },
  {
    library: 'Moment.js',
    fingerprints: [
      /moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
      /\/\/!\s*moment\.js\s*[\r\n]+\/\/!\s*version\s*:\s*(\d+\.\d+\.\d+)/i,
    ],
    isVulnerable: (v) => {
      if (lt(v, [2, 29, 4])) return { vuln: 'cve', detail: 'Moment.js < 2.29.4: ReDoS/path traversal (CVE-2022-31129 / CVE-2022-24785). Considere migrar (projeto em modo legado).', reference: 'CVE-2022-31129; CVE-2022-24785' };
      return null;
    },
  },
  {
    library: 'DOMPurify',
    fingerprints: [
      /DOMPurify[.-](\d+\.\d+\.\d+)/i,
      /purify[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    ],
    isVulnerable: (v) => {
      if (lt(v, [3, 0, 9])) return { vuln: 'cve', detail: 'DOMPurify < 3.0.9: bypass de sanitização conhecido. Atualize para a versão mais recente.', reference: 'DOMPurify security advisories' };
      return null;
    },
  },
];

/**
 * Varre um texto (conteúdo de bundle ou HTML) e retorna as libs vulneráveis detectadas.
 * Deduplica por (library+version).
 */
export function scanJsLibraries(content: string): JsLibHit[] {
  const hits: JsLibHit[] = [];
  const seen = new Set<string>();

  for (const def of LIBS) {
    for (const fp of def.fingerprints) {
      const re = new RegExp(fp.source, fp.flags.includes('g') ? fp.flags : fp.flags + 'g');
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(content)) !== null && guard++ < 50) {
        const parsed = parseVersion(m[1]);
        if (!parsed) continue;
        const verdict = def.isVulnerable(parsed);
        if (!verdict) continue;
        const key = `${def.library}@${m[1]}`;
        if (seen.has(key)) continue;
        seen.add(key);
        hits.push({ library: def.library, version: m[1], vuln: verdict.vuln, detail: verdict.detail, reference: verdict.reference });
      }
    }
  }
  return hits;
}
