import dns from 'dns/promises';
import { Finding } from '@sentinelscope/shared';
import { safeGet } from '../utils/safeHttpClient';

type RawFinding = Omit<Finding, 'id' | 'createdAt'>;

/**
 * Análise 100% passiva da postura de DNS e e-mail do domínio (SPF, DMARC, DKIM,
 * MTA-STS, CAA, DNSSEC) + descoberta de subdomínios via Certificate Transparency.
 *
 * Nenhuma dessas consultas toca o alvo de forma abusiva: são lookups de DNS
 * (resolvidos por resolvers públicos) e, para CT, uma única chamada à crt.sh.
 */

const COMMON_DKIM_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail',
  'dkim', 'smtp', 's1', 's2', 'mandrill', 'mailgun', 'sendgrid', 'zoho',
];

function baseFinding(
  scanId: string,
  url: string,
  ruleId: string,
  title: string,
  severity: Finding['severity'],
  description: string,
  impact: string,
  remediation: string,
  evidence: string | undefined,
  safeExample: string | undefined,
  reference: string,
  confidence: Finding['confidence'] = 'high'
): RawFinding {
  return {
    scanId,
    ruleId,
    title,
    category: 'DNS/E-mail',
    severity,
    url,
    evidenceMasked: evidence,
    description,
    impact,
    remediation,
    safeExample,
    reference,
    confidence,
    status: 'open',
    occurrences: 1,
  };
}

/** Extrai o domínio registrável aproximado (mantém host completo; DNS resolve em qualquer nível). */
function hostFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname.replace(/\.$/, '').toLowerCase();
  } catch {
    return null;
  }
}

/** Reduz um host a domínio de organização heurístico (últimos 2 rótulos, ou 3 para ccTLDs comuns). */
function registrableDomain(host: string): string {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const twoLevelTlds = ['com.br', 'net.br', 'org.br', 'gov.br', 'co.uk', 'com.au', 'co.jp'];
  const lastTwo = parts.slice(-2).join('.');
  if (twoLevelTlds.includes(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

async function resolveTxtSafe(name: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(name);
    return records.map(chunks => chunks.join(''));
  } catch {
    return [];
  }
}

export async function analyzeDns(url: string, scanId: string): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const host = hostFromUrl(url);
  if (!host) return findings;
  const domain = registrableDomain(host);

  const add = (f: RawFinding) => findings.push(f);

  // O domínio recebe/envia e-mail? Sem MX, SPF/DMARC continuam importantes
  // (impedir spoofing "de" @dominio), mas DKIM/MTA-STS não se aplicam.
  const hasMx = await dns.resolveMx(domain).then(r => r.length > 0).catch(() => false);
  const noMailNote = hasMx ? '' : ` O domínio não tem registro MX (não recebe e-mail), então o objetivo aqui é só impedir que terceiros enviem e-mails forjados em seu nome.`;

  // --- SPF (DNS_001 / DNS_002) ---
  const rootTxt = await resolveTxtSafe(domain);
  const spf = rootTxt.find(t => /^v=spf1/i.test(t.trim()));
  if (!spf) {
    add(baseFinding(
      scanId, url, 'DNS_001', 'SPF ausente no domínio', hasMx ? 'high' : 'medium',
      `Não há registro SPF (v=spf1) no TXT de ${domain}. SPF declara quais servidores podem enviar e-mail em nome do domínio.${noMailNote}`,
      'Sem SPF, qualquer servidor pode enviar e-mail forjado "de" @' + domain + ', facilitando phishing e spoofing contra seus próprios clientes e parceiros.',
      hasMx
        ? 'Publique um registro SPF listando apenas os provedores de envio legítimos e terminando em -all (hard fail).'
        : 'Domínio sem e-mail: publique o SPF "v=spf1 -all" (nenhum servidor autorizado) para bloquear spoofing.',
      undefined,
      hasMx ? 'v=spf1 include:_spf.google.com include:sendgrid.net -all' : 'v=spf1 -all',
      'RFC 7208 - Sender Policy Framework'
    ));
  } else {
    const permissive = /[?~+]all\b/i.test(spf) || /\+all/i.test(spf);
    const lookups = (spf.match(/\b(?:include|a|mx|ptr|exists|redirect)[:=]/gi) || []).length;
    if (/[+]?all\b/i.test(spf.replace(/-all/i, '')) && !/-all/i.test(spf)) {
      add(baseFinding(
        scanId, url, 'DNS_002', 'SPF permissivo ou incompleto', 'medium',
        `O SPF de ${domain} não termina em -all (hard fail) ou usa +all/?all, o que enfraquece a proteção.`,
        'Um SPF que não faz hard fail permite que receptores aceitem e-mails de origens não autorizadas, reduzindo a eficácia contra spoofing.',
        'Finalize o SPF com -all e mantenha o total de lookups DNS abaixo de 10 (limite da RFC).',
        spf.slice(0, 200),
        'v=spf1 include:_spf.google.com -all',
        'RFC 7208 - Sender Policy Framework'
      ));
    } else if (permissive || lookups > 10) {
      add(baseFinding(
        scanId, url, 'DNS_002', 'SPF permissivo ou com excesso de lookups', 'medium',
        `O SPF de ${domain} usa mecanismo permissivo (+all/?all) ou excede 10 lookups DNS (${lookups} detectados).`,
        'SPF permissivo aceita origens arbitrárias; exceder 10 lookups faz o SPF ser tratado como permerror e ignorado por muitos receptores.',
        'Use -all e consolide includes para ficar abaixo de 10 lookups.',
        spf.slice(0, 200),
        'v=spf1 include:_spf.google.com -all',
        'RFC 7208 - Sender Policy Framework'
      ));
    }
  }

  // --- DMARC (DNS_003 / DNS_004) ---
  const dmarcTxt = await resolveTxtSafe('_dmarc.' + domain);
  const dmarc = dmarcTxt.find(t => /^v=DMARC1/i.test(t.trim()));
  if (!dmarc) {
    add(baseFinding(
      scanId, url, 'DNS_003', 'DMARC ausente no domínio', hasMx ? 'high' : 'medium',
      `Não há registro DMARC em _dmarc.${domain}. DMARC instrui os receptores sobre o que fazer com e-mails que falham SPF/DKIM.${noMailNote}`,
      'Sem DMARC, mesmo com SPF/DKIM os receptores não têm política clara, e o domínio permanece explorável para phishing dirigido (BEC).',
      hasMx
        ? 'Publique DMARC começando em p=none com rua= para coletar relatórios, e evolua para p=quarantine e depois p=reject.'
        : 'Domínio sem e-mail: publique diretamente "v=DMARC1; p=reject" para que receptores rejeitem qualquer e-mail forjado em seu nome.',
      undefined,
      hasMx ? 'v=DMARC1; p=reject; rua=mailto:dmarc@' + domain + '; adkim=s; aspf=s' : 'v=DMARC1; p=reject',
      'RFC 7489 - DMARC'
    ));
  } else {
    const policy = (dmarc.match(/\bp\s*=\s*(none|quarantine|reject)/i) || [])[1]?.toLowerCase();
    if (policy === 'none') {
      add(baseFinding(
        scanId, url, 'DNS_004', 'DMARC em p=none (apenas monitoramento)', 'medium',
        `O DMARC de ${domain} está em p=none: monitora, mas não bloqueia nem quarentena e-mails que falham a autenticação.`,
        'Com p=none, e-mails forjados ainda são entregues normalmente na caixa da vítima; a proteção real só existe a partir de p=quarantine/p=reject.',
        'Após validar os relatórios rua, evolua a política para p=quarantine e então p=reject.',
        dmarc.slice(0, 200),
        'v=DMARC1; p=reject; rua=mailto:dmarc@' + domain + '; pct=100',
        'RFC 7489 - DMARC'
      ));
    }
  }

  // --- DKIM (DNS_005) — heurístico: nenhum seletor comum encontrado ---
  // Só faz sentido para domínios que enviam e-mail (com MX).
  let anyDkim = !hasMx;
  for (const sel of hasMx ? COMMON_DKIM_SELECTORS : []) {
    const rec = await resolveTxtSafe(`${sel}._domainkey.${domain}`);
    if (rec.some(t => /v=DKIM1|k=rsa|p=/i.test(t))) { anyDkim = true; break; }
  }
  if (!anyDkim) {
    add(baseFinding(
      scanId, url, 'DNS_005', 'DKIM não detectável nos seletores comuns', 'low',
      `Nenhum registro DKIM foi encontrado nos seletores mais comuns de ${domain}. DKIM assina criptograficamente os e-mails enviados.`,
      'Sem DKIM, a autenticação depende só de SPF (frágil a encaminhamentos) e o DMARC fica mais fácil de falhar legitimamente. Pode também ser que o seletor seja customizado (falso-positivo possível).',
      'Ative DKIM no seu provedor de e-mail e publique a chave pública no seletor correspondente.',
      undefined,
      'selector1._domainkey.' + domain + ' TXT "v=DKIM1; k=rsa; p=MIGf..."',
      'RFC 6376 - DomainKeys Identified Mail',
      'low'
    ));
  }

  // --- MTA-STS (DNS_006) ---
  const mtaStsTxt = hasMx ? await resolveTxtSafe('_mta-sts.' + domain) : [];
  const hasMtaSts = !hasMx || mtaStsTxt.some(t => /v=STSv1/i.test(t));
  if (!hasMtaSts) {
    add(baseFinding(
      scanId, url, 'DNS_006', 'MTA-STS ausente', 'low',
      `Não há política MTA-STS em _mta-sts.${domain}. MTA-STS força TLS entre servidores de e-mail.`,
      'Sem MTA-STS, a entrega SMTP pode sofrer downgrade para texto puro por um atacante na rede (STRIPTLS), expondo o conteúdo dos e-mails.',
      'Publique o TXT _mta-sts e o arquivo de política em https://mta-sts.' + domain + '/.well-known/mta-sts.txt com mode: enforce.',
      undefined,
      '_mta-sts.' + domain + ' TXT "v=STSv1; id=20260101000000"',
      'RFC 8461 - SMTP MTA Strict Transport Security',
      'medium'
    ));
  }

  // --- CAA (DNS_007) ---
  try {
    const caa = await dns.resolveCaa(domain);
    if (!caa || caa.length === 0) {
      add(baseFinding(
        scanId, url, 'DNS_007', 'Registro CAA ausente', 'low',
        `${domain} não possui registros CAA. CAA restringe quais Autoridades Certificadoras podem emitir certificados para o domínio.`,
        'Sem CAA, qualquer CA pública pode emitir um certificado para o domínio, ampliando o risco de emissão indevida (mis-issuance) e MITM com cert válido.',
        'Publique registros CAA autorizando apenas as CAs que você realmente usa.',
        undefined,
        domain + ' CAA 0 issue "letsencrypt.org"',
        'RFC 8659 - DNS Certification Authority Authorization',
        'medium'
      ));
    }
  } catch {
    // resolveCaa lança quando não há registro em alguns resolvers — trata como ausência informativa.
    add(baseFinding(
      scanId, url, 'DNS_007', 'Registro CAA ausente', 'low',
      `${domain} não possui registros CAA detectáveis. CAA restringe quais CAs podem emitir certificados para o domínio.`,
      'Sem CAA, qualquer CA pública pode emitir um certificado para o domínio, ampliando o risco de emissão indevida.',
      'Publique registros CAA autorizando apenas as CAs que você usa.',
      undefined,
      domain + ' CAA 0 issue "letsencrypt.org"',
      'RFC 8659 - DNS Certification Authority Authorization',
      'medium'
    ));
  }

  // --- DNSSEC (DNS_008) — presença de DS/RRSIG no domínio ---
  let dnssecSigned = false;
  try {
    // Um domínio assinado tem registros DNSKEY; a ausência costuma lançar/retornar vazio.
    const dnskey = await dns.resolve(domain, 'DNSKEY' as any).catch(() => []);
    dnssecSigned = Array.isArray(dnskey) && dnskey.length > 0;
  } catch {
    dnssecSigned = false;
  }
  if (!dnssecSigned) {
    add(baseFinding(
      scanId, url, 'DNS_008', 'DNSSEC não habilitado', 'info',
      `${domain} não aparenta estar assinado com DNSSEC (nenhum DNSKEY encontrado). DNSSEC garante a integridade das respostas DNS.`,
      'Sem DNSSEC, respostas DNS podem ser forjadas (cache poisoning), redirecionando usuários para servidores maliciosos mesmo com a URL correta.',
      'Habilite DNSSEC no seu provedor de DNS e publique o registro DS na zona pai (registrar).',
      undefined,
      undefined,
      'RFC 4033 - DNS Security Introduction and Requirements',
      'medium'
    ));
  }

  // --- CNAME órfão -> subdomain takeover (DNS_009) ---
  try {
    const cnames = await dns.resolveCname(host).catch(() => [] as string[]);
    for (const target of cnames) {
      const targetHost = target.replace(/\.$/, '');
      const resolved = await dns.lookup(targetHost).then(() => true).catch((e: any) => {
        // ENOTFOUND/NXDOMAIN no alvo do CNAME = registro pendurado (dangling).
        return e?.code === 'ENOTFOUND' || e?.code === 'ENODATA' ? 'dangling' : true;
      });
      if (resolved === 'dangling') {
        add(baseFinding(
          scanId, url, 'DNS_009', 'CNAME pendurado (dangling) — risco de subdomain takeover', 'critical',
          `${host} tem um CNAME apontando para ${targetHost}, mas esse destino não resolve (NXDOMAIN). É um registro DNS pendurado.`,
          'Se o recurso órfão puder ser reivindicado no provedor, um atacante passa a servir conteúdo no SEU subdomínio: rouba cookies de sessão, aplica phishing com URL legítima e contorna CSP/CORS baseados em domínio.',
          `Remova imediatamente o registro CNAME órfão de ${host} OU reivindique novamente o recurso ${targetHost} no provedor.`,
          `${host} CNAME ${targetHost} (NXDOMAIN)`,
          '# Apague o CNAME orfao no seu DNS',
          'OWASP WSTG - Test for Subdomain Takeover; CWE-350',
          'high'
        ));
      }
    }
  } catch {
    // sem CNAME — normal.
  }

  // --- Subdomínios via Certificate Transparency (DNS_010) — 1 chamada à crt.sh ---
  try {
    const ctUrl = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const ctResp = await safeGet(ctUrl, { Accept: 'application/json' }, [], { maxBodyBytes: 512 * 1024 });
    if (ctResp.statusCode === 200 && ctResp.body) {
      const names = new Set<string>();
      // O corpo pode vir truncado; casamos por regex em vez de JSON.parse estrito.
      for (const m of ctResp.body.matchAll(/"(?:common_name|name_value)":"([^"]+)"/g)) {
        for (const n of m[1].split(/\\n|\n/)) {
          const clean = n.trim().toLowerCase().replace(/^\*\./, '');
          if (clean.endsWith(domain) && clean !== domain) names.add(clean);
        }
      }
      const interesting = [...names].filter(n =>
        /(^|\.)(dev|staging|stage|test|qa|homolog|admin|api|internal|intranet|vpn|git|jenkins|grafana|kibana|db|sql|backup|old)\./.test(n)
      );
      if (interesting.length > 0) {
        add(baseFinding(
          scanId, url, 'DNS_010', 'Subdomínios sensíveis expostos em Certificate Transparency', 'info',
          `Os logs públicos de Certificate Transparency revelam subdomínios de ${domain} com nomes sensíveis: ${interesting.slice(0, 10).join(', ')}${interesting.length > 10 ? '…' : ''}.`,
          'CT logs são públicos e permanentes. Subdomínios como admin., staging. ou vpn. entregam ao atacante um mapa da superfície interna sem nenhuma sondagem ativa, orientando ataques direcionados.',
          'Garanta que ambientes internos/dev não sejam acessíveis pela internet (allowlist de IP, VPN, autenticação). Considere certificados wildcard para não expor nomes individuais em CT.',
          interesting.slice(0, 15).join('\n'),
          undefined,
          'OWASP WSTG - Information Gathering (Certificate Transparency)',
          'high'
        ));
      }
    }
  } catch {
    // crt.sh indisponível/limitado — silencioso (é um extra, não crítico).
  }

  return findings;
}
