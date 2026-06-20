# watchDOG — Relatório de Threat-Intel 2026 (Consolidado)

> Documento de pesquisa defensiva consolidado a partir de 7 briefs de threat-intel especializados.
> Objetivo: dar base técnica e referências para tornar o watchDOG o scanner defensivo mais completo do mercado em 2026.
> Para a especificação de implementação acionável (regras, regex, refactors), ver `docs/watchdog-upgrade-spec.md`.

Data de consolidação: 2026-06-19
Edição OWASP de referência: **OWASP Top 10:2021** (web) e **OWASP API Security Top 10:2023** (ainda oficial em 2026), **OWASP Top 10 for LLM Applications:2025**.

---

## Sumário executivo dos domínios

| Domínio | Vetor 2026 dominante | Severidade típica | Arquivo de regra alvo |
|---|---|---|---|
| Injeção e execução | Prototype pollution ("novo SQLi"), SSTI→RCE, command/NoSQL/XXE, deserialização | critical/high | `injection.rules.ts` |
| DoS / DDoS / resiliência | HTTP/2 Rapid Reset & variantes, ReDoS, GraphQL amplification, zip bombs, slowloris | high/medium | `dos.rules.ts` + `dosHeaders.rules.ts` |
| Supply chain | Worms auto-replicantes (Shai-Hulud 2.0), TrapDoor cross-ecossistema, AI poisoning, typosquatting | critical/high | `supplychain.rules.ts` |
| Segredos modernos | Novos formatos de token (OpenAI `sk-proj-`, GitHub `ghs_APPID_JWT`), cloud/LLM/SaaS keys | critical | `secrets.rules.ts` (estender) |
| API / Auth / Sessão | JWT algorithm confusion (cluster Q1/2026), BOLA/IDOR (~40%), mass assignment, OAuth/PKCE/state | critical/high | `jwt.rules.ts` + `apiauth.rules.ts` |
| Cloud / IaC / CI/CD / containers | `tj-actions` supply chain, script injection em `run:`, IngressNightmare, S3 público, SG 0.0.0.0/0 | critical/high | `cicd.rules.ts`, `iac.rules.ts`, `k8s.rules.ts`, `docker.rules.ts` |
| IA/LLM / Web3 / Privacidade | Prompt injection→RCE, insecure output handling, reentrancy, PII em logs/LLM | critical/high | `llm.rules.ts`, `web3.rules.ts`, `privacy.rules.ts` |
| Headers / Cookies / WAF-CDN | Cookies sem flags, CSP fraco, HSTS de baixa qualidade, COOP/COEP/CORP, ausência de WAF | medium/low | `headers.rules.ts` + `dosHeaders.rules.ts` (HttpRule) |

---

## 1. Injeção e execução de código

### Panorama
- **Prototype pollution virou o "novo SQLi" do ecossistema npm em 2026.** Cadeia de CVEs em libs de altíssimo uso: axios (`CVE-2026-42033`, `CVE-2026-25639` via `mergeConfig`), flatted `parse()` (`CVE-2026-33228`), convict (`CVE-2026-33863`), deepstream.io (`CVE-2026-49252`, CVSS 9.9) e n8n (`CVE-2026-54306`/`-54312`). Padrão detectável comum: merge/extend recursivo e `JSON.parse` copiado para um objeto sem bloquear `__proto__`/`constructor`/`prototype`.
- **SSTI com RCE direto** continua entre as classes mais críticas: Calibre Templite (`CVE-2026-25731`, GHSA-xrh9-w7qx-3gcc) executa Python arbitrário; em Node, `pug.compile`/`handlebars`/`ejs` com template montado a partir de input. Em Python, Flask `render_template_string`/Jinja2 `Template`.
- **Command injection** segue crítico em produtos enterprise (UID Enterprise Agent `CVE-2026-47367`, CVSS 9.9; Tianxin CVSS 9.8). Sinais: `child_process.exec/execSync` com template/concatenação; `os.system`/`subprocess(shell=True)`; `Runtime.exec`/`ProcessBuilder` com strings dinâmicas.
- **ReDoS** ganhou tração (Picomatch `CVE-2026-33671` via extglob). Sinal estático: quantificador aninhado (`(.*)+`, `([a-z]+)*`, `(a|aa)+`) e `new RegExp()` a partir de input.
- **Deserialização insegura** permanece RCE cross-language: `node-serialize.unserialize` (IIFE), Python `pickle.loads`/`yaml.load` sem `SafeLoader`, PHP `unserialize`, Java `ObjectInputStream`/`readObject`.
- **Open redirect e SSRF via header em SSR** voltaram ao radar (Angular SSR `CVE-2026-27739`).
- **SSRF** clássico segue habilitando acesso a metadata cloud (169.254.169.254) e port-scan interno via `fetch`/`axios`/`requests` com URL controlada pelo usuário (OWASP A10:2021).

### Referências
- Indusface — 46 Vulnerability Statistics 2026: https://www.indusface.com/blog/key-vulnerability-statistics/
- UID Enterprise Agent CVE-2026-47367: https://www.thehackerwire.com/uid-enterprise-agent-critical-command-injection-cve-2026-47367/
- CVE-2026-25731 SSTI Calibre Templite: https://github.com/dxlerYT/CVE-2026-25731
- Imperva — SSTI: https://www.imperva.com/learn/application-security/server-side-template-injection-ssti/
- Imperva — Command Injection: https://www.imperva.com/learn/application-security/command-injection/
- Snyk — Prototype Pollution axios CVE-2026-42033: https://security.snyk.io/vuln/SNYK-JS-AXIOS-16299904
- GitLab Advisories — n8n CVE-2026-54306: https://advisories.gitlab.com/npm/n8n/CVE-2026-54306/
- GitHub Advisory — flatted CVE-2026-33228: https://github.com/advisories/GHSA-rf6f-7fwh-wjgh
- Invicti — node-serialize Insecure Deserialization: https://www.invicti.com/web-application-vulnerabilities/node-serialize-insecure-deserialization
- Semgrep — Insecure Deserialization (Python): https://semgrep.dev/docs/learn/vulnerabilities/insecure-deserialization/python
- OSV — CVE-2026-33671 (Picomatch ReDoS): https://osv.dev/vulnerability/CVE-2026-33671
- oneuptime — How to Fix Insecure Deserialization (2026): https://oneuptime.com/blog/post/2026-01-24-insecure-deserialization/view

---

## 2. DoS / DDoS / resiliência

### Panorama
- **HTTP/2 Rapid Reset (CVE-2023-44487)** continua a base do recorde de DDoS L7. Variantes 2024-2025: **HTTP/2 CONTINUATION Flood** (CVE-2024-27316 e correlatas Apache/Node/Envoy/Go), **MadeYouReset** (2025) e o recorde de ~22.2 Tbps / ~10.6 Gpps mitigado pela Cloudflare (set/2025). Vetor comum: criar/cancelar streams (ou induzir RST_STREAM) mais rápido do que o servidor libera recursos.
- **ReDoS em dependências populares** é o DoS de aplicação mais subestimado — regex roda no event loop e trava todo o processo single-thread.
- **GraphQL como amplificador**: query batching, aliases duplicados e aninhamento profundo explodem resolvers; APIs sem depth limit / cost analysis / disable batching são alvo direto.
- **Decompression/zip bombs e JSON gigante**: `bodyParser.json()` sem `limit`, descompressão automática de `Content-Encoding` sem teto, upload de zip sem limite de razão.
- **Slow attacks**: Slowloris e slow-read continuam efetivos; ausência de `keepAliveTimeout`/`requestTimeout` (ou zerados) é a falha mais comum.
- **Edge como controle primário**: ausência de WAF/CDN (Cloudflare, Fastly, Akamai, CloudFront, Imperva/Incapsula, Sucuri, Vercel, Netlify, Azure Front Door) e de headers de rate-limit (`ratelimit-*` IETF, `retry-after`, `x-ratelimit-*`) virou sinal de maturidade.

### Referências
- CVE-2023-44487 (HTTP/2 Rapid Reset)
- CVE-2024-27316 (HTTP/2 CONTINUATION Flood)
- CWE-1333 (ReDoS), CWE-400 (Uncontrolled Resource Consumption), CWE-409 (Decompression Bomb)
- OWASP API4:2023 Unrestricted Resource Consumption; OWASP "Denial of Service Cheat Sheet"
- IETF draft "RateLimit header fields for HTTP"; NIST SP 800-189
- OWASP GraphQL Cheat Sheet

---

## 3. Supply chain de software

### Panorama
- **Worms auto-replicantes viraram o normal.** **Shai-Hulud** (set/2025, ~500 pacotes incl. `@ctrl/tinycolor`, `ngx-bootstrap`, `ng2-file-upload`) e **Shai-Hulud 2.0** (24/nov/2025): postinstall rouba tokens npm/GitHub via TruffleHog e **republica-se sozinho**. IOCs: `bundle.js`, `setup_bun.js`, `bun_environment.js`; workflow `.github/workflows/shai-hulud-workflow.yml`; exfiltração para `webhook.site` (ex. ID `bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`) e criação de repos/gists públicos.
- **Campanha TrapDoor (mai/2026)**: cross-ecossistema (34 pacotes / 384 versões em npm + PyPI + Crates.io), mirando devs Sui/Move/Solana. Execução por ecossistema: `postinstall` (npm), import-time (Python), `build.rs` (Rust); XOR-cifra keystores com chave `cargo-build-helper-2026`, exfiltra para GitHub Gists.
- **AI assistant poisoning (novo vetor 2026)**: TrapDoor planta instruções ocultas com caracteres Unicode de largura zero (U+200B/U+200C/U+200D/U+FEFF) em `CLAUDE.md`/`.cursorrules`, disfarçadas de "security scan". **Slopsquatting**: pacotes com nomes que LLMs alucinam.
- **Typosquatting industrializado.** Microsoft (28/mai/2026): 14 pacotes em 4h, typosquats de OpenSearch/ElasticSearch roubando creds AWS + tokens HashiCorp Vault. Ataque **Mastra** (17/jun/2026): `easy-day-js` (typosquat de `dayjs`) injetado em 140+ pacotes via takeover de org.
- **Dependency confusion** continua eficaz: pacotes internos sem escopo privado sobrepostos por versões públicas de maior número.

### Referências
- Microsoft Security Blog (typosquat npm, 2026-05-28): https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/
- StepSecurity — Mastra: https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js
- The Hacker News — TrapDoor: https://thehackernews.com/2026/05/trapdoor-supply-chain-attack-spreads.html
- Socket — TrapDoor: https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
- Datadog — Shai-Hulud 2.0: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
- CISA Alert Shai-Hulud (2025-09-23): https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- Unit42 — npm supply chain: https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
- CWE-829, CWE-506, CWE-494, CWE-427

---

## 4. Segredos modernos (formatos 2026)

### Panorama
Os formatos de segredo mudaram em 2026:
- **OpenAI** migrou para `sk-proj-`/`sk-svcacct-`/`sk-admin-` com literal `T3BlbkFJ` embutido (base64 de "OpenAI") — exigir esse literal elimina quase todos os FPs.
- **GitHub App installation tokens** (`ghs_`) passam a `ghs_APPID_JWT` (~520 chars); **PAT fine-grained** `github_pat_`.
- **Anthropic** `sk-ant-api03-`; **HuggingFace** `hf_`.
- **Cloud**: AWS `AKIA`/`ASIA`, GCP `AIza`/service-account JSON, Azure connection strings.
- **SaaS/comms**: Slack `xox*`, Twilio `SK`, SendGrid `SG.`, Mailgun `key-`, Telegram, Discord webhook.
- **Hosting/infra**: Stripe `rk_live_`/`pk_live_`, DigitalOcean `dop_v1_`, Cloudflare/Vercel/Netlify.
- **Supabase service_role JWT** (bypassa RLS), connection strings com senha (`postgres://`, `mongodb+srv://`, AMQP, Redis), chaves PEM (todas variantes incluindo PKCS8 e PGP).

Recomendação anti-FP transversal: **entropia de Shannon** (limiar ~3.5-4.0 bits/char) + allowlist de placeholders (`EXAMPLE`, `xxxx`, `your-key-here`, `process.env`, `<...>`, `${...}`, `changeme`, `test`, `dummy`).

### Referências
- GitHub Changelog — novo formato de installation tokens: https://github.blog/changelog/2026-04-24-notice-about-upcoming-new-format-for-github-app-installation-tokens/
- OWASP A02:2021; CWE-798 (Hardcoded Credentials); CWE-321 (Hardcoded Cryptographic Key); CWE-522

---

## 5. API / Autenticação / Sessão / Headers

### Panorama
- **Cluster de CVEs de JWT algorithm confusion no Q1/2026** (CVE-2026-22817, CVE-2026-23552, CVE-2026-27804) em adaptadores OAuth e libs que confiam no campo `alg` do token. Os três vetores clássicos seguem 100% funcionais: `alg:none`, confusão RS256→HS256 (assinar com a chave pública RSA como segredo HMAC) e **kid injection** (path traversal/SQLi via header `kid`).
- **BOLA / IDOR continua campeã** (~40% dos ataques a APIs). Padrão perigoso: `findById(req.params.id)` sem `WHERE userId = req.user.id`.
- **Mass assignment**: `req.body` direto para `prisma.user.update({ data: req.body })` / `Object.assign(user, req.body)`, escalando `role`/`isAdmin`/`verified`.
- **OAuth/OIDC**: ausência de **PKCE** (S256) em clientes públicos e ausência de validação de **`state`**; `redirect_uri` com wildcard/substring habilita roubo de code.
- **Hardening de resposta**: navegadores 2026 cobram **COOP/COEP/CORP**, `SameSite` explícito, **CSP sem `unsafe-inline`/`unsafe-eval`** com nonce/hash. Reflexão dinâmica de `Origin` + `Allow-Credentials: true` segue como misconfig crítico. **HSTS** de baixa qualidade (max-age curto / sem includeSubDomains).
- **GraphQL introspection habilitado em produção** expõe o schema inteiro (recon).

### Referências
- JWT Algorithm Confusion (DEV) CVE-2026-22817/27804/23552: https://dev.to/iamdevbox/jwt-algorithm-confusion-attacks-cve-2026-22817-cve-2026-27804-and-cve-2026-23552-fix-guide-4ac4
- WorkOS — JWT algorithm confusion: https://workos.com/blog/jwt-algorithm-confusion-attacks
- PortSwigger — JWT attacks: https://portswigger.net/web-security/jwt
- Red Sentry — JWT Vulnerabilities 2026: https://redsentry.com/resources/blog/jwt-vulnerabilities-list-2026-security-risks-mitigation-guide
- OWASP API Security Top 10 (Axway): https://blog.axway.com/learning-center/digital-security/risk-management/owasps-api-security
- CWE-347, CWE-639, CWE-915, CWE-601, CWE-352, CWE-1004, CWE-614, CWE-942; OAuth 2.0 Security BCP (RFC 9700); RFC 7636 (PKCE)

---

## 6. Cloud / IaC / CI/CD / containers

### Panorama
- **Supply chain de CI/CD é o alvo nº1.** O incidente `tj-actions/changed-files` (mar/2025, ~23k repos) reescreveu 350+ tags Git para um commit malicioso que dumpava secrets do runner; repetido com `reviewdog`. Lição: actions por tag/branch são **mutáveis** — só pin por SHA de 40 chars protege.
- **Script injection em `run:`** continua a campeã de RCE em pipelines: interpolar `${{ github.event.pull_request.title }}`/`...body`/`...head_ref` direto em `run:`. Combinado com `pull_request_target` + `actions/checkout` do `head.ref`, executa código não confiável com permissões de escrita do repo base.
- **IngressNightmare (CVE-2025-1974, CVSS 9.8 + CVE-2025-24513/24514/1097/1098)**: `ingress-nginx` com admission webhook exposto = RCE não autenticado no cluster.
- **Misconfig de Pod**: `privileged`, `hostNetwork/hostPID/hostIPC`, `allowPrivilegeEscalation`, ausência de `runAsNonRoot`/`readOnlyRootFilesystem`, capabilities `SYS_ADMIN/NET_ADMIN`, `hostPath` para `/` ou `/var/run/docker.sock`.
- **Terraform/cloud**: buckets S3 públicos, security groups `0.0.0.0/0` em 22/3389/3306/5432, `encrypted=false` em EBS/RDS, secrets hardcoded em `.tf`.
- **Self-hosted runners em repos públicos**: PR de fork executa código no runner persistente (persistência + pivot).

### Referências
- Cycode — tj-actions/changed-files guide: https://cycode.com/blog/github-action-tj-actions-changed-files-supply-chain-attack-the-complete-guide/
- Unit42 — GitHub Actions supply chain: https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/
- GitHub Changelog — Actions SHA pinning: https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/
- Datadog — IngressNightmare: https://securitylabs.datadoghq.com/articles/ingress-nightmare-vulnerabilities-overview-and-remediation/
- CrowdStrike — IngressNightmare: https://www.crowdstrike.com/en-us/blog/kubernetes-ingressnightmare-vulnerabilities-key-details/
- Aikido — IaC security scanning: https://www.aikido.dev/blog/iac-security-scanning-terraform-kubernetes-misconfigurations
- OWASP CICD-SEC-4/-5/-7; CIS Kubernetes/Docker/AWS Benchmarks; CWE-829, CWE-94, CWE-250, CWE-269, CWE-732, CWE-284, CWE-311, CWE-312

---

## 7. IA/LLM, Web3 e Privacidade

### 7.1 IA/LLM (OWASP LLM Top 10:2025)
- **Prompt injection (LLM01)** pelo 3º ano; vetor que mais cresce é **indirect/tool-poisoning via MCP** (descrições de tools maliciosas, cross-tool poisoning, RAG/web fetch).
- **Prompt injection → RCE virou realidade**: `CVE-2025-53773` (GitHub Copilot, CVSS 9.6), Microsoft Semantic Kernel (prompt dispara `calc.exe`), `CVE-2026-2256` (MS-Agent Shell — blacklist regex contornável). Lição: **saída de LLM nunca deve chegar a `exec`/`eval`/shell**.
- **Insecure Output Handling (LLM05)**: saída do modelo em `dangerouslySetInnerHTML`/`eval`/`child_process`/SQL.
- **Excessive Agency (LLM06)**: agentes com tools de shell/FS/HTTP sem human-in-the-loop nem allowlist (blacklist regex é o anti-padrão do ano).
- **API key de IA no client-side**: `dangerouslyAllowBrowser: true`, chaves `sk-`/`sk-ant-` em bundle frontend (`VITE_`/`NEXT_PUBLIC_`).
- **Unbounded consumption (LLM10)**: chamadas sem `max_tokens`, loops de agente sem teto → DoS econômico.
- **Model supply chain (LLM03)**: `pickle.load`/`torch.load` sem `weights_only=True` → RCE no load.

### 7.2 Web3 / Solidity
- **Reentrancy** continua liderando perdas; foco 2026 em **read-only** e cross-function reentrancy (violação de checks-effects-interactions).
- **block.timestamp/blockhash como aleatoriedade** (SWC-120) — usar Chainlink VRF.
- **Low-level calls sem checagem de retorno** (`call`/`send`/`delegatecall`); `delegatecall` para endereço controlável = takeover (SWC-112).
- **`selfdestruct`** deprecado (EIP-6780 pós-Dencun) — red flag em código novo (SWC-106).
- **`unchecked { }`** reintroduz overflow/underflow silencioso (SWC-101).

### 7.3 Privacidade / LGPD / GDPR
- **PII em logs estruturados/observabilidade** (Sentry, Datadog, console) — agravada por logs ingeridos por LLMs de análise.
- **CPF/cartão/email sem mascaramento** em respostas de API (violação de minimização, LGPD Art. 6 / GDPR Art. 5).
- **PII enviada a provedores de IA** sem base legal/DPA (risco de uso em treino).
- **Retenção indefinida** sem TTL/rota de exclusão.

### Referências
- OWASP Top 10 LLM 2025 (Oligo): https://www.oligo.security/academy/owasp-top-10-llm-updated-2025-examples-and-mitigation-strategies
- AI Agent Security 2026 (MCP/Function Calling): https://www.programming-helper.com/tech/ai-agent-security-2026-attack-surfaces-mcp-function-calling
- Microsoft Security — prompts become shells: https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/
- PointGuard AI — CVE-2026-2256 MS-Agent: https://www.pointguardai.com/ai-security-incidents/shell-game-ms-agent-flaw-lets-hackers-seize-ai-agents-cve-2026-2256
- OpenAI API key safety: https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety
- Anthropic SDK dangerouslyAllowBrowser: https://github.com/anthropics/anthropic-sdk-typescript/issues/248
- Hacken — Top 10 Smart Contract Vulns 2025: https://hacken.io/discover/smart-contract-vulnerabilities/
- Cycode — Top AI Security Vulns 2026: https://cycode.com/blog/ai-security-vulnerabilities/
- SWC-101/104/106/107/112/120; CWE-79/94/330/502/918; LGPD Art. 5/6/7/33/46; GDPR Art. 5/44; PCI-DSS 3.4

---

## 8. Engenharia do "fix prompt" (agent-ready)

Decisões de design apoiadas em práticas atuais de prompt engineering para agentes de código:
- **Prompt como "job description"**: objetivo, fronteiras (o que NÃO tocar), definition of done, ferramentas/comandos.
- **Prefixo de segurança explícito** reduz vulnerabilidades geradas em até **56%**; prompting iterativo repara **41,9%–68,7%** das vulnerabilidades existentes (FORGE 2025).
- **Separar contexto estático (persona/projeto) de dinâmico (achado específico)** melhora consistência.
- **Tags XML como "contrato"** geram saída 20–40% mais consistente em modelos Claude.
- **Concisão e fronteiras claras** vencem instruções longas.
- **Defensive prompting / scaffolding**: envolver dados não confiáveis (evidências, paths) em blocos guardados, tratá-los como dados, não instruções.

### Referências
- orq.ai — prompt engineering: https://orq.ai/blog/what-is-the-best-way-to-think-of-prompt-engineering
- sarifulislam.com — prompt engineering 2026: https://sarifulislam.com/blog/prompt-engineering-2026/
- FORGE 2025 — Benchmarking Prompt Engineering for Secure Code: https://conf.researchr.org/details/forge-2025/forge-2025-papers/11/
- Claude Docs — use XML tags: https://console.anthropic.com/docs/en/build-with-claude/prompt-engineering/use-xml-tags
- bridgemind.ai, pecollective.com, lakera.ai (prompt engineering best practices)

---

## Apêndice — mapa CWE/OWASP por domínio

| Domínio | CWE principais | OWASP |
|---|---|---|
| Injeção | 78, 89, 94, 95, 502, 611, 643, 1321, 1336 | A03:2021, A08:2021 |
| Path traversal / SSRF | 22, 918 | A01:2021, A10:2021 |
| DoS | 400, 409, 770, 834, 674, 1333 | API4:2023 |
| Supply chain | 506, 829, 494, 427, 349, 522 | A06:2021 |
| Segredos | 798, 321, 312, 532 | A02:2021 |
| Auth/JWT/Sessão | 347, 345, 613, 639, 285, 915, 601, 352, 1004, 614, 942, 1275 | API1/API2/API3/API5:2023, A01/A05:2021 |
| IaC/CI/CD/Container | 250, 269, 284, 311, 312, 552, 732, 829, 94 | CICD-SEC-4/5/7 |
| IA/LLM | 79, 94, 502, 798, 1427 | LLM01/03/05/06/10:2025 |
| Web3 | 330, 502 (+SWC-101/104/106/107/112/120) | — |
| Privacidade | 312, 532 | A09:2021, LGPD/GDPR |
