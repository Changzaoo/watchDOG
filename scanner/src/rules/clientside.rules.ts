import { FileRule } from '../types';

/**
 * Regras de confiança indevida no cliente (client-side enforcement).
 *
 * Origem: cadeia de ataque do vídeo. Dois pontos aparecem claramente:
 *  - As opções "premium" chegavam ao browser já renderizadas, apenas
 *    BORRADAS (blur) via CSS. O apresentador diz: "vai lá e tira o blur no
 *    elemento" — ou seja, o dado sensível já estava no cliente, a proteção
 *    era só visual.
 *  - A piada recorrente "se ele for no localStorage e mudar admin=true" e
 *    "muda lá um admin true" resume o antipadrão de decidir permissão/plano
 *    no front-end.
 *
 * O React (client-side rendering) entrega tudo ao browser; qualquer controle
 * de acesso feito só no front-end é contornável pelo DevTools. A defesa é
 * mover a decisão para o servidor e NÃO enviar dados que o usuário não pode ver.
 */
export const clientSideRules: FileRule[] = [
  {
    id: 'CLIENT_001',
    title: 'Permissão/plano lido de localStorage/sessionStorage',
    category: 'Autorização (client-side)',
    severity: 'high',
    confidence: 'medium',
    description:
      'A aplicação decide privilégio, plano ou papel (isAdmin, isPro, isPremium, role, plan, subscription) lendo de localStorage/sessionStorage/cookie não assinado — armazenamento totalmente editável pelo usuário no navegador.',
    impact:
      'Escalonamento trivial: o usuário abre o DevTools, altera o valor (ex.: isPremium=true, role=admin) e ganha acesso a recursos pagos ou administrativos. É o antipadrão "muda admin=true no localStorage".',
    attackScenarioDefensive:
      'O atacante executa `localStorage.setItem("plan","pro")` no console e a UI (e às vezes chamadas de API que confiam nesse valor) passa a tratá-lo como assinante Pro.',
    remediation:
      'Nunca derive autorização de valores do cliente. A entitlement deve vir do servidor a cada requisição (sessão/JWT verificado) e ser reavaliada no backend em toda ação sensível. O localStorage serve para cache de UI, nunca como fonte de verdade de permissão.',
    safeExample:
      "// Servidor decide; o cliente só reflete:\nconst { plan } = await fetch('/api/me', { credentials: 'include' }).then(r => r.json());\n// E cada endpoint pago revalida no backend:\n// if (req.user.plan !== 'pro') return res.status(402).end();",
    testSuggestion:
      'No navegador, altere o valor de plano/role no localStorage e confirme que os endpoints protegidos continuam retornando 401/402/403 (o backend não confia no cliente).',
    reference: 'OWASP A01:2021 - Broken Access Control; CWE-602 (Client-Side Enforcement of Server-Side Security)',
    patterns: [
      /(?:localStorage|sessionStorage)\.getItem\(\s*["'`](?:isAdmin|admin|isPro|isPremium|premium|role|plan|plano|subscription|assinatura|tier|entitlement|is_?active)["'`]\s*\)/i,
      /(?:localStorage|sessionStorage)\[\s*["'`](?:isAdmin|isPro|isPremium|role|plan|subscription)["'`]\s*\]/i,
    ],
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte'],
  },
  {
    id: 'CLIENT_002',
    title: 'Conteúdo premium ocultado apenas por blur/CSS (paywall visual)',
    category: 'Autorização (client-side)',
    severity: 'high',
    confidence: 'medium',
    description:
      'Conteúdo restrito a planos pagos é enviado ao cliente e apenas borrado/ocultado por CSS (filter: blur, classe "blur"/"locked", overlay). O dado real permanece no DOM/estado.',
    impact:
      'Bypass do paywall em segundos: o usuário remove a classe de blur pelo DevTools (ou lê o estado/props do componente) e vê todo o conteúdo pago sem assinar. Foi literalmente o "tira o blur no elemento" do vídeo.',
    attackScenarioDefensive:
      'A API devolve as sugestões completas; o front-end aplica className="blur-sm" nas opções premium. O atacante deleta a classe no inspetor e lê tudo — nunca precisou pagar nem chamar outra rota.',
    remediation:
      'Não envie ao cliente aquilo que ele não tem direito de ver. O backend deve omitir/redigir o conteúdo pago para usuários sem entitlement e só retorná-lo após validar o plano no servidor. Blur é efeito visual, não controle de acesso.',
    safeExample:
      "// Servidor: só inclui o conteúdo pago se o usuário tem direito\nconst full = req.user.plan === 'pro';\nreturn res.json({\n  preview: dados.preview,\n  premium: full ? dados.premium : undefined, // ausente para free\n});",
    testSuggestion:
      'Como usuário free, inspecione a resposta da API (aba Network) e o DOM: o conteúdo premium NÃO deve estar presente — nem borrado, nem em props/estado.',
    reference: 'OWASP A01:2021 - Broken Access Control; CWE-656 (Reliance on Security Through Obscurity)',
    patterns: [
      // blur e premium/locked/paywall/pro no MESMO atributo class, em qualquer ordem
      /(?:className|class)\s*=\s*["'`{][^"'`}]*(?:\bblur[\w-]*[^"'`}]*(?:premium|locked|paywall|\bpro\b)|(?:premium|locked|paywall|\bpro\b)[^"'`}]*\bblur)/i,
      /(?:premium|locked|paywall|isPro|isPremium)[^>\n]{0,80}filter\s*:\s*["'`]?blur\s*\(/i,
      /style\s*=\s*\{\{[^}]*filter\s*:\s*["'`]?blur/i,
    ],
    fileExtensions: ['.jsx', '.tsx', '.vue', '.svelte', '.html', '.css'],
  },
  {
    id: 'CLIENT_003',
    title: 'Dados premium entregues ao cliente e escondidos condicionalmente',
    category: 'Autorização (client-side)',
    severity: 'medium',
    confidence: 'low',
    description:
      'O componente recebe o conteúdo pago completo e apenas decide exibir/ocultar com base em uma flag (isPremium ? full : preview). O payload já contém o dado sensível independentemente do plano.',
    impact:
      'Mesmo sem blur, o dado pago trafega até o navegador e fica acessível via estado do componente, resposta da API ou React DevTools — o gate visual não impede a extração.',
    attackScenarioDefensive:
      'O atacante inspeciona o estado do componente (ou a resposta JSON) e encontra o campo premium preenchido mesmo estando "escondido" na tela para contas free.',
    remediation:
      'Faça o gate no servidor: contas sem direito recebem o campo ausente/redigido. A renderização condicional no cliente só é segura quando o backend já filtrou o conteúdo.',
    safeExample:
      "// Backend filtra ANTES de enviar; cliente só renderiza o que recebeu.\n// Free: { premium: null }  |  Pro: { premium: {...} }\n{data.premium ? <Premium data={data.premium} /> : <Upsell />}",
    testSuggestion:
      'Compare as respostas da API para uma conta free e uma paga: a conta free não deve receber os campos premium preenchidos.',
    reference: 'OWASP API3:2023 - Broken Object Property Level Authorization; CWE-213',
    patterns: [
      /(?:isPremium|isPro|hasSubscription|isSubscribed|plan\s*===?\s*["'`]pro)[^?\n]{0,40}\?\s*[A-Za-z0-9_.]+\s*:\s*(?:null|undefined|["'`]|<)/i,
    ],
    fileExtensions: ['.jsx', '.tsx', '.vue', '.svelte'],
  },
  {
    id: 'CLIENT_004',
    title: 'Tecnologias/infra reveladas ao cliente (reconhecimento)',
    category: 'Exposição',
    severity: 'low',
    confidence: 'low',
    description:
      'Comentários, variáveis ou strings no bundle revelam a stack e a infraestrutura (Supabase URL, Netlify, projeto, provedor de pagamento). Não é vulnerabilidade por si, mas acelera o reconhecimento do atacante (Wappalyzer + inspeção do bundle).',
    impact:
      'No vídeo, identificar "React + Netlify + Supabase" pelo front-end direcionou todo o ataque (foco em RLS e webhooks). Reduzir pistas desnecessárias aumenta o custo do reconhecimento.',
    attackScenarioDefensive:
      'Com a extensão Wappalyzer e o bundle exposto, o atacante mapeia a stack em segundos e vai direto às fraquezas conhecidas daquele backend (ex.: RLS do Supabase).',
    remediation:
      'A stack sempre é parcialmente detectável — o foco NÃO é escondê-la, e sim garantir que cada camada exposta esteja endurecida (RLS ativo, webhooks assinados, chaves só públicas no cliente). Evite comentários e endpoints internos vazando no bundle de produção.',
    safeExample:
      '// Garanta que o cliente só carregue chaves públicas por design (anon key)\n// e que toda a segurança dependa do backend, não da obscuridade da stack.',
    testSuggestion:
      'Rode o Wappalyzer no seu próprio site e faça grep no bundle por URLs internas/comentários; confirme que nada além do esperado (chaves públicas) está exposto.',
    reference: 'OWASP A05:2021 - Security Misconfiguration; CWE-200',
    patterns: [
      /https?:\/\/[a-z0-9]{15,}\.supabase\.co/i,
      /\/\/\s*(?:TODO|FIXME|HACK|internal|interno|debug)\b[^\n]{0,80}(?:api|endpoint|webhook|secret|token)/i,
    ],
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx'],
  },
];
