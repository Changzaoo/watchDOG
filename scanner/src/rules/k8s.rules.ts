import { FileRule } from '../types';

const KUBE_WORKLOAD = /^kind:\s*(Pod|Deployment|DaemonSet|StatefulSet|ReplicaSet|Job|CronJob)/im;

export const k8sRules: FileRule[] = [
  {
    id: 'K8S_001',
    title: 'Container privilegiado',
    category: 'Kubernetes',
    severity: 'critical',
    confidence: 'high',
    description:
      'Um container define securityContext.privileged: true, concedendo acesso praticamente irrestrito ao host.',
    impact:
      'Um container privilegiado pode acessar todos os devices do host, montar o filesystem do nó e escapar para o host, comprometendo todo o nó e potencialmente o cluster.',
    attackScenarioDefensive:
      'Um atacante que obtém execução de código dentro de um pod privilegiado monta /dev do host, acessa o filesystem do nó e instala um backdoor, escapando do container.',
    remediation:
      'Remova privileged: true. Conceda apenas as capabilities estritamente necessárias e prefira políticas de admissão (Pod Security Standards / OPA Gatekeeper) que proíbam containers privilegiados.',
    safeExample:
      'securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  capabilities:\n    drop: ["ALL"]',
    testSuggestion:
      'Em um manifesto com kind: Deployment, defina privileged: true e confirme a detecção; troque por false e confirme que não dispara.',
    reference: 'Kubernetes Pod Security Standards (Restricted); CIS Kubernetes Benchmark',
    patterns: [/privileged:\s*true/i],
    fileExtensions: ['.yaml', '.yml'],
    requireContent: KUBE_WORKLOAD,
  },
  {
    id: 'K8S_002',
    title: 'hostNetwork/hostPID/hostIPC habilitado',
    category: 'Kubernetes',
    severity: 'high',
    confidence: 'high',
    description:
      'O pod habilita hostNetwork, hostPID ou hostIPC: true, compartilhando o namespace de rede, processos ou IPC com o nó host.',
    impact:
      'Compartilhar namespaces do host quebra o isolamento: hostNetwork expõe interfaces e serviços do nó; hostPID permite ver/sinalizar processos do host; hostIPC permite acessar memória compartilhada de outros processos.',
    attackScenarioDefensive:
      'Um pod com hostPID: true enumera processos do host, localiza um processo com segredos em memória/argumentos e os extrai, escapando do isolamento do container.',
    remediation:
      'Remova hostNetwork/hostPID/hostIPC (mantenha-os false). Use Services e CNI para conectividade; evite compartilhar namespaces do host exceto em casos de infraestrutura bem auditados.',
    safeExample:
      'spec:\n  hostNetwork: false\n  hostPID: false\n  hostIPC: false',
    testSuggestion:
      'Em um manifesto com kind: Pod, defina hostNetwork: true e confirme a detecção; troque por false e confirme que não dispara.',
    reference: 'Kubernetes Pod Security Standards (Baseline); CIS Kubernetes Benchmark',
    patterns: [/^\s*host(?:Network|PID|IPC):\s*true/im],
    fileExtensions: ['.yaml', '.yml'],
    requireContent: KUBE_WORKLOAD,
  },
  {
    id: 'K8S_003',
    title: 'allowPrivilegeEscalation / sem runAsNonRoot',
    category: 'Kubernetes',
    severity: 'high',
    confidence: 'medium',
    description:
      'O container define allowPrivilegeEscalation: true, permitindo que um processo obtenha mais privilégios que o processo pai (ex.: via binários setuid).',
    impact:
      'A escalada de privilégios permite que um processo comprometido ganhe privilégios adicionais dentro do container, facilitando a exploração de vulnerabilidades do kernel e a fuga do container.',
    attackScenarioDefensive:
      'Um atacante com execução em um container que permite escalada usa um binário setuid para obter root dentro do container e então tenta explorar o kernel do nó para escapar.',
    remediation:
      'Defina allowPrivilegeEscalation: false e runAsNonRoot: true, drope todas as capabilities e use um usuário não-root. Reforce com Pod Security Standards (Restricted).',
    safeExample:
      'securityContext:\n  runAsNonRoot: true\n  allowPrivilegeEscalation: false\n  capabilities:\n    drop: ["ALL"]',
    testSuggestion:
      'Em um manifesto com kind: Deployment, defina allowPrivilegeEscalation: true e confirme a detecção; troque por false e confirme que não dispara.',
    reference: 'Kubernetes Pod Security Standards (Restricted)',
    patterns: [/allowPrivilegeEscalation:\s*true/i],
    fileExtensions: ['.yaml', '.yml'],
    requireContent: KUBE_WORKLOAD,
  },
  {
    id: 'K8S_004',
    title: 'Capabilities perigosas (SYS_ADMIN/NET_ADMIN/ALL)',
    category: 'Kubernetes',
    severity: 'high',
    confidence: 'high',
    description:
      'O container adiciona capabilities Linux perigosas (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE ou ALL) ao securityContext.',
    impact:
      'Capabilities como SYS_ADMIN concedem privilégios quase equivalentes a root; SYS_MODULE permite carregar módulos de kernel; SYS_PTRACE permite inspecionar outros processos. Facilitam a fuga do container e o comprometimento do nó.',
    attackScenarioDefensive:
      'Um container com CAP_SYS_ADMIN monta dispositivos e manipula o filesystem do host, conseguindo escapar para o nó a partir de uma RCE no aplicativo.',
    remediation:
      'Drope todas as capabilities (drop: ["ALL"]) e adicione apenas as estritamente necessárias. Nunca adicione SYS_ADMIN, SYS_MODULE, SYS_PTRACE, NET_ADMIN ou ALL sem justificativa auditada.',
    safeExample:
      'securityContext:\n  capabilities:\n    drop: ["ALL"]\n    add: ["NET_BIND_SERVICE"]   # apenas o mínimo necessário',
    testSuggestion:
      'Em um manifesto com kind: Pod, adicione capabilities.add: ["SYS_ADMIN"] e confirme a detecção; remova-a e confirme que não dispara.',
    reference: 'Kubernetes Pod Security Standards (Restricted); Linux capabilities(7)',
    patterns: [
      /add:\s*\[?[^\]\n]*\b(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|ALL)\b/i,
      /-\s*(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|ALL)\s*$/im,
    ],
    fileExtensions: ['.yaml', '.yml'],
    requireContent: KUBE_WORKLOAD,
  },
  {
    id: 'K8S_005',
    title: 'Secret com dados em plaintext (stringData)',
    category: 'Kubernetes',
    severity: 'high',
    confidence: 'medium',
    description:
      'Um objeto kind: Secret usa o campo stringData com valores sensíveis (password, secret, token, api_key, private_key) em texto claro no manifesto.',
    impact:
      'Secrets do Kubernetes não são criptografados por padrão e stringData em texto claro acaba versionado no Git, exposto em pipelines e visível a qualquer um com acesso ao repositório ou ao manifesto.',
    attackScenarioDefensive:
      'Um manifesto de Secret com stringData.password é commitado no repositório. Um atacante com acesso de leitura ao repositório extrai a senha e a usa para autenticar no serviço alvo.',
    remediation:
      'Nunca versione segredos em texto claro. Use um gerenciador externo (Sealed Secrets, External Secrets Operator, Vault) ou criptografia em repouso no etcd, e injete os valores em runtime.',
    safeExample:
      '# Referencie um segredo gerenciado externamente; não inclua o valor no manifesto.\napiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\nspec:\n  secretStoreRef:\n    name: vault-backend',
    testSuggestion:
      'Crie um manifesto kind: Secret com stringData contendo "password:" e confirme a detecção; remova os dados em texto claro e confirme que não dispara.',
    reference: 'Kubernetes Docs: Secrets (good practices); OWASP A02:2021 - Cryptographic Failures',
    patterns: [
      /^\s*kind:\s*Secret\b/im,
      /stringData:\s*[\s\S]{0,400}?(?:password|secret|token|api[_-]?key|private[_-]?key)\s*:/i,
    ],
    fileExtensions: ['.yaml', '.yml'],
    requireContent: KUBE_WORKLOAD,
  },
  {
    id: 'K8S_006',
    title: 'hostPath montando diretório sensível',
    category: 'Kubernetes',
    severity: 'critical',
    confidence: 'high',
    description:
      'Um volume hostPath monta um diretório sensível do host (/, /etc, /root, /var/run/docker.sock ou /var/lib/kubelet) dentro do container.',
    impact:
      'Montar caminhos sensíveis do host permite ler/escrever arquivos do nó. Montar /var/run/docker.sock concede controle total do daemon Docker, equivalente a root no host e fuga trivial do container.',
    attackScenarioDefensive:
      'Um pod monta /var/run/docker.sock. Um atacante com execução no pod cria um novo container privilegiado via o socket do Docker, montando o filesystem do host e assumindo o nó.',
    remediation:
      'Evite hostPath para diretórios sensíveis. Nunca monte o socket do Docker em pods de aplicação. Use volumes apropriados (emptyDir, PVC) e políticas de admissão que bloqueiem hostPath sensíveis.',
    safeExample:
      'volumes:\n  - name: cache\n    emptyDir: {}   # evite hostPath; use emptyDir ou um PersistentVolumeClaim',
    testSuggestion:
      'Em um manifesto com kind: DaemonSet, declare um hostPath com path: "/var/run/docker.sock" e confirme a detecção; troque por emptyDir e confirme que não dispara.',
    reference: 'Kubernetes Pod Security Standards (Baseline); CIS Kubernetes Benchmark',
    patterns: [
      /hostPath:\s*[\s\S]{0,120}?path:\s*["']?(?:\/(?:|etc|root|var\/run\/docker\.sock|var\/lib\/kubelet)\b)/i,
    ],
    fileExtensions: ['.yaml', '.yml'],
    requireContent: KUBE_WORKLOAD,
  },
];
