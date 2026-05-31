# watchDOG - Auditoria de Segurança Defensiva

> Ferramenta de análise de segurança 100% local e defensiva para seus próprios projetos.

---

## ⚠️ Aviso de Uso Autorizado

Esta ferramenta foi criada para **análise defensiva** de aplicações. Use **apenas** em:
- Projetos de sua própria autoria
- Projetos onde você tem **autorização explícita por escrito** do proprietário

O uso não autorizado em sistemas de terceiros pode constituir violação de leis de crimes cibernéticos.

**Esta ferramenta NÃO:**
- Executa exploração destrutiva
- Faz brute force ou fuzzing agressivo
- Derruba serviços
- Executa payloads maliciosos
- Envia dados para servidores externos

---

## O que é o watchDOG?

watchDOG é uma ferramenta de auditoria de segurança defensiva que analisa:

- **Projetos locais**: análise estática de código, configs, dependências, secrets, Docker, CI/CD
- **URLs online**: headers de segurança, HTTPS/TLS, CORS, caminhos expostos (análise passiva)
- **Threat model**: ativos, perfis de atacante, superfícies de ataque e lacunas de controle
- **Defense depth**: leitura por camadas defensivas para priorizar correções

### Categorias de análise:
- 🔐 Secrets e credenciais hardcoded
- 📦 Dependências vulneráveis
- 🔑 Autenticação (JWT, bcrypt, sessão)
- 🛡️ Autorização (IDOR, RBAC, RLS)
- 📤 Upload de arquivos
- 🌐 Headers HTTP de segurança
- 🔄 Configuração de CORS
- 🐳 Docker e CI/CD
- 🗄️ Banco de dados
- ⛓️ Web3 (Solidity)
- 📝 Logs com dados sensíveis
- 🇧🇷 Privacidade e LGPD

---

## Instalação

### Pré-requisitos
- Node.js >= 18
- npm >= 9

### Passos

```bash
# 1. Entre no diretório
cd sentinelscope

# 2. Instale todas as dependências
npm install

# 3. Compile o pacote shared
npm run build --workspace=shared

# 4. Compile o scanner
npm run build --workspace=scanner

# 5. Configure o banco de dados
cd backend
npx prisma migrate dev --name init
cd ..
```

---

## Como Rodar

### Modo desenvolvimento (recomendado)

```bash
# Terminal 1 - Backend
npm run dev:backend

# Terminal 2 - Frontend
npm run dev:frontend
```

Ou ambos de uma vez:
```bash
npm run dev
```

Acesse: **http://localhost:5173**

Backend API: http://localhost:3001

---

## Como fazer o primeiro scan

### Scan Local

1. Acesse http://localhost:5173
2. Clique em **"Analisar Projeto Local"**
3. Informe o caminho completo do projeto (ex: `C:\Users\usuario\meu-projeto`)
4. Clique em **"Iniciar Análise"**
5. Aguarde o progresso em tempo real
6. Visualize os achados e exporte o relatório

### Scan por URL

1. Clique em **"Analisar URL Online"**
2. Confirme o checkbox de autorização (obrigatório)
3. Informe a URL (ex: `https://minhaaplicacao.com`)
4. Escolha a profundidade de análise
5. Clique em **"Iniciar Análise"**

---

## Como Interpretar o Score

| Score | Label | Descrição |
|-------|-------|-----------|
| 90-100 | Excelente | Projeto muito bem configurado |
| 75-89 | Bom | Boa configuração. Corrija altos. |
| 50-74 | Atenção | Vários problemas. Priorize críticos. |
| 25-49 | Crítico | Sérios problemas. Corrija imediatamente. |
| 0-24 | Muito Crítico | Não exponha em produção. |

O score é calculado com base na severidade dos achados:
- Crítico: -20 pontos cada
- Alto: -10 pontos cada
- Médio: -5 pontos cada
- Baixo: -2 pontos cada

---

## Como Exportar Relatório

Na página de resultado do scan, clique no botão **"Exportar"** e escolha:
- **JSON** - Dados estruturados para integração
- **Markdown** - Relatório em texto para documentação
- **PDF** - Relatório visual para apresentação
- **Checklist** - Lista prática de correção por severidade

---

## Como Adicionar Novas Regras

1. Abra `scanner/src/rules/<categoria>.rules.ts`

2. Adicione uma nova regra seguindo o padrão:

```typescript
{
  id: 'CUSTOM_001',           // ID único
  title: 'Nome da regra',
  category: 'Minha Categoria',
  severity: 'high',           // critical|high|medium|low|info
  description: 'O que detecta',
  impact: 'Qual o impacto',
  remediation: 'Como corrigir',
  safeExample: '// Código seguro',
  reference: 'OWASP A01:2021',
  patterns: [/padrão_regex/],
  fileExtensions: ['.ts', '.js'],
}
```

3. Recompile o scanner:
```bash
npm run build --workspace=scanner
```

---

## Estrutura do Projeto

```
sentinelscope/
├── shared/          # Tipos TypeScript compartilhados
├── scanner/         # Engine de análise
│   └── src/
│       ├── rules/   # 80+ regras de segurança
│       ├── analyzers/  # Analisadores de projeto, URL, dependências
│       └── utils/   # Utilitários (mascaramento, severity, HTTP)
├── backend/         # API Express + SQLite + SSE
│   ├── src/
│   │   ├── routes/  # Endpoints da API
│   │   └── db/      # Prisma client
│   └── prisma/      # Schema do banco
└── frontend/        # React + Vite + TailwindCSS
    └── src/
        ├── pages/   # Dashboard, Scans, Histórico, etc.
        ├── components/  # UI components
        ├── store/   # Zustand global state
        └── lib/     # API client, utils
```

---

## Scripts Disponíveis

```bash
npm run dev            # Rodar frontend + backend
npm run dev:frontend   # Só o frontend (porta 5173)
npm run dev:backend    # Só o backend (porta 3001)
npm run build          # Build completo
npm run typecheck      # Verificar tipos TypeScript
```

---

## Deploy

### Backend no Render

O arquivo `render.yaml` define um Web Service Node chamado `watchdog-api`.

Configurações esperadas:
- Build command: `npm ci && npm run build --workspace=shared && npm run build --workspace=scanner && npm run prisma:generate --workspace=backend && npm run build --workspace=backend`
- Pre-deploy command: `npm run prisma:migrate:deploy --workspace=backend`
- Start command: `npm run start --workspace=backend`
- Health check: `/health`
- `DATABASE_URL`: `file:/var/data/watchdog.db`
- `ENABLE_LOCAL_SCANS`: `false`
- `CORS_ORIGINS`: URL pública do frontend na Vercel, por exemplo `https://watchdog.vercel.app`

O banco SQLite usa o disco persistente `/var/data` configurado no Blueprint.

### Frontend na Vercel

O arquivo `vercel.json` compila apenas `shared` e `frontend`, publicando `frontend/dist`.

Em producao, o frontend usa os rewrites do Vercel para chamar o backend pelo mesmo dominio:

```text
/api/*  -> https://watchdog-to6v.onrender.com/api/*
/health -> https://watchdog-to6v.onrender.com/health
```

Isso evita chamadas diretas do navegador para `onrender.com`, que podem ser bloqueadas por ad blockers ou privacy shields. Se precisar chamar o backend diretamente em outro deploy, configure `VITE_USE_DIRECT_API=true` junto com `VITE_API_URL`.

Depois de saber a URL final da Vercel, volte no Render e defina `CORS_ORIGINS` com essa URL.

Em produção, o scan local fica desativado porque um backend hospedado não consegue acessar pastas do computador do usuário. Para auditar pastas locais, rode a versão local.

---

## Limitações

- Análise estática: não detecta vulnerabilidades em runtime
- Falsos positivos: algumas regras podem disparar em código legítimo
- URLs: análise passiva apenas, sem autenticação de sessão complexa
- Arquivos >500KB e node_modules são ignorados
- Sem análise de binários

---

## Roadmap

- [ ] Plugin para VS Code
- [ ] Comparação de scans históricos
- [ ] CI/CD integration (GitHub Actions)
- [ ] Análise de infraestrutura (Terraform, Kubernetes)
- [ ] Machine learning para redução de falsos positivos
- [ ] Suporte a projetos Go, Rust, Java

---

*watchDOG - Use com responsabilidade. Apenas em seus próprios projetos.*
