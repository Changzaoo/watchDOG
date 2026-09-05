import { FileRule } from '../types';

/**
 * Falhas criptográficas (OWASP A04:2025).
 *
 * Cobre os erros que aparecem com mais frequência em aplicações web:
 * hashing de senha inadequado, aleatoriedade previsível para tokens,
 * modos/IV inseguros em cifragem simétrica e comparação de segredos
 * sensível a timing.
 */
export const cryptoRules: FileRule[] = [
  {
    id: 'CRYPTO_001',
    title: 'Hash inseguro (MD5/SHA1) para senha ou token',
    category: 'Criptografia',
    severity: 'critical',
    confidence: 'medium',
    description:
      'Uso de MD5 ou SHA-1 para derivar/armazenar senhas ou gerar tokens de segurança. São algoritmos rápidos e quebrados por colisão, inadequados para segredos.',
    impact:
      'Senhas vazadas podem ser revertidas em minutos com rainbow tables e GPUs. Um dump do banco compromete todas as contas, e a reutilização de senha propaga o dano para outros serviços.',
    attackScenarioDefensive:
      'Após um vazamento do banco, o atacante roda hashcat sobre os hashes MD5 e recupera a senha em texto claro de milhares de usuários em poucas horas.',
    remediation:
      'Use um algoritmo lento e com salt desenhado para senhas: argon2id (preferido), bcrypt (custo >= 12) ou scrypt. Para integridade use SHA-256+; nunca MD5/SHA-1 em contexto de segurança.',
    safeExample:
      "import argon2 from 'argon2';\nconst hash = await argon2.hash(senha, { type: argon2.argon2id });\nconst ok = await argon2.verify(hash, senhaInformada);\n// Alternativa: bcrypt.hash(senha, 12)",
    testSuggestion:
      'Inspecione a coluna de senha no banco: hashes devem começar com $argon2id$ ou $2b$ e ter tamanho variável com salt embutido.',
    reference: 'OWASP A04:2025 - Cryptographic Failures; CWE-916; CWE-327',
    patterns: [
      /createHash\s*\(\s*["'`](?:md5|sha1)["'`]\s*\)[\s\S]{0,120}?(?:password|senha|passwd|pwd|token|secret)/i,
      /(?:password|senha|passwd|pwd|token|secret)[\s\S]{0,80}?createHash\s*\(\s*["'`](?:md5|sha1)["'`]/i,
      /hashlib\.(?:md5|sha1)\s*\([^)]*(?:password|senha|passwd|token|secret)/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.py'],
  },
  {
    id: 'CRYPTO_002',
    title: 'Math.random() usado para token/segredo',
    category: 'Criptografia',
    severity: 'high',
    confidence: 'medium',
    description:
      'Geração de token, senha, OTP, chave de sessão ou identificador de segurança usando Math.random(), que é um PRNG não criptográfico e previsível.',
    impact:
      'A sequência do Math.random() pode ser prevista a partir de saídas observadas, permitindo que um atacante adivinhe tokens de reset de senha, OTPs ou identificadores de sessão de outros usuários.',
    attackScenarioDefensive:
      'O atacante solicita vários resets de senha para contas que controla, observa os tokens gerados, reconstrói o estado do PRNG e prevê o próximo token — usando-o para sequestrar a conta da vítima.',
    remediation:
      'Use um gerador criptograficamente seguro: crypto.randomBytes()/crypto.randomUUID() no Node, crypto.getRandomValues() no browser, secrets no Python.',
    safeExample:
      "import crypto from 'node:crypto';\nconst token = crypto.randomBytes(32).toString('hex');\nconst id = crypto.randomUUID();\n// Python: secrets.token_urlsafe(32)",
    testSuggestion:
      'Gere vários tokens seguidos e confirme alta entropia (>= 128 bits) e ausência de correlação; nenhum deve ser derivável dos anteriores.',
    reference: 'OWASP A04:2025 - Cryptographic Failures; CWE-338',
    patterns: [
      /(?:token|secret|senha|password|otp|code|codigo|nonce|salt|apiKey|api_key|sessionId|session_id|resetCode)\s*[:=][^;\n]{0,80}Math\.random\s*\(/i,
      /Math\.random\s*\(\)[^;\n]{0,60}\.toString\s*\(\s*(?:16|36)\s*\)[^;\n]{0,40}(?:substr|slice|substring)/i,
    ],
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'CRYPTO_003',
    title: 'Cifra insegura: modo ECB ou IV estático',
    category: 'Criptografia',
    severity: 'high',
    confidence: 'medium',
    description:
      'Cifragem simétrica usando modo ECB (que preserva padrões do texto claro) ou com IV/nonce fixo em código, em vez de aleatório por mensagem.',
    impact:
      'ECB revela estrutura do dado cifrado (blocos iguais geram cifra igual). IV estático em CBC/CTR/GCM permite ataques de reuso de keystream e recuperação parcial do texto claro.',
    attackScenarioDefensive:
      'Com IV fixo em AES-CTR, dois textos cifrados com a mesma chave permitem que o atacante faça XOR entre eles e elimine o keystream, recuperando o conteúdo sensível.',
    remediation:
      'Use AES-256-GCM (autenticado) com IV aleatório de 12 bytes gerado por mensagem e armazenado junto ao ciphertext. Nunca use ECB nem reutilize IV com a mesma chave.',
    safeExample:
      "const iv = crypto.randomBytes(12);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\nconst enc = Buffer.concat([cipher.update(txt, 'utf8'), cipher.final()]);\nconst tag = cipher.getAuthTag();\n// guarde iv + tag junto do ciphertext",
    testSuggestion:
      'Cifre a mesma mensagem duas vezes: os ciphertexts devem ser diferentes (IV aleatório). Confirme que o modo é GCM/autenticado.',
    reference: 'OWASP A04:2025 - Cryptographic Failures; CWE-327; CWE-329',
    patterns: [
      /createCipheriv?\s*\(\s*["'`][^"'`]*-ecb["'`]/i,
      /createCipheriv\s*\(\s*[^,]+,\s*[^,]+,\s*(?:["'`][A-Za-z0-9+/=]{8,}["'`]|Buffer\.from\s*\(\s*["'`][^"'`]+["'`])/,
      /\bMODE_ECB\b|AES\.new\s*\([^)]*MODE_ECB/,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.py'],
  },
  {
    id: 'CRYPTO_004',
    title: 'Comparação de segredo sensível a timing',
    category: 'Criptografia',
    severity: 'medium',
    confidence: 'low',
    description:
      'Comparação de token, hash, assinatura ou chave de API usando === / == / localeCompare, que retorna assim que encontra o primeiro byte diferente.',
    impact:
      'A diferença de tempo entre comparações vaza informação byte a byte, permitindo que um atacante com muitas tentativas reconstrua o segredo (timing attack).',
    attackScenarioDefensive:
      'O atacante mede o tempo de resposta de milhares de requisições variando o primeiro byte do token; o byte correto responde marginalmente mais devagar, e ele descobre o segredo caractere por caractere.',
    remediation:
      'Compare segredos com crypto.timingSafeEqual() sobre buffers de mesmo tamanho (compare primeiro os comprimentos de forma segura, ex.: via hash).',
    safeExample:
      "const a = Buffer.from(tokenRecebido);\nconst b = Buffer.from(tokenEsperado);\nconst ok = a.length === b.length && crypto.timingSafeEqual(a, b);\nif (!ok) return res.sendStatus(401);",
    testSuggestion:
      'Revise os pontos de verificação de token/assinatura e confirme o uso de timingSafeEqual em vez de comparação direta.',
    reference: 'CWE-208 - Observable Timing Discrepancy; OWASP A04:2025',
    patterns: [
      /(?:apiKey|api_key|apiToken|authToken|accessToken|secretKey|secret|hmac|digest)\s*(?:===?|!==?)\s*(?:req|request|headers|body|query|params)\./i,
      /(?:req|request)\.(?:headers|body|query|params)\[?["'`]?[a-z0-9_-]*(?:token|key|secret|signature)[a-z0-9_-]*["'`]?\]?\s*(?:===?|!==?)\s*(?:process\.env|[A-Z_]{4,})/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'CRYPTO_005',
    title: 'Senha armazenada sem hash (texto claro ou encoding reversível)',
    category: 'Criptografia',
    severity: 'critical',
    confidence: 'low',
    description:
      'Persistência de senha diretamente do corpo da requisição, ou usando base64/encriptação reversível, em vez de hash unidirecional com salt.',
    impact:
      'Um vazamento do banco expõe as senhas em texto claro imediatamente, comprometendo as contas da aplicação e de todos os serviços onde o usuário reutiliza a senha.',
    attackScenarioDefensive:
      'Um SQL injection ou backup mal protegido entrega a tabela de usuários; como as senhas estão em claro (ou em base64 trivialmente reversível), o atacante usa as credenciais direto em outros serviços (credential stuffing).',
    remediation:
      'Nunca armazene senha reversível. Aplique argon2id/bcrypt antes de persistir e valide sempre por comparação de hash. Base64 é codificação, não criptografia.',
    safeExample:
      "const senhaHash = await argon2.hash(req.body.password, { type: argon2.argon2id });\nawait prisma.user.create({ data: { email, senhaHash } });",
    testSuggestion:
      'Cadastre um usuário e inspecione a linha no banco: a senha nunca deve ser legível nem decodificável por base64.',
    reference: 'OWASP A04:2025 - Cryptographic Failures; CWE-256; CWE-257',
    patterns: [
      /(?:password|senha|passwd)\s*:\s*req\.body\.(?:password|senha|passwd)\b/i,
      /(?:password|senha)\s*[:=]\s*Buffer\.from\s*\([^)]*\)\.toString\s*\(\s*["'`]base64["'`]\s*\)/i,
      /(?:password|senha)\s*[:=]\s*btoa\s*\(/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'],
  },
  {
    id: 'CRYPTO_006',
    title: 'bcrypt com custo baixo (rounds < 12)',
    category: 'Criptografia',
    severity: 'medium',
    confidence: 'high',
    description:
      'Uso de bcrypt com fator de custo (salt rounds) menor que 12, tornando o hash rápido demais para o hardware atual.',
    impact:
      'Custo baixo permite bilhões de tentativas por segundo em GPU, reduzindo drasticamente o tempo necessário para quebrar senhas fracas e médias em caso de vazamento.',
    attackScenarioDefensive:
      'Com rounds=8, o atacante testa um dicionário de 10 milhões de senhas contra cada hash vazado em poucos minutos, recuperando grande parte das contas.',
    remediation:
      'Use custo >= 12 (idealmente calibrado para ~250ms no seu hardware) ou migre para argon2id, que resiste melhor a ataques com GPU/ASIC.',
    safeExample: "const hash = await bcrypt.hash(senha, 12);",
    testSuggestion:
      'Meça o tempo de bcrypt.hash no ambiente de produção: deve ficar em torno de 200-300ms por hash.',
    reference: 'OWASP Password Storage Cheat Sheet; CWE-916',
    patterns: [
      /bcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*(?:[1-9]|10|11)\s*[,)]/,
      /(?:genSalt|genSaltSync)\s*\(\s*(?:[1-9]|10|11)\s*\)/,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'CRYPTO_007',
    title: 'Verificação de certificado TLS desabilitada',
    category: 'Criptografia',
    severity: 'high',
    confidence: 'high',
    description:
      'Código desabilita a validação de certificado TLS (rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0, verify=False).',
    impact:
      'Sem validar o certificado, a conexão aceita qualquer par — inclusive um proxy malicioso —, permitindo interceptação e alteração do tráfego (man-in-the-middle) mesmo usando HTTPS.',
    attackScenarioDefensive:
      'Um atacante na mesma rede apresenta um certificado auto-assinado; como a verificação está desligada, a aplicação envia tokens e dados sensíveis diretamente para ele.',
    remediation:
      'Nunca desabilite a verificação em produção. Se precisar confiar numa CA interna, adicione o certificado raiz via ca: [fs.readFileSync("ca.pem")] ou NODE_EXTRA_CA_CERTS.',
    safeExample:
      "const agent = new https.Agent({\n  rejectUnauthorized: true,\n  ca: [fs.readFileSync('ca-interna.pem')],\n});",
    testSuggestion:
      'Aponte a aplicação para um endpoint com certificado inválido e confirme que a conexão é recusada.',
    reference: 'OWASP A04:2025; CWE-295 - Improper Certificate Validation',
    patterns: [
      /rejectUnauthorized\s*:\s*false/i,
      /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'`]?0/,
      /verify\s*=\s*False/,
      /ssl\._create_unverified_context\s*\(/,
    ],
    fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.py', '.env'],
  },
];
