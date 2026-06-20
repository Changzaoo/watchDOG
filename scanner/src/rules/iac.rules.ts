import { FileRule } from '../types';

export const iacRules: FileRule[] = [
  {
    id: 'IAC_001',
    title: 'Terraform: bucket S3 com ACL pública',
    category: 'IaC',
    severity: 'critical',
    confidence: 'high',
    description:
      'Um recurso Terraform define uma ACL pública (public-read, public-read-write ou authenticated-read) em um bucket S3.',
    impact:
      'ACLs públicas expõem os objetos do bucket a qualquer pessoa na internet (e public-read-write permite até gravação anônima). Vazamento ou adulteração de dados.',
    attackScenarioDefensive:
      'Um bucket de backups é provisionado com acl = "public-read". Um atacante enumera o bucket e baixa dados sensíveis sem nenhuma autenticação.',
    remediation:
      'Use acl = "private" e habilite o bloqueio de acesso público (aws_s3_bucket_public_access_block) com todas as flags em true. Conceda acesso por políticas IAM específicas, não por ACL.',
    safeExample:
      'resource "aws_s3_bucket_public_access_block" "this" {\n  bucket                  = aws_s3_bucket.this.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}',
    testSuggestion:
      'Defina um recurso com acl = "public-read" e confirme a detecção; troque por acl = "private" e confirme que não dispara.',
    reference: 'AWS S3 Security Best Practices; CIS AWS Foundations Benchmark',
    patterns: [/\bacl\s*=\s*"(?:public-read|public-read-write|authenticated-read)"/i],
    fileExtensions: ['.tf'],
  },
  {
    id: 'IAC_002',
    title: 'Terraform: SG abrindo 22/3389/3306/5432 para 0.0.0.0/0',
    category: 'IaC',
    severity: 'critical',
    confidence: 'high',
    description:
      'Uma regra de Security Group abre uma porta de administração ou banco de dados (SSH 22, RDP 3389, MySQL 3306, PostgreSQL 5432) para 0.0.0.0/0 ou ::/0.',
    impact:
      'Expõe serviços sensíveis a toda a internet, permitindo brute force, exploração de vulnerabilidades e acesso direto a bancos de dados.',
    attackScenarioDefensive:
      'Um SG abre a porta 3389 para 0.0.0.0/0. Bots varrem a internet, encontram o RDP exposto e realizam brute force até comprometer a instância.',
    remediation:
      'Restrinja cidr_blocks a faixas conhecidas (VPN/bastion/escritório). Para acesso administrativo, prefira SSM Session Manager ou um bastion host; nunca exponha bancos de dados à internet.',
    safeExample:
      'ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]   # apenas rede interna/VPN\n}',
    testSuggestion:
      'Defina um ingress com from_port = 22 e cidr_blocks = ["0.0.0.0/0"] e confirme a detecção; restrinja o CIDR e confirme que não dispara.',
    reference: 'CIS AWS Foundations Benchmark: Ensure no SG allows ingress from 0.0.0.0/0 to admin ports',
    patterns: [
      /(?:from_port\s*=\s*(?:22|3389|3306|5432)\b)[\s\S]{0,200}?cidr_blocks\s*=\s*\[[^\]]*(?:0\.0\.0\.0\/0|::\/0)/i,
    ],
    fileExtensions: ['.tf'],
  },
  {
    id: 'IAC_003',
    title: 'Terraform: criptografia em repouso desabilitada',
    category: 'IaC',
    severity: 'high',
    confidence: 'medium',
    description:
      'Um recurso define explicitamente storage_encrypted = false ou encrypted = false, desabilitando a criptografia em repouso.',
    impact:
      'Dados armazenados em discos, snapshots ou bancos ficam sem criptografia. Acesso físico ao storage, snapshot vazado ou erro de configuração expõe os dados em texto claro.',
    attackScenarioDefensive:
      'Um snapshot de um volume com encrypted = false é acidentalmente compartilhado publicamente. Como não há criptografia, qualquer um que o copie lê os dados diretamente.',
    remediation:
      'Habilite a criptografia em repouso (storage_encrypted = true / encrypted = true) usando KMS. Defina chaves gerenciadas e rotação adequada.',
    safeExample:
      'resource "aws_db_instance" "this" {\n  storage_encrypted = true\n  kms_key_id        = aws_kms_key.db.arn\n}',
    testSuggestion:
      'Defina storage_encrypted = false em um recurso e confirme a detecção; troque para true e confirme que não dispara.',
    reference: 'CIS AWS Foundations Benchmark: Ensure encryption at rest is enabled',
    patterns: [/(?:storage_encrypted|encrypted)\s*=\s*false/i],
    fileExtensions: ['.tf'],
  },
  {
    id: 'CLOUD_001',
    title: 'Credenciais cloud hardcoded em IaC/config',
    category: 'IaC',
    severity: 'critical',
    confidence: 'high',
    description:
      'Credenciais de cloud em texto claro foram encontradas em arquivos de IaC/configuração: Access Key ID da AWS (AKIA...), secret access key ou chave privada (PEM).',
    impact:
      'Credenciais versionadas concedem acesso direto à conta de cloud. Um atacante com acesso ao repositório pode assumir a identidade e comprometer toda a infraestrutura.',
    attackScenarioDefensive:
      'Um par de chaves AWS é commitado em um arquivo .tfvars. Um bot que varre repositórios públicos encontra a chave em minutos e a usa para provisionar instâncias para mineração e exfiltrar dados.',
    remediation:
      'Remova as credenciais do código e rotacione-as imediatamente. Use roles/identidades gerenciadas, variáveis de ambiente ou um cofre de segredos (AWS Secrets Manager, Vault). Adicione varredura de segredos no pré-commit/CI.',
    safeExample:
      'provider "aws" {\n  region = var.region\n  # Sem credenciais no código: usa role/instance profile,\n  # variáveis de ambiente ou perfil compartilhado.\n}',
    testSuggestion:
      'Inclua uma string no formato AKIA seguida de 16 caracteres maiúsculos/dígitos e confirme a detecção; remova-a e confirme que não dispara.',
    reference: 'OWASP A07:2021 - Identification and Authentication Failures; AWS Credentials Best Practices',
    patterns: [
      /\bAKIA[0-9A-Z]{16}\b/,
      /aws_secret_access_key\s*=\s*["'][A-Za-z0-9/+]{40}["']/i,
      /"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/i,
    ],
    fileExtensions: ['.tf', '.tfvars', '.yaml', '.yml', '.json', '.env'],
  },
];
