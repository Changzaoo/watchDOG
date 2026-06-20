import { Finding, TechStack, DefenseLayerData, DefenseLayerStatus } from '@sentinelscope/shared';

interface LayerDefinition {
  name: string;
  criticalRuleIds: string[];
  warningRuleIds: string[];
  techRequired?: string[];
}

const LAYER_DEFINITIONS: LayerDefinition[] = [
  {
    name: 'Frontend',
    criticalRuleIds: ['REACT_001', 'REACT_003', 'REACT_004', 'SECRET_010'],
    warningRuleIds: ['REACT_002', 'REACT_005', 'REACT_006', 'REACT_007', 'REACT_008'],
  },
  {
    name: 'API / Backend',
    criticalRuleIds: ['NODE_001', 'NODE_002', 'NODE_009', 'NODE_010', 'NODE_011'],
    warningRuleIds: ['NODE_003', 'NODE_004', 'NODE_005', 'NODE_006', 'NODE_007', 'NODE_008', 'NODE_012', 'API_003', 'API_007'],
  },
  {
    name: 'Autenticação',
    criticalRuleIds: ['AUTH_001', 'AUTH_002', 'AUTH_003'],
    warningRuleIds: ['AUTH_004', 'AUTH_005', 'AUTH_006', 'AUTH_007', 'AUTH_008'],
  },
  {
    name: 'Autorização',
    criticalRuleIds: ['AUTHZ_001', 'AUTHZ_002', 'AUTHZ_003', 'AUTHZ_005', 'FIRE_003', 'FIRE_005'],
    warningRuleIds: ['AUTHZ_004', 'AUTHZ_006', 'AUTHZ_007', 'SUPA_002', 'SUPA_005'],
  },
  {
    name: 'Secrets / Credenciais',
    criticalRuleIds: ['SECRET_001', 'SECRET_002', 'SECRET_003', 'SECRET_004', 'SECRET_005', 'SECRET_006', 'SECRET_007', 'SECRET_009', 'SECRET_011', 'SECRET_012', 'SECRET_013', 'SECRET_014', 'SECRET_015', 'SECRET_017', 'SECRET_018', 'SECRET_019', 'SECRET_020', 'SUPA_001', 'FIRE_001', 'FIRE_002'],
    warningRuleIds: ['SECRET_008', 'SECRET_010', 'SECRET_016'],
  },
  {
    name: 'Headers HTTP',
    criticalRuleIds: [],
    warningRuleIds: ['HEAD_001', 'HEAD_002', 'HEAD_003', 'HEAD_004', 'HEAD_005', 'HEAD_006', 'HEAD_007', 'HEAD_008', 'HEAD_009'],
  },
  {
    name: 'CORS',
    criticalRuleIds: ['CORS_009'],
    warningRuleIds: ['CORS_001', 'CORS_002', 'CORS_003'],
  },
  {
    name: 'Banco de Dados',
    criticalRuleIds: ['DB_001', 'DB_002', 'DB_003', 'DB_004'],
    warningRuleIds: ['DB_005', 'DB_006'],
  },
  {
    name: 'Upload de Arquivos',
    criticalRuleIds: ['UPLOAD_004', 'UPLOAD_007'],
    warningRuleIds: ['UPLOAD_001', 'UPLOAD_002', 'UPLOAD_003', 'UPLOAD_005', 'UPLOAD_006'],
  },
  {
    name: 'Docker / Infra',
    criticalRuleIds: ['DOCKER_004', 'DOCKER_005', 'DOCKER_008', 'DOCKER_011'],
    warningRuleIds: ['DOCKER_001', 'DOCKER_002', 'DOCKER_003', 'DOCKER_006', 'DOCKER_007', 'DOCKER_010', 'DOCKER_012', 'DOCKER_013'],
  },
  {
    name: 'CI/CD',
    criticalRuleIds: ['CICD_001', 'CICD_004'],
    warningRuleIds: ['CICD_002', 'CICD_003', 'CICD_005'],
  },
  {
    name: 'Logs / Monitoramento',
    criticalRuleIds: ['LOG_002'],
    warningRuleIds: ['LOG_001', 'LOG_003', 'LOG_004', 'LOG_005'],
  },
  {
    name: 'Privacidade / LGPD',
    criticalRuleIds: ['PRIVACY_010'],
    warningRuleIds: ['PRIV_001', 'PRIV_002', 'PRIV_003', 'PRIV_004', 'PRIV_005', 'PRIVACY_011', 'PRIVACY_012', 'PRIVACY_013'],
  },
  {
    name: 'Web3 / Contratos',
    criticalRuleIds: ['WEB3_001', 'WEB3_002', 'WEB3_003', 'WEB3_004', 'WEB3_012', 'WEB3_015'],
    warningRuleIds: ['WEB3_005', 'WEB3_006', 'WEB3_007', 'WEB3_010', 'WEB3_011', 'WEB3_013', 'WEB3_014'],
    techRequired: ['ethers.js', 'web3.js', 'wagmi', 'Hardhat', 'Foundry', 'Truffle'],
  },
  {
    name: 'Dependências',
    criticalRuleIds: [],
    warningRuleIds: ['DEP_001'],
  },
  {
    name: 'Injeção & Execução',
    criticalRuleIds: ['INJ_001', 'INJ_002', 'INJ_003', 'INJ_004', 'INJ_005', 'INJ_009', 'INJ_010', 'INJ_011', 'INJ_015', 'INJ_016', 'SSRF_001'],
    warningRuleIds: ['INJ_006', 'INJ_007', 'INJ_008', 'INJ_012', 'INJ_013', 'INJ_014', 'RED_001'],
  },
  {
    name: 'DoS & Resiliência',
    criticalRuleIds: [],
    warningRuleIds: ['DOS_001', 'DOS_002', 'DOS_003', 'DOS_004', 'DOS_005', 'DOS_006', 'DOS_007', 'DOS_008', 'DOS_009', 'DOS_010', 'DOS_011', 'DOS_012', 'DOS_013', 'DOS_014'],
  },
  {
    name: 'JWT & Tokens',
    criticalRuleIds: ['JWT_001', 'JWT_002', 'JWT_004'],
    warningRuleIds: ['JWT_003', 'JWT_005', 'JWT_006'],
  },
  {
    name: 'API & Autorização (BOLA/Mass Assignment/OAuth)',
    criticalRuleIds: [],
    warningRuleIds: ['AUTHZ_010', 'AUTHZ_011', 'AUTHZ_012', 'MASS_001', 'OAUTH_001', 'OAUTH_002', 'OAUTH_003', 'CSRF_001', 'CSRF_002', 'COOKIE_C01'],
  },
  {
    name: 'Supply Chain',
    criticalRuleIds: ['SUPPLY_001', 'SUPPLY_002', 'SUPPLY_006', 'SUPPLY_010'],
    warningRuleIds: ['SUPPLY_003', 'SUPPLY_004', 'SUPPLY_005', 'SUPPLY_007', 'SUPPLY_008', 'SUPPLY_009'],
  },
  {
    name: 'IaC & Kubernetes',
    criticalRuleIds: ['IAC_001', 'IAC_002', 'CLOUD_001', 'K8S_001', 'K8S_006'],
    warningRuleIds: ['IAC_003', 'K8S_002', 'K8S_003', 'K8S_004', 'K8S_005', 'CICD_015'],
  },
  {
    name: 'LLM / IA',
    criticalRuleIds: ['LLM_002', 'LLM_003', 'LLM_004'],
    warningRuleIds: ['LLM_001', 'LLM_005', 'LLM_006', 'AI_001'],
  },
];

export function generateDefenseDepth(
  findings: Finding[],
  techStack: TechStack[],
  scanId: string
): Omit<DefenseLayerData, 'id'>[] {
  const ruleIds = new Set(findings.map(f => f.ruleId));
  const techNames = new Set(techStack.map(t => t.name));

  return LAYER_DEFINITIONS
    .filter(layer => {
      // Skip web3 layer if no web3 tech detected
      if (layer.techRequired) {
        return layer.techRequired.some(t => techNames.has(t));
      }
      return true;
    })
    .map(layer => {
      const criticalHits = layer.criticalRuleIds.filter(id => ruleIds.has(id));
      const warningHits = layer.warningRuleIds.filter(id => ruleIds.has(id));
      const allHits = [...criticalHits, ...warningHits];

      let status: DefenseLayerStatus;
      let summary: string;

      if (criticalHits.length > 0) {
        status = 'critical';
        summary = `${criticalHits.length} problema(s) crítico(s) detectado(s). Corrija imediatamente.`;
      } else if (warningHits.length > 1) {
        status = 'warning';
        summary = `${warningHits.length} problema(s) de atenção detectado(s). Revise e corrija.`;
      } else if (warningHits.length === 1) {
        status = 'warning';
        summary = `1 problema de atenção detectado: ${findings.find(f => f.ruleId === warningHits[0])?.title || warningHits[0]}.`;
      } else if (allHits.length === 0 && (layer.criticalRuleIds.length + layer.warningRuleIds.length) > 0) {
        status = 'healthy';
        summary = 'Nenhum problema detectado nesta camada.';
      } else {
        status = 'unknown';
        summary = 'Sem dados suficientes para análise desta camada.';
      }

      return {
        scanId,
        name: layer.name,
        status,
        issuesCount: allHits.length,
        summary,
      };
    });
}

export function getDefenseScore(layers: Omit<DefenseLayerData, 'id'>[]): number {
  const weights: Record<DefenseLayerStatus, number> = {
    healthy: 0,
    warning: 5,
    critical: 15,
    unknown: 1,
  };
  const totalPenalty = layers.reduce((acc, l) => acc + (weights[l.status] || 0), 0);
  return Math.max(0, 100 - totalPenalty);
}
