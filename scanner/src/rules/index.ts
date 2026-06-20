import { FileRule, HttpRule } from '../types';
import { apiRules } from './api.rules';
import { authRules } from './auth.rules';
import { authorizationRules } from './authorization.rules';
import { corsRules } from './cors.rules';
import { databaseRules } from './database.rules';
import { dockerRules } from './docker.rules';
import { firebaseRules } from './firebase.rules';
import { githubRules } from './github.rules';
import { headersRules } from './headers.rules';
import { logsRules } from './logs.rules';
import { nodeRules } from './node.rules';
import { privacyRules } from './privacy.rules';
import { reactRules } from './react.rules';
import { secretsRules } from './secrets.rules';
import { supabaseRules } from './supabase.rules';
import { uploadRules } from './upload.rules';
import { web3Rules } from './web3.rules';
// Novos arquivos de regras (upgrade 2026)
import { injectionRules } from './injection.rules';
import { ssrfRules } from './ssrf.rules';
import { jwtRules } from './jwt.rules';
import { apiAuthRules } from './apiauth.rules';
import { cookiesRules } from './cookies.rules';
import { dosRules } from './dos.rules';
import { supplyChainRules } from './supplychain.rules';
import { cicdRules } from './cicd.rules';
import { iacRules } from './iac.rules';
import { k8sRules } from './k8s.rules';
import { llmRules } from './llm.rules';
import { dosHeadersRules } from './dosHeaders.rules';

export {
  apiRules,
  authRules,
  authorizationRules,
  corsRules,
  databaseRules,
  dockerRules,
  firebaseRules,
  githubRules,
  headersRules,
  logsRules,
  nodeRules,
  privacyRules,
  reactRules,
  secretsRules,
  supabaseRules,
  uploadRules,
  web3Rules,
  injectionRules,
  ssrfRules,
  jwtRules,
  apiAuthRules,
  cookiesRules,
  dosRules,
  supplyChainRules,
  cicdRules,
  iacRules,
  k8sRules,
  llmRules,
  dosHeadersRules,
};

export const allFileRules: FileRule[] = [
  ...secretsRules,
  ...reactRules,
  ...nodeRules,
  ...authRules,
  ...authorizationRules,
  ...uploadRules,
  ...dockerRules,
  ...corsRules,
  ...databaseRules,
  ...web3Rules,
  ...logsRules,
  ...privacyRules,
  ...apiRules,
  ...githubRules,
  ...supabaseRules,
  ...firebaseRules,
  // Upgrade 2026
  ...injectionRules,
  ...ssrfRules,
  ...jwtRules,
  ...apiAuthRules,
  ...cookiesRules,
  ...dosRules,
  ...supplyChainRules,
  ...cicdRules,
  ...iacRules,
  ...k8sRules,
  ...llmRules,
];

// Regras HTTP usadas pelo URL analyzer (headers + WAF/CDN/rate-limit)
export const allHttpRules: HttpRule[] = [
  ...headersRules,
  ...dosHeadersRules,
];
