import { FileRule } from '../types';
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
];
