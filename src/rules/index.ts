import { exposedSchemasRule } from './api/exposed-schemas.js';
import { doubleConfirmChangesRule } from './auth/double-confirm-changes.js';
import { externalProviderMissingCredsRule } from './auth/external-provider-missing-creds.js';
import { insecureRedirectUrlsRule } from './auth/insecure-redirect-urls.js';
import { jwtExpiryRule } from './auth/jwt-expiry.js';
import { oidcSkipNonceRule } from './auth/oidc-skip-nonce.js';
import { refreshTokenRotationRule } from './auth/refresh-token-rotation.js';
import { securePasswordChangeRule } from './auth/secure-password-change.js';
import { testOtpEnabledRule } from './auth/test-otp-enabled.js';
import { sessionReplicationRoleRule } from './database/session-replication.js';
import { edgeFunctionVerifyJwtRule } from './functions/verify-jwt.js';
import { defaultRegistry } from './registry.js';
import { plaintextSecretsRule } from './secrets/plaintext-secrets.js';
import { publicStorageBucketRule } from './storage/public-bucket.js';

export const ALL_BUILTIN_RULES = [
  plaintextSecretsRule,
  exposedSchemasRule,
  sessionReplicationRoleRule,
  refreshTokenRotationRule,
  doubleConfirmChangesRule,
  oidcSkipNonceRule,
  insecureRedirectUrlsRule,
  testOtpEnabledRule,
  jwtExpiryRule,
  externalProviderMissingCredsRule,
  edgeFunctionVerifyJwtRule,
  publicStorageBucketRule,
  securePasswordChangeRule,
];

// Register all rules in the default registry
for (const rule of ALL_BUILTIN_RULES) {
  defaultRegistry.register(rule);
}

export {
  defaultRegistry,
  plaintextSecretsRule,
  exposedSchemasRule,
  sessionReplicationRoleRule,
  refreshTokenRotationRule,
  doubleConfirmChangesRule,
  oidcSkipNonceRule,
  insecureRedirectUrlsRule,
  testOtpEnabledRule,
  jwtExpiryRule,
  externalProviderMissingCredsRule,
  edgeFunctionVerifyJwtRule,
  publicStorageBucketRule,
  securePasswordChangeRule,
};
