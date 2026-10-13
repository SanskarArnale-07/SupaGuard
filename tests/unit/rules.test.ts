import { describe, expect, it } from 'vitest';
import { createRuleContext } from '../../src/config/context.js';
import { parseConfigToml } from '../../src/config/parser.js';
import {
  doubleConfirmChangesRule,
  edgeFunctionVerifyJwtRule,
  exposedSchemasRule,
  externalProviderMissingCredsRule,
  insecureRedirectUrlsRule,
  jwtExpiryRule,
  oidcSkipNonceRule,
  plaintextSecretsRule,
  publicStorageBucketRule,
  refreshTokenRotationRule,
  securePasswordChangeRule,
  sessionReplicationRoleRule,
  testOtpEnabledRule,
} from '../../src/rules/index.js';

function makeContext(toml: string) {
  const parsed = parseConfigToml(toml);
  if (!parsed.success) {
    throw new Error(`Invalid TOML in test: ${parsed.error.message}`);
  }
  return createRuleContext(parsed.data, parsed.explicitPaths);
}

describe('Security Rules Registry & Verification', () => {
  describe('SEC-SEC-001: Plaintext Secrets', () => {
    it('detects unmasked plaintext secrets in OAuth provider', () => {
      const ctx = makeContext(`
        [auth.external.github]
        enabled = true
        secret = "ghp_raw_plaintext_secret_123"
      `);
      const findings = plaintextSecretsRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-SEC-001');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].path).toBe('auth.external.github.secret');
      expect(findings[0].observedValue).toContain('[REDACTED_SECRET');
      expect(findings[0].observedValue).not.toContain('ghp_raw');
    });

    it('passes when secret uses env() reference', () => {
      const ctx = makeContext(`
        [auth.external.github]
        enabled = true
        secret = "env(GITHUB_SECRET)"
      `);
      const findings = plaintextSecretsRule.check(ctx);
      expect(findings).toHaveLength(0);
    });

    it('detects plaintext studio openai_api_key', () => {
      const ctx = makeContext(`
        [studio]
        openai_api_key = "sk-proj-plaintext-api-key"
      `);
      const findings = plaintextSecretsRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].path).toBe('studio.openai_api_key');
      expect(findings[0].observedValue).not.toContain('sk-proj');
    });

    it('detects plural secrets and unusual secret names (auth.hook.<name>.secrets, custom apiKey)', () => {
      const ctx = makeContext(`
        [auth.hook.custom_hook]
        secrets = "my_webhook_secret_key"
        [custom_service]
        apiKey = "secret_custom_api_key"
      `);
      const findings = plaintextSecretsRule.check(ctx);
      expect(findings.length).toBeGreaterThanOrEqual(2);
      expect(findings.some((f) => f.path === 'auth.hook.custom_hook.secrets')).toBe(true);
      expect(findings.some((f) => f.path === 'custom_service.apiKey')).toBe(true);
      for (const f of findings) {
        expect(f.observedValue).toContain('[REDACTED_SECRET');
        expect(f.observedValue).not.toContain('secret_custom');
      }
    });

    it('detects unmasked sensitive tokens and keys (bearer_token, bot_token, encryption_key, signing_key)', () => {
      const ctx = makeContext(`
        [custom_service]
        bearer_token = "eyJh_my_secret_bearer_token"
        bot_token = "xoxb-1234-5678-secret-bot-token"
        encryption_key = "my-super-secret-aes-key-32b"
        signing_key = "my-rsa-private-signing-key"
      `);
      const findings = plaintextSecretsRule.check(ctx);
      expect(findings).toHaveLength(4);
      for (const f of findings) {
        expect(f.ruleId).toBe('SEC-SEC-001');
        expect(f.severity).toBe('critical');
        expect(f.observedValue).toContain('[REDACTED_SECRET');
        expect(f.observedValue).not.toContain('secret');
        expect(f.observedValue).not.toContain('xoxb');
      }
    });

    it('passes when sensitive keys use env() references', () => {
      const ctx = makeContext(`
        [custom_service]
        bearer_token = "env(MY_BEARER_TOKEN)"
        bot_token = "env(SLACK_BOT_TOKEN)"
        encryption_key = "env(APP_ENCRYPTION_KEY)"
        signing_key = "env(JWT_SIGNING_KEY)"
      `);
      const findings = plaintextSecretsRule.check(ctx);
      expect(findings).toHaveLength(0);
    });

    it('handles malformed secret values (e.g. numeric or boolean) safely', () => {
      const ctx = makeContext(`
        [auth.external.github]
        secret = 99887766
      `);
      const findings = plaintextSecretsRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].observedValue).toContain('[REDACTED_SECRET');
      expect(findings[0].observedValue).not.toContain('99887766');
    });
  });

  describe('SEC-AUTH-001: Refresh Token Rotation', () => {
    it('triggers when enable_refresh_token_rotation is explicitly false', () => {
      const ctx = makeContext(`
        [auth]
        enable_refresh_token_rotation = false
      `);
      const findings = refreshTokenRotationRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-AUTH-001');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].observedValue).toBe('false');
    });

    it('passes when enable_refresh_token_rotation is true or omitted', () => {
      const ctx1 = makeContext(`
        [auth]
        enable_refresh_token_rotation = true
      `);
      expect(refreshTokenRotationRule.check(ctx1)).toHaveLength(0);

      const ctx2 = makeContext(`
        [auth]
        site_url = "http://localhost:3000"
      `);
      expect(refreshTokenRotationRule.check(ctx2)).toHaveLength(0);
    });
  });

  describe('SEC-AUTH-002: Double Confirm Changes', () => {
    it('triggers when auth.email.double_confirm_changes is explicitly false', () => {
      const ctx = makeContext(`
        [auth.email]
        double_confirm_changes = false
      `);
      const findings = doubleConfirmChangesRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-AUTH-002');
      expect(findings[0].severity).toBe('high');
    });

    it('passes when double_confirm_changes is true or omitted', () => {
      const ctx = makeContext(`
        [auth.email]
        enable_signup = true
      `);
      expect(doubleConfirmChangesRule.check(ctx)).toHaveLength(0);
    });
  });

  describe('SEC-AUTH-003: OIDC Skip Nonce Check', () => {
    it('triggers when skip_nonce_check is true for a provider', () => {
      const ctx = makeContext(`
        [auth.external.google]
        enabled = true
        skip_nonce_check = true
      `);
      const findings = oidcSkipNonceRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-AUTH-003');
      expect(findings[0].path).toBe('auth.external.google.skip_nonce_check');
    });

    it('passes when skip_nonce_check is false or omitted', () => {
      const ctx = makeContext(`
        [auth.external.google]
        enabled = true
        skip_nonce_check = false
      `);
      expect(oidcSkipNonceRule.check(ctx)).toHaveLength(0);
    });
  });

  describe('SEC-AUTH-004: Insecure or Permissive Redirect URLs', () => {
    it('flags completely open wildcard redirect URLs as high severity', () => {
      const ctx = makeContext(`
        [auth]
        additional_redirect_urls = ["*", "https://*"]
      `);
      const findings = insecureRedirectUrlsRule.check(ctx);
      expect(findings).toHaveLength(2);
      expect(findings[0].severity).toBe('high');
      expect(findings[0].ruleTitle).toContain('Excessively Permissive or Open Wildcard');
      expect(findings[1].severity).toBe('high');
    });

    it('flags unscoped multi-tenant hosting root wildcards as high severity', () => {
      const ctx = makeContext(`
        [auth]
        additional_redirect_urls = [
          "https://*.vercel.app/**",
          "https://*.netlify.app/**",
          "https://*.onrender.com/**",
          "https://*.up.railway.app/**",
          "https://*.fly.dev/**",
          "https://*.amplifyapp.com/**"
        ]
      `);
      const findings = insecureRedirectUrlsRule.check(ctx);
      expect(findings).toHaveLength(6);
      for (const finding of findings) {
        expect(finding.severity).toBe('high');
        expect(finding.rationale).toContain('multi-tenant hosting platforms');
      }
    });

    it('classifies scoped preview deployment wildcards on multi-tenant hosts as low severity', () => {
      const ctx = makeContext(`
        [auth]
        additional_redirect_urls = [
          "https://*-myteam.onrender.com/**",
          "https://myproj-*.up.railway.app/**",
          "https://*-staging.fly.dev/**",
          "https://main-*.amplifyapp.com/**"
        ]
      `);
      const findings = insecureRedirectUrlsRule.check(ctx);
      expect(findings).toHaveLength(4);
      for (const finding of findings) {
        expect(finding.severity).toBe('low');
        expect(finding.ruleTitle).toContain('Scoped Wildcard');
      }
    });

    it('flags unencrypted HTTP redirect URLs to remote hosts as high severity', () => {
      const ctx = makeContext(`
        [auth]
        additional_redirect_urls = ["http://remote-app.com/callback", "http://localhost:3000"]
      `);
      const findings = insecureRedirectUrlsRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe('high');
      expect(findings[0].ruleTitle).toContain('Unencrypted HTTP');
      expect(findings[0].observedValue).toContain('http://remote-app.com');
    });

    it('classifies legitimate scoped preview deployment wildcards as low severity advisories', () => {
      const ctx = makeContext(`
        [auth]
        additional_redirect_urls = [
          "https://*-myteam.vercel.app/**",
          "https://**--myorg.netlify.app/**"
        ]
      `);
      const findings = insecureRedirectUrlsRule.check(ctx);
      expect(findings).toHaveLength(2);
      expect(findings[0].severity).toBe('low');
      expect(findings[0].ruleTitle).toContain('Scoped Wildcard');
      expect(findings[0].rationale).toContain('preview deployments');
      expect(findings[1].severity).toBe('low');
    });

    it('allows exact HTTPS endpoints and localhost', () => {
      const ctx = makeContext(`
        [auth]
        additional_redirect_urls = [
          "http://localhost:3000",
          "http://127.0.0.1:8080",
          "https://app.example.com/auth/callback"
        ]
      `);
      expect(insecureRedirectUrlsRule.check(ctx)).toHaveLength(0);
    });

    it('flags unencrypted HTTP site_url to remote hosts as high severity', () => {
      const ctx = makeContext(`
        [auth]
        site_url = "http://api.remote-production.com"
      `);
      const findings = insecureRedirectUrlsRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe('high');
      expect(findings[0].ruleTitle).toBe('Unencrypted HTTP Site URL');
      expect(findings[0].path).toBe('auth.site_url');
      expect(findings[0].observedValue).toContain('http://api.remote-production.com');
    });

    it('allows valid HTTPS, localhost, 127.0.0.1 and mobile deep-link site_url without flagging', () => {
      const ctxHttps = makeContext(`
        [auth]
        site_url = "https://app.example.com"
      `);
      expect(insecureRedirectUrlsRule.check(ctxHttps)).toHaveLength(0);

      const ctxLocalhost = makeContext(`
        [auth]
        site_url = "http://localhost:3000"
      `);
      expect(insecureRedirectUrlsRule.check(ctxLocalhost)).toHaveLength(0);

      const ctxLoopback = makeContext(`
        [auth]
        site_url = "http://127.0.0.1:8080"
      `);
      expect(insecureRedirectUrlsRule.check(ctxLoopback)).toHaveLength(0);

      const ctxMobile = makeContext(`
        [auth]
        site_url = "mycustomapp://callback"
      `);
      expect(insecureRedirectUrlsRule.check(ctxMobile)).toHaveLength(0);
    });

    it('does not apply additional_redirect_urls wildcard logic to site_url', () => {
      const ctx = makeContext(`
        [auth]
        site_url = "https://my-preview.vercel.app"
      `);
      expect(insecureRedirectUrlsRule.check(ctx)).toHaveLength(0);
    });
  });

  describe('SEC-AUTH-005: SMS Test OTP', () => {
    it('triggers when test_otp table has entries', () => {
      const ctx = makeContext(`
        [auth.sms.test_otp]
        "1234567890" = "123456"
      `);
      const findings = testOtpEnabledRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-AUTH-005');
      expect(findings[0].path).toBe('auth.sms.test_otp');
    });

    it('passes when test_otp is absent', () => {
      const ctx = makeContext(`
        [auth.sms]
        enable_signup = true
      `);
      expect(testOtpEnabledRule.check(ctx)).toHaveLength(0);
    });
  });

  describe('SEC-AUTH-006: JWT Expiry', () => {
    it('triggers when jwt_expiry exceeds 86,400 seconds (24 hours)', () => {
      const ctx = makeContext(`
        [auth]
        jwt_expiry = 604800
      `);
      const findings = jwtExpiryRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-AUTH-006');
      expect(findings[0].severity).toBe('medium');
    });

    it('passes when jwt_expiry is default 3600 or reasonable', () => {
      const ctx = makeContext(`
        [auth]
        jwt_expiry = 3600
      `);
      expect(jwtExpiryRule.check(ctx)).toHaveLength(0);
    });
  });

  describe('SEC-AUTH-007: Incomplete OAuth Provider Credentials', () => {
    it('triggers when provider is enabled with empty client_id or secret', () => {
      const ctx = makeContext(`
        [auth.external.apple]
        enabled = true
        client_id = ""
        secret = ""
      `);
      const findings = externalProviderMissingCredsRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-AUTH-007');
    });

    it('passes when provider is disabled or properly populated', () => {
      const ctx1 = makeContext(`
        [auth.external.apple]
        enabled = false
        client_id = ""
      `);
      expect(externalProviderMissingCredsRule.check(ctx1)).toHaveLength(0);

      const ctx2 = makeContext(`
        [auth.external.apple]
        enabled = true
        client_id = "env(APPLE_CLIENT_ID)"
        secret = "env(APPLE_SECRET)"
      `);
      expect(externalProviderMissingCredsRule.check(ctx2)).toHaveLength(0);
    });
  });

  describe('SEC-AUTH-008: Secure Password Change', () => {
    it('triggers when secure_password_change is explicitly false', () => {
      const ctx = makeContext(`
        [auth.email]
        secure_password_change = false
      `);
      const findings = securePasswordChangeRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-AUTH-008');
      expect(findings[0].severity).toBe('low');
    });
  });

  describe('SEC-FN-001: Edge Function Verify JWT', () => {
    it('triggers when verify_jwt is explicitly false', () => {
      const ctx = makeContext(`
        [functions.my_webhook]
        enabled = true
        verify_jwt = false
      `);
      const findings = edgeFunctionVerifyJwtRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-FN-001');
      expect(findings[0].path).toBe('functions.my_webhook.verify_jwt');
    });

    it('passes when verify_jwt is true or omitted', () => {
      const ctx = makeContext(`
        [functions.my_webhook]
        enabled = true
        verify_jwt = true
      `);
      expect(edgeFunctionVerifyJwtRule.check(ctx)).toHaveLength(0);
    });
  });

  describe('SEC-DB-001: Database Session Replication Role', () => {
    it('triggers when session_replication_role is replica', () => {
      const ctx = makeContext(`
        [db.settings]
        session_replication_role = "replica"
      `);
      const findings = sessionReplicationRoleRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-DB-001');
      expect(findings[0].severity).toBe('high');
    });

    it('passes when session_replication_role is origin or omitted', () => {
      const ctx = makeContext(`
        [db.settings]
        session_replication_role = "origin"
      `);
      expect(sessionReplicationRoleRule.check(ctx)).toHaveLength(0);
    });
  });

  describe('SEC-API-001: Internal Schemas Exposed in API', () => {
    it('triggers when internal schemas like auth or vault are included in api.schemas', () => {
      const ctx = makeContext(`
        [api]
        schemas = ["public", "auth", "vault"]
      `);
      const findings = exposedSchemasRule.check(ctx);
      expect(findings).toHaveLength(2);
      expect(findings[0].ruleId).toBe('SEC-API-001');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].rationale).toContain('widens the API attack surface');
    });

    it('passes when standard schemas like public or storage are used', () => {
      const ctx = makeContext(`
        [api]
        schemas = ["public", "storage", "graphql_public"]
      `);
      expect(exposedSchemasRule.check(ctx)).toHaveLength(0);
    });
  });

  describe('SEC-ST-001: Public Storage Bucket', () => {
    it('reports info finding when storage bucket is public = true', () => {
      const ctx = makeContext(`
        [storage.buckets.documents]
        public = true
      `);
      const findings = publicStorageBucketRule.check(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-ST-001');
      expect(findings[0].severity).toBe('info');
    });

    it('passes when bucket is public = false', () => {
      const ctx = makeContext(`
        [storage.buckets.documents]
        public = false
      `);
      expect(publicStorageBucketRule.check(ctx)).toHaveLength(0);
    });
  });
});
