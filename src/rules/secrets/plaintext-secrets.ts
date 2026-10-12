import { isEnvVarReference, isSensitivePath, maskSensitiveValue } from '../../reporter/mask.js';
import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

const STATIC_SECRET_FIELDS = [
  'studio.openai_api_key',
  'auth.email.smtp.pass',
  'experimental.s3_secret_key',
  'experimental.s3_access_key',
];

export const plaintextSecretsRule: SecurityRule = {
  id: 'SEC-SEC-001',
  title: 'Plaintext Secret in Configuration File',
  category: 'secrets',
  severity: 'critical',
  description:
    'Detects unmasked, hardcoded credentials or API tokens in config.toml instead of env() references.',
  policyAssumption:
    'Version-controlled configuration files must never store static secrets, API tokens, or passwords. Supabase CLI supports "env(VAR_NAME)" substitution for secrets.',
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const checkedPaths = new Set<string>();

    const checkField = (fieldPath: string, displayPath: string) => {
      if (checkedPaths.has(fieldPath)) return;
      checkedPaths.add(fieldPath);

      if (!context.hasExplicitPath(fieldPath)) return;
      const value = context.getExplicitValue(fieldPath);

      if (value === null || value === undefined) return;

      // If it's a string
      if (typeof value === 'string') {
        const trimmed = value.trim();
        // If empty string or valid env(...) reference, it's not a committed secret
        if (trimmed === '' || isEnvVarReference(trimmed)) {
          return;
        }
      }

      // Hardcoded plaintext secret or unexpected secret literal detected!
      findings.push({
        ruleId: 'SEC-SEC-001',
        ruleTitle: 'Plaintext Secret in Configuration File',
        severity: 'critical',
        category: 'secrets',
        path: displayPath,
        observedValue: maskSensitiveValue(value, true),
        rationale: `The setting "${displayPath}" contains an unencrypted plaintext credential or literal secret. Committing secrets to version control exposes them to unauthorized repository readers and version history leaks.`,
        policyAssumption:
          'All secrets in config.toml must reference environment variables via env(VARIABLE_NAME) to prevent credential exposure in source control.',
        remediation: `Replace the hardcoded secret at "${displayPath}" with an environment variable reference, e.g. 'env(YOUR_SECRET_NAME)'.`,
      });
    };

    // 1. Check known static secret fields
    for (const field of STATIC_SECRET_FIELDS) {
      checkField(field, field);
    }

    // 2. Check external auth providers: auth.external.<provider>.secret
    const externalSection = context.getSection<Record<string, Record<string, unknown>>>('auth.external');
    if (externalSection) {
      for (const provider of Object.keys(externalSection)) {
        checkField(`auth.external.${provider}.secret`, `auth.external.${provider}.secret`);
      }
    }

    // 3. Check SMS providers: auth.sms.<provider>.auth_token / api_key / api_secret / access_key
    const smsSection = context.getSection<Record<string, Record<string, unknown>>>('auth.sms');
    if (smsSection) {
      for (const provider of Object.keys(smsSection)) {
        if (provider === 'test_otp') continue;
        const sub = smsSection[provider];
        if (sub && typeof sub === 'object') {
          for (const key of ['auth_token', 'api_key', 'api_secret', 'access_key']) {
            checkField(`auth.sms.${provider}.${key}`, `auth.sms.${provider}.${key}`);
          }
        }
      }
    }

    // 4. Check auth hooks: auth.hook.<hook_name>.secrets
    const hookSection = context.getSection<Record<string, Record<string, unknown>>>('auth.hook');
    if (hookSection) {
      for (const hookName of Object.keys(hookSection)) {
        checkField(`auth.hook.${hookName}.secrets`, `auth.hook.${hookName}.secrets`);
      }
    }

    // 5. Check all other explicitly configured paths that match sensitive patterns
    if (context.explicitPaths) {
      for (const path of context.explicitPaths) {
        if (isSensitivePath(path) && !checkedPaths.has(path) && !path.startsWith('auth.sms.test_otp')) {
          checkField(path, path);
        }
      }
    }

    return findings;
  },
};
