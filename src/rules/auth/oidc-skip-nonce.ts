import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

export const oidcSkipNonceRule: SecurityRule = {
  id: 'SEC-AUTH-003',
  title: 'OIDC Nonce Validation Bypassed',
  category: 'auth',
  severity: 'high',
  description:
    'Detects external OAuth/OIDC providers where cryptographic nonce validation has been disabled.',
  policyAssumption:
    'OpenID Connect flows should enforce cryptographic nonce verification to prevent token replay and injection attacks.',
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const externalSection = context.getSection<Record<string, Record<string, unknown>>>('auth.external');

    if (!externalSection) {
      return [];
    }

    for (const [provider, config] of Object.entries(externalSection)) {
      const path = `auth.external.${provider}.skip_nonce_check`;
      if (context.hasExplicitPath(path) && config?.skip_nonce_check === true) {
        findings.push({
          ruleId: 'SEC-AUTH-003',
          ruleTitle: 'OIDC Nonce Validation Bypassed',
          severity: 'high',
          category: 'auth',
          path,
          observedValue: 'true',
          rationale: `OIDC nonce validation is disabled for provider "${provider}". Without nonce verification, the authentication flow cannot guarantee that the presented ID token was issued in response to the original authorization request, enabling replay attacks with stolen ID tokens.`,
          policyAssumption:
            'External OIDC providers must validate the cryptographically bound nonce parameter unless technically impossible.',
          remediation: `Set "${path} = false" or remove the override in supabase/config.toml to enforce nonce validation.`,
        });
      }
    }

    return findings;
  },
};
