import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

export const externalProviderMissingCredsRule: SecurityRule = {
  id: 'SEC-AUTH-007',
  title: 'Enabled OAuth Provider Missing Credentials',
  category: 'auth',
  severity: 'medium',
  description:
    'Detects external OAuth providers that are enabled but missing client_id or secret.',
  policyAssumption:
    'Enabled authentication providers should be completely configured to prevent auth state confusion or runtime failures.',
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const externalSection = context.getSection<Record<string, Record<string, unknown>>>('auth.external');

    if (!externalSection) {
      return [];
    }

    for (const [provider, config] of Object.entries(externalSection)) {
      if (!config || typeof config !== 'object') continue;

      if (config.enabled === true) {
        const clientId = typeof config.client_id === 'string' ? config.client_id.trim() : '';
        const secret = typeof config.secret === 'string' ? config.secret.trim() : '';

        const missingParts: string[] = [];
        if (!clientId) missingParts.push('client_id');
        if (!secret) missingParts.push('secret');

        if (missingParts.length > 0) {
          findings.push({
            ruleId: 'SEC-AUTH-007',
            ruleTitle: 'Enabled OAuth Provider Missing Credentials',
            severity: 'medium',
            category: 'auth',
            path: `auth.external.${provider}`,
            observedValue: `enabled = true, missing: [${missingParts.join(', ')}]`,
            rationale: `The OAuth provider "${provider}" is enabled (enabled = true), but ${missingParts.join(' and ')} is empty or unconfigured. This leads to broken authentication flows and unpredictable runtime behavior.`,
            policyAssumption:
              'External authentication providers must either be disabled or fully configured with valid client IDs and secrets.',
            remediation: `Configure ${missingParts.map((p) => `"auth.external.${provider}.${p} = \\"env(...)\\""`).join(' and ')}, or set "auth.external.${provider}.enabled = false".`,
          });
        }
      }
    }

    return findings;
  },
};
