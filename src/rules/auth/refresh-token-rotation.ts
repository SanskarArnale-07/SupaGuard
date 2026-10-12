import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

export const refreshTokenRotationRule: SecurityRule = {
  id: 'SEC-AUTH-001',
  title: 'Refresh Token Rotation Disabled',
  category: 'auth',
  severity: 'high',
  description:
    'Checks whether refresh token rotation has been explicitly disabled in authentication settings.',
  policyAssumption:
    'Refresh token rotation should be enabled so refresh tokens are single-use, preventing token reuse attacks.',
  check(context: RuleContext): Finding[] {
    const path = 'auth.enable_refresh_token_rotation';
    if (!context.hasExplicitPath(path)) {
      return [];
    }

    const value = context.getExplicitValue(path);
    if (value === false) {
      return [
        {
          ruleId: 'SEC-AUTH-001',
          ruleTitle: 'Refresh Token Rotation Disabled',
          severity: 'high',
          category: 'auth',
          path,
          observedValue: 'false',
          rationale:
            'When refresh token rotation is disabled, refresh tokens never expire upon exchange. An intercepted or leaked refresh token can be replayed indefinitely by an attacker to obtain fresh session tokens.',
          policyAssumption:
            'Production authentication services must enforce single-use refresh token rotation with immediate invalidation of superseded tokens.',
          remediation:
            'Set "auth.enable_refresh_token_rotation = true" or remove the override in supabase/config.toml to use the default rotation behavior.',
        },
      ];
    }

    return [];
  },
};
