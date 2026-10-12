import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

const MAX_RECOMMENDED_EXPIRY_SECONDS = 86400; // 24 hours

export const jwtExpiryRule: SecurityRule = {
  id: 'SEC-AUTH-006',
  title: 'Excessive JWT Expiration Lifetime',
  category: 'auth',
  severity: 'medium',
  description:
    'Checks whether the access token JWT expiry time exceeds recommended security thresholds.',
  policyAssumption:
    'Access tokens are stateless bearer credentials; short lifetimes (typically <= 1 hour, at most 24 hours) minimize the impact of token interception.',
  check(context: RuleContext): Finding[] {
    const path = 'auth.jwt_expiry';
    if (!context.hasExplicitPath(path)) {
      return [];
    }

    const value = context.getExplicitValue<number>(path);
    if (typeof value === 'number' && value > MAX_RECOMMENDED_EXPIRY_SECONDS) {
      const hours = Math.round(value / 3600);
      return [
        {
          ruleId: 'SEC-AUTH-006',
          ruleTitle: 'Excessive JWT Expiration Lifetime',
          severity: 'medium',
          category: 'auth',
          path,
          observedValue: `${value} seconds (~${hours} hours)`,
          rationale: `The configured JWT expiry of ${value} seconds (~${hours} hours) exceeds the recommended maximum of 24 hours (86,400 seconds). Bearer tokens cannot be individually revoked without global key rotation, extending the vulnerability window if a client token is compromised.`,
          policyAssumption:
            'Short-lived access tokens combined with refresh token rotation provide a superior security posture compared to long-lived access tokens.',
          remediation:
            'Reduce "auth.jwt_expiry" to 3600 seconds (1 hour, the Supabase default) and rely on refresh token rotation for session maintenance.',
        },
      ];
    }

    return [];
  },
};
