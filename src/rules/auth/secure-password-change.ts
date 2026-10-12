import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

export const securePasswordChangeRule: SecurityRule = {
  id: 'SEC-AUTH-008',
  title: 'Password Re-Authentication for Password Change Disabled',
  category: 'auth',
  severity: 'low',
  description:
    'Checks whether changing a password requires providing the existing password first.',
  policyAssumption:
    'High-security applications should require the existing password to change passwords, protecting sessions against physical device hijacking.',
  check(context: RuleContext): Finding[] {
    const path = 'auth.email.secure_password_change';
    if (!context.hasExplicitPath(path)) {
      return [];
    }

    const value = context.getExplicitValue(path);
    if (value === false) {
      return [
        {
          ruleId: 'SEC-AUTH-008',
          ruleTitle: 'Password Re-Authentication for Password Change Disabled',
          severity: 'low',
          category: 'auth',
          path,
          observedValue: 'false',
          rationale:
            'When secure_password_change is false, users can update their password without proving possession of their current password. An adversary with transient physical access to an unlocked device could alter the user password and lock them out.',
          policyAssumption:
            'Requiring the current password during credential change is a recommended defensive depth measure.',
          remediation:
            'Set "auth.email.secure_password_change = true" in supabase/config.toml.',
        },
      ];
    }

    return [];
  },
};
