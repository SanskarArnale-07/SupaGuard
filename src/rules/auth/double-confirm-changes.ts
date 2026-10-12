import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

export const doubleConfirmChangesRule: SecurityRule = {
  id: 'SEC-AUTH-002',
  title: 'Email Change Double Confirmation Disabled',
  category: 'auth',
  severity: 'high',
  description:
    'Checks whether email change requests require confirmation on both old and new email addresses.',
  policyAssumption:
    'Email address changes should require verification from both original and new mailboxes to prevent silent account takeover.',
  check(context: RuleContext): Finding[] {
    const path = 'auth.email.double_confirm_changes';
    if (!context.hasExplicitPath(path)) {
      return [];
    }

    const value = context.getExplicitValue(path);
    if (value === false) {
      return [
        {
          ruleId: 'SEC-AUTH-002',
          ruleTitle: 'Email Change Double Confirmation Disabled',
          severity: 'high',
          category: 'auth',
          path,
          observedValue: 'false',
          rationale:
            'When double confirmation is disabled, an email change only requires verification from the new address. If an attacker gains temporary session access, they can change the account email without the legitimate owner being able to prevent or verify the transfer.',
          policyAssumption:
            'Critical account identifiers like primary emails require approval from the current mailbox to safeguard user accounts.',
          remediation:
            'Set "auth.email.double_confirm_changes = true" or remove the override in supabase/config.toml.',
        },
      ];
    }

    return [];
  },
};
