import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

export const testOtpEnabledRule: SecurityRule = {
  id: 'SEC-AUTH-005',
  title: 'Static Test OTP Configuration Present',
  category: 'auth',
  severity: 'high',
  description:
    'Detects static phone-to-OTP testing overrides configured under [auth.sms.test_otp].',
  policyAssumption:
    'Static test OTPs should only exist during local development and must never be deployed or committed to shared/production configuration.',
  check(context: RuleContext): Finding[] {
    const path = 'auth.sms.test_otp';
    if (!context.hasExplicitPath(path)) {
      return [];
    }

    const testOtpTable = context.getSection<Record<string, unknown>>(path);
    if (!testOtpTable || Object.keys(testOtpTable).length === 0) {
      return [];
    }

    const count = Object.keys(testOtpTable).length;

    return [
      {
        ruleId: 'SEC-AUTH-005',
        ruleTitle: 'Static Test OTP Configuration Present',
        severity: 'high',
        category: 'auth',
        path,
        observedValue: `[${count} static OTP entries configured]`,
        rationale:
          'Static SMS test OTPs allow authentication bypass with fixed, hardcoded verification codes. If this configuration is used in production or staging, attackers knowing the test numbers can authenticate without receiving an SMS.',
        policyAssumption:
          'SMS authentication in preflight and production environments must deliver dynamic, time-limited one-time passwords.',
        remediation:
          'Remove the "[auth.sms.test_otp]" table from supabase/config.toml before deploying changes.',
      },
    ];
  },
};
