import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

export const edgeFunctionVerifyJwtRule: SecurityRule = {
  id: 'SEC-FN-001',
  title: 'Edge Function JWT Verification Disabled',
  category: 'functions',
  severity: 'medium',
  description:
    'Detects Edge Functions configured with verify_jwt = false, which allows unauthenticated invocations.',
  policyAssumption:
    'Edge Functions should verify JWTs by default unless explicitly intended to serve as public webhooks with independent signature verification.',
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const functionsSection = context.getSection<Record<string, Record<string, unknown>>>('functions');

    if (!functionsSection) {
      return [];
    }

    for (const [funcName, config] of Object.entries(functionsSection)) {
      if (!config || typeof config !== 'object') continue;

      const path = `functions.${funcName}.verify_jwt`;
      if (context.hasExplicitPath(path) && config.verify_jwt === false) {
        findings.push({
          ruleId: 'SEC-FN-001',
          ruleTitle: 'Edge Function JWT Verification Disabled',
          severity: 'medium',
          category: 'functions',
          path,
          observedValue: 'false',
          rationale: `The Edge Function "${funcName}" has JWT verification disabled (verify_jwt = false). Requests without a valid Authorization Bearer token will be accepted and executed. If this function performs privileged operations, it is exposed to unauthorized access.`,
          policyAssumption:
            'Edge Functions should require valid authentication unless designated as public webhook receivers implementing custom signature verification.',
          remediation: `Set "${path} = true" in supabase/config.toml, or verify that the function code validates incoming signatures (e.g. Stripe webhook signatures).`,
        });
      }
    }

    return findings;
  },
};
