import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

export const sessionReplicationRoleRule: SecurityRule = {
  id: 'SEC-DB-001',
  title: 'Database Session Replication Role Set to Replica',
  category: 'database',
  severity: 'high',
  description:
    'Detects if PostgreSQL session_replication_role is set to replica, which suppresses triggers and constraint checks.',
  policyAssumption:
    'Standard database sessions should run under "origin" replication role to guarantee that triggers, constraints, and audit rules are executed.',
  check(context: RuleContext): Finding[] {
    const path = 'db.settings.session_replication_role';
    if (!context.hasExplicitPath(path)) {
      return [];
    }

    const value = context.getExplicitValue<string>(path);
    if (typeof value === 'string' && value.toLowerCase() === 'replica') {
      return [
        {
          ruleId: 'SEC-DB-001',
          ruleTitle: 'Database Session Replication Role Set to Replica',
          severity: 'high',
          category: 'database',
          path,
          observedValue: `"${value}"`,
          rationale:
            'Setting "session_replication_role = replica" disables standard database triggers, rewrite rules, and foreign key constraint validations. This can allow users or background processes to bypass audit logs and business security logic.',
          policyAssumption:
            'Replication mode "replica" should only be used by migration or replication tools during raw data syncing, not configured globally in project settings.',
          remediation:
            'Remove "session_replication_role" or set it to "origin" under [db.settings] in supabase/config.toml.',
        },
      ];
    }

    return [];
  },
};
