import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

export const publicStorageBucketRule: SecurityRule = {
  id: 'SEC-ST-001',
  title: 'Storage Bucket Configured for Public Access',
  category: 'storage',
  severity: 'info',
  description:
    'Notifies when a storage bucket is explicitly marked as public (unauthenticated read access).',
  policyAssumption:
    'Public buckets bypass RLS read policies. This check ensures public exposure is intentional and documented.',
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const bucketsSection = context.getSection<Record<string, Record<string, unknown>>>('storage.buckets');

    if (!bucketsSection) {
      return [];
    }

    for (const [bucketName, config] of Object.entries(bucketsSection)) {
      if (!config || typeof config !== 'object') continue;

      const path = `storage.buckets.${bucketName}.public`;
      if (context.hasExplicitPath(path) && config.public === true) {
        findings.push({
          ruleId: 'SEC-ST-001',
          ruleTitle: 'Storage Bucket Configured for Public Access',
          severity: 'info',
          category: 'storage',
          path,
          observedValue: 'true',
          rationale: `Storage bucket "${bucketName}" is configured with "public = true". Objects in public buckets can be downloaded by anyone on the internet without authentication or Row Level Security policy checks.`,
          policyAssumption:
            'Public bucket status should be deliberate. Buckets containing confidential documents, invoices, or personal data must have public = false.',
          remediation: `Verify that "${bucketName}" only holds public assets (e.g. public avatars, marketing icons). If private, change "${path} = false" and use signed URLs or RLS policies.`,
        });
      }
    }

    return findings;
  },
};
