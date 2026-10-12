import type { MigrationDatabaseState } from '../../migrations/types.js';
import type { Finding } from '../../types/rule.js';

/**
 * SEC-MIG-RLS-002: Suspicious or Overly Permissive Row Level Security Policies
 */
export function checkSuspiciousPolicies(dbState: MigrationDatabaseState): Finding[] {
  const findings: Finding[] = [];

  for (const table of dbState.tables.values()) {
    // Skip dropped tables
    if (table.dropped) {
      continue;
    }

    for (const policy of table.policies.values()) {
      // Skip dropped policies
      if (policy.dropped) {
        continue;
      }

      const roles = policy.roles;
      const isPublicOrAnon = roles.includes('public') || roles.includes('anon');
      const isAuth = roles.includes('authenticated');

      // If policy only targets internal/service roles (e.g. service_role), skip
      if (!isPublicOrAnon && !isAuth) {
        continue;
      }

      const location = `${policy.createdIn.file}:${policy.createdIn.line}`;

      // In PostgreSQL:
      // If WITH CHECK is omitted for commands where allowed (ALL, UPDATE),
      // the USING clause will be used as the WITH CHECK clause.
      const hasExplicitWithCheck = policy.hasExplicitWithCheck ?? false;
      const hasRestrictiveWithCheck = hasExplicitWithCheck && !policy.isUnrestrictedWithCheck;
      const effectiveWithCheckIsUnrestricted = hasExplicitWithCheck
        ? policy.isUnrestrictedWithCheck
        : policy.isUnrestrictedUsing;

      // 1. SELECT (reads): governed exclusively by USING expression
      const allowsUnrestrictedSelect =
        (policy.command === 'select' || policy.command === 'all') &&
        policy.isUnrestrictedUsing;

      // 2. INSERT (new rows): governed by WITH CHECK expression
      // If WITH CHECK is explicitly restrictive, insert is NOT unrestricted
      const allowsUnrestrictedInsert =
        (policy.command === 'insert' || policy.command === 'all') &&
        effectiveWithCheckIsUnrestricted;

      // 3. DELETE (deletions): In PostgreSQL, DELETE only evaluates the USING clause!
      // WITH CHECK is never evaluated for DELETE operations.
      const allowsUnrestrictedDelete =
        (policy.command === 'delete' || policy.command === 'all') &&
        policy.isUnrestrictedUsing;

      // 4. UPDATE (modifications): requires row visibility (USING) and valid new row (WITH CHECK)
      const allowsUnrestrictedUpdate =
        (policy.command === 'update' || policy.command === 'all') &&
        policy.isUnrestrictedUsing &&
        effectiveWithCheckIsUnrestricted;

      // Check for High-Severity Unrestricted Write Access for public or anon
      if (isPublicOrAnon) {
        if (allowsUnrestrictedInsert || allowsUnrestrictedDelete || allowsUnrestrictedUpdate) {
          let actionDesc = policy.command.toUpperCase();
          let clauseDesc = 'USING (true)';

          if (policy.command === 'insert') {
            actionDesc = 'INSERT';
            clauseDesc = 'WITH CHECK (true)';
          } else if (policy.command === 'all') {
            if (allowsUnrestrictedInsert && allowsUnrestrictedDelete && allowsUnrestrictedUpdate) {
              actionDesc = 'ALL';
              clauseDesc = policy.isUnrestrictedUsing && policy.isUnrestrictedWithCheck
                ? 'USING (true) and WITH CHECK (true)'
                : 'USING (true)';
            } else if (allowsUnrestrictedDelete && hasRestrictiveWithCheck) {
              actionDesc = 'DELETE';
              clauseDesc = 'USING (true)';
            }
          } else if (policy.command === 'update') {
            actionDesc = 'UPDATE';
            clauseDesc = policy.isUnrestrictedUsing && policy.isUnrestrictedWithCheck
              ? 'USING (true) and WITH CHECK (true)'
              : 'USING (true)';
          } else if (policy.command === 'delete') {
            actionDesc = 'DELETE';
            clauseDesc = 'USING (true)';
          }

          const rationaleDetail =
            policy.command === 'all' && hasRestrictiveWithCheck
              ? `Policy "${policy.name}" on table "${table.schema}.${table.name}" grants command ALL with USING (true). While WITH CHECK restricts INSERT and UPDATE, in PostgreSQL the DELETE command evaluates only the USING clause and ignores WITH CHECK, allowing unauthenticated or public callers to delete any row.`
              : `Policy "${policy.name}" on table "${table.schema}.${table.name}" grants unrestricted write access (${actionDesc}) to unauthenticated or public callers using an unconditionally true predicate (${clauseDesc}). In Supabase, this enables any anonymous user to insert, alter, or remove records without constraint or row-level authorization.`;

          findings.push({
            ruleId: 'SEC-MIG-RLS-002',
            ruleTitle: 'Unrestricted Write Access Allowed by RLS Policy',
            severity: 'high',
            category: 'migrations',
            path: location,
            observedValue: `Policy "${policy.name}" allows unrestricted "${actionDesc}" via ${clauseDesc} to roles: [${roles.join(', ')}]`,
            rationale: rationaleDetail,
            policyAssumption:
              'Write operations (INSERT, UPDATE, DELETE, ALL) must enforce authentication and row ownership checks (such as auth.uid() = user_id) unless the table is explicitly an open public ingest destination.',
            remediation: `Scope policy "${policy.name}" to authenticated users and add row-level ownership checks (e.g. "WITH CHECK (auth.uid() = user_id)").`,
            filePath: policy.createdIn.file,
            line: policy.createdIn.line,
            schema: table.schema,
            table: table.name,
            policyName: policy.name,
          });
          continue;
        }
      }

      // Check for Medium-Severity Unrestricted Mutation across rows for authenticated users
      if (isAuth) {
        if (allowsUnrestrictedDelete || allowsUnrestrictedUpdate) {
          let actionDesc = policy.command.toUpperCase();
          let clauseDesc = 'USING (true)';

          if (policy.command === 'all') {
            if (allowsUnrestrictedDelete && allowsUnrestrictedUpdate) {
              actionDesc = 'ALL';
              clauseDesc = policy.isUnrestrictedUsing && policy.isUnrestrictedWithCheck
                ? 'USING (true) and WITH CHECK (true)'
                : 'USING (true)';
            } else if (allowsUnrestrictedDelete && hasRestrictiveWithCheck) {
              actionDesc = 'DELETE';
              clauseDesc = 'USING (true)';
            }
          } else if (policy.command === 'update') {
            actionDesc = 'UPDATE';
            clauseDesc = policy.isUnrestrictedUsing && policy.isUnrestrictedWithCheck
              ? 'USING (true) and WITH CHECK (true)'
              : 'USING (true)';
          } else if (policy.command === 'delete') {
            actionDesc = 'DELETE';
            clauseDesc = 'USING (true)';
          }

          const rationaleDetail =
            policy.command === 'all' && hasRestrictiveWithCheck
              ? `Policy "${policy.name}" on table "${table.schema}.${table.name}" permits command ALL with USING (true). While WITH CHECK restricts INSERT and UPDATE, in PostgreSQL DELETE commands evaluate only the USING clause, allowing any authenticated user to delete records belonging to other users.`
              : `Policy "${policy.name}" on table "${table.schema}.${table.name}" permits any authenticated user to execute ${actionDesc} on all rows using an unconditionally true predicate (${clauseDesc}). Without row ownership verification (such as auth.uid() = user_id), any authenticated user can alter or delete records created by other users.`;

          findings.push({
            ruleId: 'SEC-MIG-RLS-002',
            ruleTitle: 'Unrestricted Mutation Across Rows for Authenticated Users',
            severity: 'medium',
            category: 'migrations',
            path: location,
            observedValue: `Policy "${policy.name}" allows unrestricted "${actionDesc}" via ${clauseDesc} to authenticated users`,
            rationale: rationaleDetail,
            policyAssumption:
              'In multi-tenant or multi-user applications, row updates and deletions should verify that the acting user owns or is authorized for the target row.',
            remediation: `Add a row ownership condition to policy "${policy.name}", such as "USING (auth.uid() = user_id)".`,
            filePath: policy.createdIn.file,
            line: policy.createdIn.line,
            schema: table.schema,
            table: table.name,
            policyName: policy.name,
          });
          continue;
        }

        // Check for Low-Severity Unconditional INSERT for authenticated users
        if (allowsUnrestrictedInsert && policy.command === 'insert') {
          findings.push({
            ruleId: 'SEC-MIG-RLS-002',
            ruleTitle: 'Unconditional INSERT Permitted for Authenticated Users',
            severity: 'low',
            category: 'migrations',
            path: location,
            observedValue: `Policy "${policy.name}" allows unconditional INSERT to authenticated users`,
            rationale: `Policy "${policy.name}" allows any authenticated user to insert rows without validating foreign keys or user identity. While often intentional for user submissions, verifying identity via WITH CHECK (auth.uid() = user_id) prevents user impersonation in row fields.`,
            policyAssumption:
              'New rows inserted by authenticated clients should bind ownership identifiers to auth.uid().',
            remediation: `Consider adding "WITH CHECK (auth.uid() = user_id)" to ensure users cannot insert records on behalf of other user IDs.`,
            filePath: policy.createdIn.file,
            line: policy.createdIn.line,
            schema: table.schema,
            table: table.name,
            policyName: policy.name,
          });
          continue;
        }
      }

      // Check for Info-Severity Public Read Access
      if (allowsUnrestrictedSelect && (isPublicOrAnon || isAuth)) {
        findings.push({
          ruleId: 'SEC-MIG-RLS-002',
          ruleTitle: 'Public Read Access Allowed by RLS Policy',
          severity: 'info',
          category: 'migrations',
          path: location,
          observedValue: `Policy "${policy.name}" allows world-readable SELECT via USING (true)`,
          rationale: `Policy "${policy.name}" on table "${table.schema}.${table.name}" allows reading all rows using an unconditionally true predicate (USING (true)). This is standard and expected for public content (e.g. marketing catalogs, public profiles), but this advisory verifies that the table does not contain private or sensitive user information.`,
          policyAssumption:
            'Public read access should be deliberate and confined to non-confidential public data.',
          remediation: `Verify that "${table.schema}.${table.name}" contains only public data. If private, restrict the SELECT policy with row-level ownership checks.`,
          filePath: policy.createdIn.file,
          line: policy.createdIn.line,
          schema: table.schema,
          table: table.name,
          policyName: policy.name,
        });
      }
    }
  }

  return findings;
}
