import type { MigrationDatabaseState } from '../../migrations/types.js';
import type { Finding } from '../../types/rule.js';

function getDualClauseDesc(policy: { hasExplicitUsing?: boolean; hasExplicitWithCheck?: boolean }): string {
  const hasUsing = policy.hasExplicitUsing ?? false;
  const hasWithCheck = policy.hasExplicitWithCheck ?? false;
  if (hasUsing && hasWithCheck) {
    return 'USING (true) and WITH CHECK (true)';
  }
  if (!hasUsing && !hasWithCheck) {
    return 'omitted USING and WITH CHECK (defaults to true)';
  }
  if (hasUsing && !hasWithCheck) {
    return 'USING (true) and omitted WITH CHECK (defaults to true)';
  }
  return 'omitted USING (defaults to true) and WITH CHECK (true)';
}

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
      // PolicyState already models PostgreSQL command-specific defaulting:
      // For INSERT: omitted WITH CHECK is true (unrestricted).
      // For UPDATE/ALL: omitted WITH CHECK inherits USING.
      const effectiveWithCheckIsUnrestricted = policy.isUnrestrictedWithCheck;
      const hasRestrictiveWithCheck = !policy.isUnrestrictedWithCheck;

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
          let clauseDesc = policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)';

          if (policy.command === 'insert') {
            actionDesc = 'INSERT';
            clauseDesc = policy.hasExplicitWithCheck ? 'WITH CHECK (true)' : 'omitted WITH CHECK (defaults to true)';
          } else if (policy.command === 'all') {
            if (allowsUnrestrictedInsert && allowsUnrestrictedDelete && allowsUnrestrictedUpdate) {
              actionDesc = 'ALL';
              clauseDesc = getDualClauseDesc(policy);
            } else if (allowsUnrestrictedDelete && hasRestrictiveWithCheck) {
              actionDesc = 'DELETE';
              clauseDesc = policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)';
            }
          } else if (policy.command === 'update') {
            actionDesc = 'UPDATE';
            clauseDesc = policy.isUnrestrictedUsing && policy.isUnrestrictedWithCheck
              ? getDualClauseDesc(policy)
              : (policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)');
          } else if (policy.command === 'delete') {
            actionDesc = 'DELETE';
            clauseDesc = policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)';
          }

          const rationaleDetail =
            policy.command === 'all' && hasRestrictiveWithCheck
              ? `Policy "${policy.name}" on table "${table.schema}.${table.name}" grants command ALL with ${policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)'}. While WITH CHECK restricts INSERT and UPDATE, in PostgreSQL the DELETE command evaluates only the USING clause and ignores WITH CHECK, allowing unauthenticated or public callers to delete any row.`
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

        // Permissive USING on UPDATE with restrictive WITH CHECK for public or anon
        if (policy.command === 'update' && policy.isUnrestrictedUsing && hasRestrictiveWithCheck) {
          const clauseDesc = policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)';
          findings.push({
            ruleId: 'SEC-MIG-RLS-002',
            ruleTitle: 'Permissive USING on UPDATE Policy with Restrictive WITH CHECK',
            severity: 'medium',
            category: 'migrations',
            path: location,
            observedValue: `Policy "${policy.name}" allows selecting any row for UPDATE via ${clauseDesc} to roles: [${roles.join(', ')}]`,
            rationale: `Policy "${policy.name}" on table "${table.schema}.${table.name}" allows unauthenticated or anonymous callers to select any row for update because the USING clause is unconditionally true (or omitted). While WITH CHECK constrains resulting updated rows, callers may be able to alter records created by other callers if columns match the check condition, presenting a potential cross-row modification or ownership-reassignment risk. Actual exploitability depends on table privileges, column grants, triggers, applicable SELECT policies, and whether other RLS policies restrict row visibility.`,
            policyAssumption:
              'Update operations should constrain which existing rows are visible for update via row ownership or status checks in the USING clause.',
            remediation: `Add row ownership or status checks to the USING clause of policy "${policy.name}", or restrict UPDATE operations to authenticated callers.`,
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
          let clauseDesc = policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)';

          if (policy.command === 'all') {
            if (allowsUnrestrictedDelete && allowsUnrestrictedUpdate) {
              actionDesc = 'ALL';
              clauseDesc = getDualClauseDesc(policy);
            } else if (allowsUnrestrictedDelete && hasRestrictiveWithCheck) {
              actionDesc = 'DELETE';
              clauseDesc = policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)';
            }
          } else if (policy.command === 'update') {
            actionDesc = 'UPDATE';
            clauseDesc = policy.isUnrestrictedUsing && policy.isUnrestrictedWithCheck
              ? getDualClauseDesc(policy)
              : (policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)');
          } else if (policy.command === 'delete') {
            actionDesc = 'DELETE';
            clauseDesc = policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)';
          }

          const rationaleDetail =
            policy.command === 'all' && hasRestrictiveWithCheck
              ? `Policy "${policy.name}" on table "${table.schema}.${table.name}" permits command ALL with ${policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)'}. While WITH CHECK restricts INSERT and UPDATE, in PostgreSQL DELETE commands evaluate only the USING clause, allowing any authenticated user to delete records belonging to other users.`
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

        // Permissive USING on UPDATE with restrictive WITH CHECK for authenticated users
        if (policy.command === 'update' && policy.isUnrestrictedUsing && hasRestrictiveWithCheck) {
          const clauseDesc = policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)';
          findings.push({
            ruleId: 'SEC-MIG-RLS-002',
            ruleTitle: 'Permissive USING on UPDATE Policy with Restrictive WITH CHECK',
            severity: 'low',
            category: 'migrations',
            path: location,
            observedValue: `Policy "${policy.name}" allows selecting any row for UPDATE via ${clauseDesc} to authenticated users`,
            rationale: `Policy "${policy.name}" on table "${table.schema}.${table.name}" permits authenticated callers to select any row for an update operation because the USING clause is unconditionally true (or omitted). While WITH CHECK ensures that the resulting row satisfies row-level ownership (e.g. auth.uid() = user_id), callers may be able to target rows belonging to other users, creating a potential cross-row or ownership-reassignment risk. Actual exploitability depends on table privileges, column update privileges, triggers, applicable SELECT policies, and whether other RLS policies restrict row visibility.`,
            policyAssumption:
              'In multi-user tables, UPDATE policies should restrict row visibility in the USING clause (such as USING (auth.uid() = user_id)) so users can only target their own records for update.',
            remediation: `Add a row ownership check to the USING clause of policy "${policy.name}", such as "USING (auth.uid() = user_id)".`,
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
        const clauseDesc = policy.hasExplicitUsing ? 'USING (true)' : 'omitted USING (defaults to true)';
        findings.push({
          ruleId: 'SEC-MIG-RLS-002',
          ruleTitle: 'Public Read Access Allowed by RLS Policy',
          severity: 'info',
          category: 'migrations',
          path: location,
          observedValue: `Policy "${policy.name}" allows world-readable SELECT via ${clauseDesc}`,
          rationale: `Policy "${policy.name}" on table "${table.schema}.${table.name}" allows reading all rows using an unconditionally true predicate (${clauseDesc}). This is standard and expected for public content (e.g. marketing catalogs, public profiles), but this advisory verifies that the table does not contain private or sensitive user information.`,
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
