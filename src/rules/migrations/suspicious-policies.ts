import type {
  MigrationDatabaseState,
  PolicyCommand,
  PolicyState,
  TableState,
} from '../../migrations/types.js';
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

function policyAppliesToCommand(policy: PolicyState, cmd: PolicyCommand): boolean {
  return policy.command === 'all' || policy.command === cmd;
}

function policyAppliesToRole(policy: PolicyState, role: string): boolean {
  return (
    policy.roles.includes('public') ||
    policy.roles.length === 0 ||
    policy.roles.includes(role)
  );
}

function hasNarrowingRestrictiveClause(
  table: TableState,
  cmd: PolicyCommand,
  role: string,
  clause: 'using' | 'with_check'
): boolean {
  for (const policy of table.policies.values()) {
    if (policy.dropped || policy.permissive) continue;
    if (!policyAppliesToCommand(policy, cmd) || !policyAppliesToRole(policy, role)) continue;
    if (clause === 'using' && policy.isNarrowingUsing) return true;
    if (clause === 'with_check' && policy.isNarrowingWithCheck) return true;
  }
  return false;
}

function isPolicyNarrowedByRestrictive(
  table: TableState,
  policy: PolicyState,
  clause: 'using' | 'with_check'
): boolean {
  const roles =
    policy.roles.includes('public') || policy.roles.length === 0
      ? ['anon', 'authenticated']
      : policy.roles.filter((r) => r === 'anon' || r === 'authenticated');

  if (roles.length === 0) return false;

  const cmd = policy.command;
  const commands: PolicyCommand[] =
    cmd === 'all'
      ? clause === 'with_check'
        ? ['insert', 'update']
        : ['select', 'delete', 'update']
      : [cmd];

  return roles.every((role) =>
    commands.every((c) => hasNarrowingRestrictiveClause(table, c, role, clause))
  );
}

function restrictiveMitigatesOwnershipDisjunction(
  restrictivePolicy: PolicyState,
  ownerPolicy: PolicyState,
  cmd: PolicyCommand
): boolean {
  const isInsert = cmd === 'insert';
  const rEnforcesOwnership = isInsert
    ? restrictivePolicy.hasOwnershipCheckWithCheck
    : restrictivePolicy.hasOwnershipCheckUsing;
  if (!rEnforcesOwnership) return false;

  const ownerCols = isInsert
    ? ownerPolicy.ownershipColumnsWithCheck ?? []
    : ownerPolicy.ownershipColumnsUsing ?? [];
  const restrictiveCols = isInsert
    ? restrictivePolicy.ownershipColumnsWithCheck ?? []
    : restrictivePolicy.ownershipColumnsUsing ?? [];
  const rIsEntityMembership = isInsert
    ? restrictivePolicy.hasEntityMembershipWithCheck ?? false
    : restrictivePolicy.hasEntityMembershipUsing ?? false;
  const ownerIsEntityMembership = isInsert
    ? ownerPolicy.hasEntityMembershipWithCheck ?? false
    : ownerPolicy.hasEntityMembershipUsing ?? false;

  // 1. If the owner policy binds specific table column(s) (e.g. user_id):
  if (ownerCols.length > 0) {
    // If the restrictive policy also binds specific table column(s) (e.g. created_by):
    if (restrictiveCols.length > 0) {
      // The analyzer must not assume that two different column names establish the same authorization boundary.
      return ownerCols.every((col) => restrictiveCols.includes(col));
    }
    // If the restrictive policy enforces row ownership via a proven entity-correlated membership check:
    if (rIsEntityMembership) {
      return true;
    }
    // An empty ownership-column list (e.g. disjunctive OR across different columns,
    // or unclassified predicate) is NOT proof that the column boundary is enforced.
    return false;
  }

  // 2. If the owner policy is an entity-correlated membership check:
  if (ownerIsEntityMembership) {
    return rIsEntityMembership;
  }

  return false;
}

/**
 * SEC-MIG-RLS-002: Suspicious or Overly Permissive Row Level Security Policies
 */
export function checkSuspiciousPolicies(dbState: MigrationDatabaseState): Finding[] {
  const findings: Finding[] = [];
  const emittedDisjunctions = new Set<string>();

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

      // Restrictive policies only filter; they never independently grant access
      if (!policy.permissive) {
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
      // In aggregate analysis: verify whether applicable restrictive policies demonstrably narrow access.
      const effectiveUsingUnrestricted =
        policy.isUnrestrictedUsing && !isPolicyNarrowedByRestrictive(table, policy, 'using');
      const effectiveWithCheckUnrestricted =
        policy.isUnrestrictedWithCheck && !isPolicyNarrowedByRestrictive(table, policy, 'with_check');
      const hasRestrictiveWithCheck = !effectiveWithCheckUnrestricted;

      // 1. SELECT (reads): governed exclusively by USING expression
      const allowsUnrestrictedSelect =
        (policy.command === 'select' || policy.command === 'all') &&
        effectiveUsingUnrestricted;

      // 2. INSERT (new rows): governed by WITH CHECK expression
      // If WITH CHECK is explicitly restrictive, insert is NOT unrestricted
      const allowsUnrestrictedInsert =
        (policy.command === 'insert' || policy.command === 'all') &&
        effectiveWithCheckUnrestricted;

      // 3. DELETE (deletions): In PostgreSQL, DELETE only evaluates the USING clause!
      // WITH CHECK is never evaluated for DELETE operations.
      const allowsUnrestrictedDelete =
        (policy.command === 'delete' || policy.command === 'all') &&
        effectiveUsingUnrestricted;

      // 4. UPDATE (modifications): requires row visibility (USING) and valid new row (WITH CHECK)
      const allowsUnrestrictedUpdate =
        (policy.command === 'update' || policy.command === 'all') &&
        effectiveUsingUnrestricted &&
        effectiveWithCheckUnrestricted;

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
        if (policy.command === 'update' && effectiveUsingUnrestricted && hasRestrictiveWithCheck) {
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
        if (policy.command === 'update' && effectiveUsingUnrestricted && hasRestrictiveWithCheck) {
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

    // 2. Aggregate Multi-Permissive Policy Disjunction Analysis
    // In PostgreSQL, multiple PERMISSIVE policies combine via logical OR (pol1 OR pol2).
    // If an ownership policy exists (e.g. auth.uid() = user_id), but another permissive policy
    // on the same table grants access under a non-ownership condition without a narrowing
    // restrictive policy, callers can access rows belonging to other users whenever the
    // second condition holds, broadening access beyond the ownership boundary.
    for (const role of ['authenticated', 'anon'] as const) {
      for (const cmd of ['select', 'insert', 'update', 'delete'] as const) {
        const applicablePermissive = Array.from(table.policies.values()).filter(
          (p) =>
            !p.dropped &&
            p.permissive &&
            policyAppliesToCommand(p, cmd) &&
            policyAppliesToRole(p, role)
        );
        const applicableRestrictive = Array.from(table.policies.values()).filter(
          (p) =>
            !p.dropped &&
            !p.permissive &&
            policyAppliesToCommand(p, cmd) &&
            policyAppliesToRole(p, role)
        );

        if (applicablePermissive.length < 2) continue;

        const ownershipPolicies = applicablePermissive.filter((p) =>
          cmd === 'insert' ? p.hasOwnershipCheckWithCheck : p.hasOwnershipCheckUsing
        );
        const broadPolicies = applicablePermissive.filter((p) => {
          const hasOwnership =
            cmd === 'insert' ? p.hasOwnershipCheckWithCheck : p.hasOwnershipCheckUsing;
          const isUnrestricted =
            cmd === 'insert' ? p.isUnrestrictedWithCheck : p.isUnrestrictedUsing;
          return !hasOwnership && !isUnrestricted;
        });

        // Check whether tenant isolation is active to calibrate advisory explanation
        const applicableTenantRestrictive = applicableRestrictive.find((r) =>
          cmd === 'insert' ? r.hasTenantCheckWithCheck : r.hasTenantCheckUsing
        );

        if (ownershipPolicies.length > 0 && broadPolicies.length > 0) {
          for (const pBroad of broadPolicies) {
            const dedupKey = `${table.schema}.${table.name}:${pBroad.name}:${role}:${cmd}`;
            if (emittedDisjunctions.has(dedupKey)) continue;

            // Check if every ownership policy is mitigated by an applicable restrictive policy.
            // If all ownership boundaries are mitigated, the disjunction cannot broaden beyond them.
            const unmitigatedOwners = ownershipPolicies.filter(
              (pOwner) =>
                !applicableRestrictive.some((r) =>
                  restrictiveMitigatesOwnershipDisjunction(r, pOwner, cmd)
                )
            );

            if (unmitigatedOwners.length === 0) {
              // All ownership boundaries are genuinely mitigated by restrictive policies!
              continue;
            }

            emittedDisjunctions.add(dedupKey);

            const pOwner = unmitigatedOwners[0];
            const sev = cmd === 'update' || cmd === 'delete' ? 'medium' : 'low';

            // Check if a restrictive policy exists that enforces row identity but fails to mitigate this ownership boundary
            const applicableMismatchRestrictive = applicableRestrictive.find((r) => {
              const rEnforces = cmd === 'insert' ? r.hasOwnershipCheckWithCheck : r.hasOwnershipCheckUsing;
              if (!rEnforces) return false;
              const ownerCols = cmd === 'insert' ? pOwner.ownershipColumnsWithCheck ?? [] : pOwner.ownershipColumnsUsing ?? [];
              const rCols = cmd === 'insert' ? r.ownershipColumnsWithCheck ?? [] : r.ownershipColumnsUsing ?? [];
              const rIsEntityMembership = cmd === 'insert' ? r.hasEntityMembershipWithCheck ?? false : r.hasEntityMembershipUsing ?? false;
              if (ownerCols.length > 0 && rCols.length > 0) {
                return !ownerCols.every((c) => rCols.includes(c));
              }
              if (ownerCols.length > 0 && rCols.length === 0 && !rIsEntityMembership) {
                return true;
              }
              return false;
            });

            const ownerCol = (cmd === 'insert' ? pOwner.ownershipColumnsWithCheck : pOwner.ownershipColumnsUsing)?.[0] ?? 'ownership';
            const rCols = applicableMismatchRestrictive
              ? (cmd === 'insert' ? applicableMismatchRestrictive.ownershipColumnsWithCheck : applicableMismatchRestrictive.ownershipColumnsUsing) ?? []
              : [];
            const rCol = rCols[0] ?? '';

            const tenantContext = applicableTenantRestrictive
              ? ` (within tenant boundary enforced by "${applicableTenantRestrictive.name}")`
              : '';
            const mismatchContext = applicableMismatchRestrictive
              ? rCol
                ? ` (unmitigated by restrictive policy "${applicableMismatchRestrictive.name}" on column "${rCol}")`
                : ` (unmitigated by restrictive policy "${applicableMismatchRestrictive.name}")`
              : '';

            const rationaleContext = applicableMismatchRestrictive
              ? rCol
                ? ` While restrictive policy "${applicableMismatchRestrictive.name}" enforces row identity on column "${rCol}", it does not verify "${ownerCol}" as enforced by policy "${pOwner.name}". Because different columns may define different security boundaries, callers satisfying "${pBroad.name}" can access rows belonging to other users whenever "${rCol}" matches auth.uid().`
                : ` While restrictive policy "${applicableMismatchRestrictive.name}" checks user identity, its disjunctive or unconfirmed condition does not guarantee "${ownerCol}" as enforced by policy "${pOwner.name}". Callers satisfying "${pBroad.name}" can access rows belonging to other users whenever "${applicableMismatchRestrictive.name}" is satisfied.`
              : applicableTenantRestrictive
                ? ` While restrictive policy "${applicableTenantRestrictive.name}" isolates records by tenant, permissive policy "${pBroad.name}" combines via OR with ownership policy "${pOwner.name}", allowing callers to access records created by other users within the same tenant whenever "${pBroad.name}" is satisfied.`
                : ` Callers can access records created by other users whenever "${pBroad.name}" is satisfied, broadening access beyond the ownership boundary.`;

            findings.push({
              ruleId: 'SEC-MIG-RLS-002',
              ruleTitle:
                'Permissive Policy Disjunction Broadens Access Beyond Ownership Boundary',
              severity: sev,
              category: 'migrations',
              path: `${pBroad.createdIn.file}:${pBroad.createdIn.line}`,
              observedValue: `Policy "${pBroad.name}" combines via OR with ownership policy "${pOwner.name}" for command "${cmd.toUpperCase()}" to role "${role}"${tenantContext}${mismatchContext}`,
              rationale: `Policy "${pBroad.name}" on table "${table.schema}.${table.name}" combines via logical OR with ownership policy "${pOwner.name}" for command "${cmd.toUpperCase()}" to role "${role}". In PostgreSQL, multiple PERMISSIVE policies for the same command and role evaluate as a logical disjunction (pol1 OR pol2). While policy "${pOwner.name}" enforces a row ownership boundary (such as an auth.uid() check), permissive policy "${pBroad.name}" grants access under an independent condition without verifying user identity.${rationaleContext}`,
              policyAssumption:
                'When row ownership policies are defined to isolate user data, additional permissive policies on the same table widen accessibility for all rows satisfying their conditions. To filter rows within an owner boundary, use AS RESTRICTIVE policies (which combine via AND) rather than additional PERMISSIVE policies.',
              remediation: `If "${pBroad.name}" is intended to further restrict rows that owners can access, recreate it using "AS RESTRICTIVE" so PostgreSQL combines them with AND. If shared or public access for these rows is intentional, verify that non-owner access does not expose confidential data.`,
              filePath: pBroad.createdIn.file,
              line: pBroad.createdIn.line,
              schema: table.schema,
              table: table.name,
              policyName: pBroad.name,
            });
          }
        }
      }
    }
  }

  return findings;
}
