import type { MigrationDatabaseState, TableState, ViewState } from '../../migrations/types.js';
import type { Finding } from '../../types/rule.js';

export interface ViewSecurityOptions {
  /** Schemas exposed to the PostgREST API (defaults to ['public']) */
  exposedSchemas?: string[];
}

export interface ResolvedViewDependencies {
  /** Physical base tables discovered transitively */
  physicalTables: TableState[];
  /** Relations referenced by the view that could not be resolved in migration state */
  untrackedRelations: string[];
  /** Views traversed during resolution */
  referencedViews: ViewState[];
  /** Whether a circular reference chain between views was detected */
  hasCycle: boolean;
  /** Whether underlying view definition was untracked in migrations */
  dependenciesUnknown?: boolean;
}

/**
 * Searches for a view in the migration database state by schema and name.
 */
function findView(
  dbState: MigrationDatabaseState,
  schema: string,
  name: string
): ViewState | undefined {
  const exactKey = `${schema.toLowerCase()}.${name}`;
  if (dbState.views.has(exactKey)) return dbState.views.get(exactKey);

  const lowerKey = `${schema.toLowerCase()}.${name.toLowerCase()}`;
  for (const [key, view] of dbState.views.entries()) {
    if (key.toLowerCase() === lowerKey) return view;
  }
  return undefined;
}

/**
 * Searches for a physical table in the migration database state by schema and name.
 */
function findTable(
  dbState: MigrationDatabaseState,
  schema: string,
  name: string
): TableState | undefined {
  const exactKey = `${schema.toLowerCase()}.${name}`;
  if (dbState.tables.has(exactKey)) return dbState.tables.get(exactKey);

  const lowerKey = `${schema.toLowerCase()}.${name.toLowerCase()}`;
  for (const [key, table] of dbState.tables.entries()) {
    if (key.toLowerCase() === lowerKey) return table;
  }
  return undefined;
}

/**
 * Resolves a relation reference (schema-qualified or unqualified) against the database state.
 */
function resolveRelation(
  dbState: MigrationDatabaseState,
  currentSchema: string,
  ref: { schema?: string; table: string }
): { type: 'view'; view: ViewState } | { type: 'table'; table: TableState } | undefined {
  if (ref.schema) {
    const view = findView(dbState, ref.schema, ref.table);
    if (view) return { type: 'view', view };

    const table = findTable(dbState, ref.schema, ref.table);
    if (table) return { type: 'table', table };

    return undefined;
  }

  // Unqualified relation: check view's schema first, then 'public'
  const inCurrentSchemaView = findView(dbState, currentSchema, ref.table);
  if (inCurrentSchemaView) return { type: 'view', view: inCurrentSchemaView };

  const inCurrentSchemaTable = findTable(dbState, currentSchema, ref.table);
  if (inCurrentSchemaTable) return { type: 'table', table: inCurrentSchemaTable };

  if (currentSchema.toLowerCase() !== 'public') {
    const inPublicView = findView(dbState, 'public', ref.table);
    if (inPublicView) return { type: 'view', view: inPublicView };

    const inPublicTable = findTable(dbState, 'public', ref.table);
    if (inPublicTable) return { type: 'table', table: inPublicTable };
  }

  // Check across all schemas if unique
  const matchingViews: ViewState[] = [];
  for (const v of dbState.views.values()) {
    if (v.name.toLowerCase() === ref.table.toLowerCase()) matchingViews.push(v);
  }
  if (matchingViews.length === 1) return { type: 'view', view: matchingViews[0] };

  const matchingTables: TableState[] = [];
  for (const t of dbState.tables.values()) {
    if (t.name.toLowerCase() === ref.table.toLowerCase()) matchingTables.push(t);
  }
  if (matchingTables.length === 1) return { type: 'table', table: matchingTables[0] };

  return undefined;
}

/**
 * Transitively resolves physical base tables referenced by a view, detecting cycles safely.
 */
export function resolvePhysicalTableDependencies(
  startView: ViewState,
  dbState: MigrationDatabaseState
): ResolvedViewDependencies {
  const physicalTablesMap = new Map<string, TableState>();
  const untrackedSet = new Set<string>();
  const referencedViewsMap = new Map<string, ViewState>();
  let hasCycle = false;
  let dependenciesUnknown = startView.definitionUntracked === true;

  function traverse(currentView: ViewState, currentPath: Set<string>) {
    const viewKey = `${currentView.schema.toLowerCase()}.${currentView.name.toLowerCase()}`;
    if (currentPath.has(viewKey)) {
      hasCycle = true;
      return;
    }

    if (currentView.definitionUntracked) {
      dependenciesUnknown = true;
    }

    const nextPath = new Set(currentPath);
    nextPath.add(viewKey);

    for (const ref of currentView.referencedTables) {
      const target = resolveRelation(dbState, currentView.schema, ref);
      if (!target) {
        untrackedSet.add(ref.schema ? `${ref.schema}.${ref.table}` : ref.table);
      } else if (target.type === 'table') {
        if (!target.table.dropped) {
          const tableKey = `${target.table.schema.toLowerCase()}.${target.table.name.toLowerCase()}`;
          physicalTablesMap.set(tableKey, target.table);
        }
      } else if (target.type === 'view') {
        const nestedViewKey = `${target.view.schema.toLowerCase()}.${target.view.name.toLowerCase()}`;
        if (!target.view.dropped) {
          referencedViewsMap.set(nestedViewKey, target.view);
          traverse(target.view, nextPath);
        }
      }
    }
  }

  traverse(startView, new Set<string>());

  return {
    physicalTables: Array.from(physicalTablesMap.values()),
    untrackedRelations: Array.from(untrackedSet),
    referencedViews: Array.from(referencedViewsMap.values()),
    hasCycle,
    dependenciesUnknown,
  };
}

/**
 * SEC-MIG-VIEW-001: PostgreSQL View May Bypass Underlying Row-Level Security
 *
 * Inspects PostgreSQL views in API-exposed schemas to detect exposed views that do not
 * enable `security_invoker = true`. In PostgreSQL, standard views evaluate underlying
 * relation permissions and row-level security policies using the view owner's context
 * rather than the invoking user's context (such as PostgREST's `anon` or `authenticated` roles).
 */
export function checkViewSecurity(
  dbState: MigrationDatabaseState,
  options: ViewSecurityOptions = {}
): Finding[] {
  const exposed = new Set(
    (options.exposedSchemas && options.exposedSchemas.length > 0
      ? options.exposedSchemas
      : ['public']
    ).map((s) => s.trim().toLowerCase())
  );

  const findings: Finding[] = [];

  for (const view of dbState.views.values()) {
    // 1. Skip views dropped by a subsequent migration
    if (view.dropped) {
      continue;
    }

    // 2. Only inspect views located in schemas exposed to the API layer
    if (!exposed.has(view.schema.toLowerCase())) {
      continue;
    }

    // 3. Skip views that have explicitly enabled security_invoker = true
    if (view.securityInvoker === true) {
      continue;
    }

    // 4. Resolve transitive physical table dependencies
    const deps = resolvePhysicalTableDependencies(view, dbState);
    const rlsTables = deps.physicalTables.filter((t) => t.rowLevelSecurityEnabled);
    const nonRlsTables = deps.physicalTables.filter((t) => !t.rowLevelSecurityEnabled);

    const targetLoc = view.modifiedIn ?? view.createdIn;
    const location = `${targetLoc.file}:${targetLoc.line}`;
    const qualifiedView =
      view.schema === 'public' ? `"${view.name}"` : `"${view.schema}"."${view.name}"`;

    const originDesc = view.modifiedIn
      ? `was modified in "${view.modifiedIn.file}" (line ${view.modifiedIn.line}) [originally created in "${view.createdIn.file}", line ${view.createdIn.line}]`
      : view.definitionUntracked
        ? `was encountered in "${view.createdIn.file}" (line ${view.createdIn.line}) via ALTER VIEW without a preceding CREATE VIEW statement in tracked migrations`
        : `was created in "${view.createdIn.file}" (line ${view.createdIn.line})`;

    // CASE A: At least one referenced physical table has Row Level Security enabled
    if (rlsTables.length > 0) {
      const rlsTableNames = rlsTables.map((t) => `"${t.schema}.${t.name}"`).join(', ');
      const hasForceRls = rlsTables.some((t) => t.forceRowLevelSecurity === true);
      const viewOwner = view.owner;

      let ownerPrivilegeAssessment = '';
      if (viewOwner) {
        if (viewOwner === 'postgres' || viewOwner === 'supabase_admin') {
          ownerPrivilegeAssessment = `The view owner is recorded as "${viewOwner}", an administrative superuser role with BYPASSRLS privileges in Supabase. Because underlying relation permissions and RLS evaluation normally use the view owner's context (unless security_invoker = true is specified), PostgREST queries from "anon" or "authenticated" roles will evaluate underlying table access using "${viewOwner}" privileges and bypass underlying table RLS policies.`;
        } else {
          ownerPrivilegeAssessment = `The view owner is recorded as "${viewOwner}". If this owner has BYPASSRLS privileges or owns the underlying table(s), queries from API roles ("anon" / "authenticated") will bypass the underlying table RLS policies. If this owner does not possess BYPASSRLS and does not own the underlying table(s), RLS policies applicable to "${viewOwner}" may still be evaluated.`;
        }
      } else {
        ownerPrivilegeAssessment = `The view owner is not explicitly declared in migrations. In Supabase environments, migrations execute under administrative roles (such as "postgres") that possess BYPASSRLS privileges and own created relations by default. Because exact runtime role privileges cannot be verified statically from migrations alone, this finding identifies a high potential risk of RLS bypass rather than a guaranteed bypass. Developers should verify whether the view owner possesses BYPASSRLS or owns underlying tables.`;
      }

      let forceRlsNote = '';
      if (hasForceRls) {
        forceRlsNote = ` Underlying table(s) have FORCE ROW LEVEL SECURITY enabled, which forces the table owner to obey RLS policies; however, roles with BYPASSRLS (such as the default "postgres" role in Supabase) still bypass RLS even when FORCE ROW LEVEL SECURITY is enabled.`;
      } else {
        forceRlsNote = ` Underlying table(s) do not have FORCE ROW LEVEL SECURITY enabled. If the view owner also owns the underlying table(s), PostgreSQL will not apply RLS policies for that owner during view execution.`;
      }

      const cycleNote = deps.hasCycle
        ? ' Note: A circular reference was detected during view dependency resolution.'
        : '';

      const rationale = `View "${view.schema}.${view.name}" ${originDesc} in schema "${view.schema}" exposed by PostgREST (via api.schemas), but does not have WITH (security_invoker = true) enabled in the final migration state. It queries underlying physical table(s) with Row Level Security enabled: ${rlsTableNames}. In PostgreSQL, underlying relation permissions and row-level security (RLS) evaluation for ordinary views normally use the view owner's context rather than the invoking user's context, whereas enabling security_invoker changes those checks to the invoking user's context. ${ownerPrivilegeAssessment}${forceRlsNote}${cycleNote}`;

      findings.push({
        ruleId: 'SEC-MIG-VIEW-001',
        ruleTitle: 'PostgreSQL View May Bypass Underlying Row-Level Security',
        severity: 'high',
        category: 'migrations',
        path: location,
        observedValue: 'security_invoker not enabled (defaults to false)',
        rationale,
        policyAssumption:
          "All PostgreSQL views in API-exposed schemas that reference tables with Row Level Security should enable security_invoker (ALTER VIEW ... SET (security_invoker = true)) so that PostgREST queries evaluate RLS policies against the invoking user (e.g. anon or authenticated) rather than using the view owner's context.",
        remediation: `Add "ALTER VIEW ${qualifiedView} SET (security_invoker = true);" in a migration so that PostgreSQL evaluates underlying table permissions and Row Level Security policies using the invoking user's context instead of the view owner's. Alternatively, if creating or replacing the view, specify "WITH (security_invoker = true)".`,
        filePath: targetLoc.file,
        line: targetLoc.line,
        schema: view.schema,
        view: view.name,
      });
    }

    // CASE B: View references tracked tables, but NONE have RLS enabled (Informational advisory)
    else if (nonRlsTables.length > 0) {
      const nonRlsTableNames = nonRlsTables.map((t) => `"${t.schema}.${t.name}"`).join(', ');

      findings.push({
        ruleId: 'SEC-MIG-VIEW-001',
        ruleTitle: 'Exposed PostgreSQL View Without security_invoker',
        severity: 'info',
        category: 'migrations',
        path: location,
        observedValue: 'security_invoker not enabled (underlying tables do not currently enforce RLS)',
        rationale: `View "${view.schema}.${view.name}" ${originDesc} in schema "${view.schema}" exposed by PostgREST without WITH (security_invoker = true). Its referenced tracked table(s) (${nonRlsTableNames}) do not currently have Row Level Security enabled. Although no active RLS policies are currently bypassed, omitting security_invoker means any future RLS policies added to underlying tables will be bypassed by default. Explicitly enabling security_invoker ensures consistent invoking-user security semantics.`,
        policyAssumption:
          'PostgreSQL views in API-exposed schemas should generally enable security_invoker to maintain consistent access control as schemas evolve.',
        remediation: `Consider adding "ALTER VIEW ${qualifiedView} SET (security_invoker = true);" to ensure the view consistently respects invoking user permissions as your schema evolves.`,
        filePath: targetLoc.file,
        line: targetLoc.line,
        schema: view.schema,
        view: view.name,
      });
    }

    // CASE C: View references untracked relations without any known tables
    else if (deps.untrackedRelations.length > 0) {
      const untrackedNames = deps.untrackedRelations.join(', ');

      findings.push({
        ruleId: 'SEC-MIG-VIEW-001',
        ruleTitle: 'Exposed PostgreSQL View References Untracked Relations Without security_invoker',
        severity: 'info',
        category: 'migrations',
        path: location,
        observedValue: `security_invoker not enabled (references untracked relations: ${untrackedNames})`,
        rationale: `View "${view.schema}.${view.name}" ${originDesc} in schema "${view.schema}" exposed by PostgREST without WITH (security_invoker = true). It references relation(s) not defined in tracked migrations: ${untrackedNames}. SupaGuard cannot statically determine whether these relations enforce Row Level Security.`,
        policyAssumption:
          'Exposed views referencing external or unmanaged relations should specify WITH (security_invoker = true) to prevent unintended privilege escalation.',
        remediation: `Verify whether the referenced relations (${untrackedNames}) enforce Row Level Security, and consider adding "ALTER VIEW ${qualifiedView} SET (security_invoker = true);".`,
        filePath: targetLoc.file,
        line: targetLoc.line,
        schema: view.schema,
        view: view.name,
      });
    }

    // CASE D: View has circular dependencies without base tables
    else if (deps.hasCycle) {
      findings.push({
        ruleId: 'SEC-MIG-VIEW-001',
        ruleTitle: 'Exposed PostgreSQL View Contains Circular Dependency Without security_invoker',
        severity: 'info',
        category: 'migrations',
        path: location,
        observedValue: 'security_invoker not enabled (circular view dependency detected)',
        rationale: `View "${view.schema}.${view.name}" ${originDesc} in schema "${view.schema}" exposed by PostgREST without WITH (security_invoker = true). A circular reference was safely detected among view definitions. Because the dependency chain loops, base physical table protections cannot be determined statically.`,
        policyAssumption:
          'Exposed views should explicitly configure WITH (security_invoker = true) to prevent unexpected privilege escalation.',
        remediation: `Review the view definition to resolve the circular reference or add "ALTER VIEW ${qualifiedView} SET (security_invoker = true);".`,
        filePath: targetLoc.file,
        line: targetLoc.line,
        schema: view.schema,
        view: view.name,
      });
    }

    // CASE E: View definition untracked in migrations (encountered via ALTER VIEW without CREATE VIEW)
    else if (view.definitionUntracked || deps.dependenciesUnknown) {
      findings.push({
        ruleId: 'SEC-MIG-VIEW-001',
        ruleTitle: 'Exposed Pre-Existing PostgreSQL View Without security_invoker',
        severity: 'info',
        category: 'migrations',
        path: location,
        observedValue: 'security_invoker not enabled (underlying view definition and dependencies untracked)',
        rationale: `View "${view.schema}.${view.name}" was encountered in "${targetLoc.file}" (line ${targetLoc.line}) via ALTER VIEW without a preceding CREATE VIEW statement in tracked migrations. The view is located in schema "${view.schema}" exposed by PostgREST without WITH (security_invoker = true), and its underlying dependencies cannot be statically verified. If the view references underlying tables that enforce Row Level Security, queries from API roles ("anon" or "authenticated") may execute using the view owner's context rather than the invoking user's context.`,
        policyAssumption:
          'PostgreSQL views in API-exposed schemas should explicitly specify WITH (security_invoker = true) to ensure consistent invoking-user RLS evaluation, even when view definitions pre-date tracked migrations.',
        remediation: `Verify whether the underlying tables referenced by ${qualifiedView} enforce Row Level Security, and add "ALTER VIEW ${qualifiedView} SET (security_invoker = true);" if access should be evaluated using the invoking user's permissions and RLS policies.`,
        filePath: targetLoc.file,
        line: targetLoc.line,
        schema: view.schema,
        view: view.name,
      });
    }
  }

  return findings;
}
