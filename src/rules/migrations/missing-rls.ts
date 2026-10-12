import type { MigrationDatabaseState } from '../../migrations/types.js';
import type { Finding } from '../../types/rule.js';

export interface MissingRlsOptions {
  /** Schemas exposed to the PostgREST API (defaults to ['public']) */
  exposedSchemas?: string[];
}

/**
 * SEC-MIG-RLS-001: Missing Row Level Security on API-Exposed Table
 */
export function checkMissingRls(
  dbState: MigrationDatabaseState,
  options: MissingRlsOptions = {}
): Finding[] {
  const exposed = new Set(
    (options.exposedSchemas && options.exposedSchemas.length > 0
      ? options.exposedSchemas
      : ['public']
    ).map((s) => s.trim().toLowerCase())
  );

  const findings: Finding[] = [];

  for (const table of dbState.tables.values()) {
    // 1. Skip tables dropped by a subsequent migration
    if (table.dropped) {
      continue;
    }

    // 2. Only inspect tables located in schemas exposed to the API layer
    if (!exposed.has(table.schema.toLowerCase())) {
      continue;
    }

    // 3. Skip tables that have RLS enabled in the final represented migration state
    if (table.rowLevelSecurityEnabled) {
      continue;
    }

    // Table is exposed without RLS in final state
    const location = `${table.createdIn.file}:${table.createdIn.line}`;

    findings.push({
      ruleId: 'SEC-MIG-RLS-001',
      ruleTitle: 'Table in API-Exposed Schema Lacks Row Level Security',
      severity: 'high',
      category: 'migrations',
      path: location,
      observedValue: 'Row Level Security disabled (final state)',
      rationale: `Table "${table.schema}.${table.name}" was created in "${table.createdIn.file}" (line ${table.createdIn.line}) in schema "${table.schema}" exposed by PostgREST (via api.schemas), but does not have Row Level Security (RLS) enabled in the final migration state. In Supabase, PostgREST routes allow anonymous and authenticated clients to access tables in exposed schemas. Without RLS enabled, tables are accessible according to PostgreSQL role grants, bypassing row-level access control.`,
      policyAssumption:
        'All persistent database tables in API-exposed schemas must have Row Level Security enabled (ALTER TABLE ... ENABLE ROW LEVEL SECURITY). Note that enabling RLS does not by itself guarantee that policies are secure; a table with RLS enabled and zero policies denies all client requests by default, whereas omitting RLS leaves the table governed solely by role table grants.',
      remediation: `Add "ALTER TABLE ${table.schema === 'public' ? `"${table.name}"` : `"${table.schema}"."${table.name}"`} ENABLE ROW LEVEL SECURITY;" in a migration, and create appropriate policies using CREATE POLICY.`,
      filePath: table.createdIn.file,
      line: table.createdIn.line,
      schema: table.schema,
      table: table.name,
    });
  }

  return findings;
}
