/**
 * Represents a single discovered SQL migration file.
 */
export interface MigrationFile {
  /** Relative path from project root, e.g. "supabase/migrations/20240101000000_init.sql" */
  relativePath: string;
  /** Absolute filesystem path */
  absolutePath: string;
  /** File basename, e.g. "20240101000000_init.sql" */
  filename: string;
  /** Raw SQL text */
  content: string;
}

/**
 * Represents a migration file that could not be read during discovery.
 */
export interface UnreadableMigrationFile {
  /** Relative path from project root, e.g. "supabase/migrations/20240101000000_init.sql" */
  relativePath: string;
  /** Absolute filesystem path */
  absolutePath: string;
  /** File basename, e.g. "20240101000000_init.sql" */
  filename: string;
  /** Error message describing why reading failed */
  error: string;
}

/**
 * Represents a failure encountered while locating, inspecting, or listing a migrations directory.
 */
export interface MigrationDiscoveryError {
  /** Filesystem path to the migrations directory */
  dirPath: string;
  /** Error message describing why discovery or listing failed */
  error: string;
}

/**
 * Supported RLS policy operations.
 */
export type PolicyCommand = 'select' | 'insert' | 'update' | 'delete' | 'all';

/**
 * State representation of a Row Level Security policy.
 */
export interface PolicyState {
  /** Policy name */
  name: string;
  /** Schema containing target table */
  schema: string;
  /** Target table name */
  table: string;
  /** Command operation */
  command: PolicyCommand;
  /** Roles granted by this policy */
  roles: string[];
  /** Whether policy is PERMISSIVE (default true) or RESTRICTIVE */
  permissive: boolean;
  /** Whether the USING expression is unconditionally true (e.g. USING (true)) */
  isUnrestrictedUsing: boolean;
  /** Whether the WITH CHECK expression is unconditionally true (e.g. WITH CHECK (true)) */
  isUnrestrictedWithCheck: boolean;
  /** Whether a USING clause was explicitly defined in SQL */
  hasExplicitUsing?: boolean;
  /** Whether a WITH CHECK clause was explicitly defined in SQL */
  hasExplicitWithCheck?: boolean;
  /** Whether the USING expression references auth.* or identity functions */
  hasAuthCheckUsing?: boolean;
  /** Whether the WITH CHECK expression references auth.* or identity functions */
  hasAuthCheckWithCheck?: boolean;
  /** Whether the USING expression enforces user-level row ownership (e.g. auth.uid() = user_id) */
  hasOwnershipCheckUsing?: boolean;
  /** Whether the WITH CHECK expression enforces user-level row ownership (e.g. auth.uid() = user_id) */
  hasOwnershipCheckWithCheck?: boolean;
  /** Specific table columns bound to auth identity for row ownership in USING expression (e.g. ['user_id']) */
  ownershipColumnsUsing?: string[];
  /** Specific table columns bound to auth identity for row ownership in WITH CHECK expression */
  ownershipColumnsWithCheck?: string[];
  /** Whether the USING expression enforces row ownership via an entity-correlated membership subquery */
  hasEntityMembershipUsing?: boolean;
  /** Whether the WITH CHECK expression enforces row ownership via an entity-correlated membership subquery */
  hasEntityMembershipWithCheck?: boolean;
  /** Whether the USING expression enforces a tenant boundary (e.g. tenant_id = (auth.jwt()->>'tenant_id')::uuid) */
  hasTenantCheckUsing?: boolean;
  /** Whether the WITH CHECK expression enforces a tenant boundary */
  hasTenantCheckWithCheck?: boolean;
  /** Whether the USING expression demonstrably narrows row accessibility */
  isNarrowingUsing?: boolean;
  /** Whether the WITH CHECK expression demonstrably narrows row accessibility */
  isNarrowingWithCheck?: boolean;
  /** Location where this policy was created */
  createdIn: {
    file: string;
    line: number;
  };
  /** Location where this policy was last altered (if applicable) */
  modifiedIn?: {
    file: string;
    line: number;
  };
  /** Whether this policy was subsequently dropped */
  dropped: boolean;
  /** Location where this policy was dropped (if applicable) */
  droppedIn?: {
    file: string;
    line: number;
  };
}

/**
 * State representation of a database table.
 */
export interface TableState {
  /** Database schema, e.g. "public" */
  schema: string;
  /** Table name */
  name: string;
  /** Location where table was created */
  createdIn: {
    file: string;
    line: number;
  };
  /** Whether Row Level Security is currently enabled */
  rowLevelSecurityEnabled: boolean;
  /** Location of the most recent ALTER TABLE ... ENABLE/DISABLE ROW LEVEL SECURITY */
  rlsChangedIn?: {
    file: string;
    line: number;
    enabled: boolean;
  };
  /** Whether this table has been dropped */
  dropped: boolean;
  /** Location where table was dropped */
  droppedIn?: {
    file: string;
    line: number;
  };
  /** Policies attached to this table, keyed by policy name */
  policies: Map<string, PolicyState>;
}

/**
 * Aggregated database state resulting from applying migration files in order.
 */
export interface MigrationDatabaseState {
  /** Tables discovered, keyed by `${schema}.${name}` */
  tables: Map<string, TableState>;
  /** Migrations successfully processed in order */
  migrationsProcessed: string[];
  /** Syntax or parser warnings/errors encountered across migration files */
  syntaxErrors: Array<{
    file: string;
    line: number;
    column: number;
    message: string;
  }>;
}
