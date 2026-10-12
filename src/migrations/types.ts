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
