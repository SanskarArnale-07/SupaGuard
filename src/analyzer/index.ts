import * as path from 'node:path';
import { createRuleContext } from '../config/context.js';
import { discoverMigrations, type DiscoveryOptions } from '../migrations/discover.js';
import { buildMigrationDatabaseState } from '../migrations/state.js';
import type { MigrationFile, UnreadableMigrationFile, MigrationDiscoveryError } from '../migrations/types.js';
import { defaultRegistry } from '../rules/index.js';
import { checkMissingRls } from '../rules/migrations/missing-rls.js';
import { checkSuspiciousPolicies } from '../rules/migrations/suspicious-policies.js';
import { checkViewSecurity } from '../rules/migrations/view-security.js';
import { RuleRegistry } from '../rules/registry.js';
import { ExitCode, type ExitCodeValue } from '../types/exit-codes.js';
import type { LoadedConfig } from '../types/config.js';
import type { AnalysisResult, ReportSummary } from '../types/report.js';
import type { Finding, Severity } from '../types/rule.js';

export interface AnalyzerOptions {
  registry?: RuleRegistry;
  strict?: boolean;
  /** Whether to run in advisory mode (exit 0 on security findings, non-zero on execution errors) */
  advisory?: boolean;
  /** Explicit directory for SQL migrations (optional) */
  migrationsDir?: string;
  /** In-memory migration files (optional, useful for testing) */
  migrations?: MigrationFile[];
  /** In-memory unreadable migration files (optional, useful for testing) */
  unreadableMigrations?: UnreadableMigrationFile[];
  /** In-memory discovery errors (optional, useful for testing) */
  discoveryErrors?: MigrationDiscoveryError[];
  /** Custom migration discovery options for dependency injection / testing */
  discoveryOptions?: Partial<DiscoveryOptions>;
  /** Whether to skip migration scanning entirely (default false) */
  skipMigrations?: boolean;
}

const EXECUTION_ERROR_RULE_IDS = new Set([
  'SEC-MIG-DISCOVERY-ERR',
  'SEC-MIG-READ-ERR',
  'SEC-MIG-PARSE-ERR',
  'SEC-MIG-INTERNAL-ERR',
]);

/**
 * Checks if a finding represents an operational/execution error rather than
 * an ordinary security finding.
 */
export function isExecutionErrorFinding(finding: Finding): boolean {
  return (
    EXECUTION_ERROR_RULE_IDS.has(finding.ruleId) ||
    (finding.path === '(internal)' && finding.observedValue === '(evaluation error)')
  );
}

/**
 * Checks if any findings represent operational/execution errors.
 */
export function hasExecutionErrors(findings: Finding[]): boolean {
  return findings.some(isExecutionErrorFinding);
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Executes registered configuration security rules and SQL migration rules,
 * returning a unified AnalysisResult.
 */
export async function analyzeConfig(
  config: LoadedConfig,
  options: AnalyzerOptions = {}
): Promise<AnalysisResult> {
  const registry = options.registry ?? defaultRegistry;
  const strict = options.strict ?? false;

  const context = createRuleContext(config.parsed, config.explicitPaths);
  const rules = registry.getAll();

  const allFindings: Finding[] = [];

  // 1. Evaluate configuration rules (Phase 1)
  for (const rule of rules) {
    try {
      const findings = rule.check(context);
      if (findings && Array.isArray(findings)) {
        allFindings.push(...findings);
      }
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      allFindings.push({
        ruleId: rule.id,
        ruleTitle: rule.title,
        severity: 'high',
        category: rule.category,
        path: '(internal)',
        observedValue: '(evaluation error)',
        rationale: `Rule threw an unexpected evaluation error: ${errorObj.message || 'Unknown error'}`,
        policyAssumption: rule.policyAssumption,
        remediation: 'Inspect configuration TOML syntax or report an issue.',
      });
    }
  }

  // 2. Evaluate SQL migrations (Phase 2)
  let migrationRulesCount = 0;
  if (!options.skipMigrations) {
    let migrations: MigrationFile[] = [];
    let readErrors: UnreadableMigrationFile[] = options.unreadableMigrations ?? [];
    let discoveryErrors: MigrationDiscoveryError[] = options.discoveryErrors ?? [];

    if (options.migrations) {
      migrations = options.migrations;
      if ((options.migrations as any).readErrors) {
        readErrors = [...readErrors, ...(options.migrations as any).readErrors];
      }
      if ((options.migrations as any).discoveryErrors) {
        discoveryErrors = [...discoveryErrors, ...(options.migrations as any).discoveryErrors];
      }
    } else {
      const discovered = discoverMigrations({
        configPath: config.filePath,
        migrationsDir: options.migrationsDir,
        ...options.discoveryOptions,
      });
      migrations = discovered;
      readErrors = [...readErrors, ...discovered.readErrors];
      discoveryErrors = [...discoveryErrors, ...discovered.discoveryErrors];
    }

    if (migrations.length > 0 || readErrors.length > 0 || discoveryErrors.length > 0) {
      migrationRulesCount = 3; // SEC-MIG-RLS-001, SEC-MIG-RLS-002, and SEC-MIG-VIEW-001
    }

    // Record discovery errors as HIGH-severity diagnostics
    for (const discErr of discoveryErrors) {
      const displayPath =
        path.relative(process.cwd(), discErr.dirPath).replace(/\\/g, '/') || discErr.dirPath;
      allFindings.push({
        ruleId: 'SEC-MIG-DISCOVERY-ERR',
        ruleTitle: 'Migrations Directory Discovery Failure',
        severity: 'high',
        category: 'migrations',
        path: displayPath,
        observedValue: discErr.error,
        rationale: `The migrations directory "${displayPath}" was located but could not be inspected or listed (${discErr.error}). Security preflight analysis was incomplete because migrations in this directory could not be discovered or evaluated.`,
        policyAssumption:
          'Located migration directories must be accessible and readable so security preflights can accurately evaluate database state.',
        remediation:
          'Verify directory permissions and ensure SupaGuard has permission to read and list the migrations directory.',
        filePath: displayPath,
      });
    }

    // Record unreadable migration files as HIGH-severity diagnostics
    for (const readErr of readErrors) {
      allFindings.push({
        ruleId: 'SEC-MIG-READ-ERR',
        ruleTitle: 'Unreadable SQL Migration File',
        severity: 'high',
        category: 'migrations',
        path: readErr.relativePath || readErr.filename,
        observedValue: readErr.error,
        rationale: `The migration file "${readErr.filename}" could not be read (${readErr.error}). Security analysis of this migration was incomplete because its SQL statements could not be evaluated.`,
        policyAssumption:
          'All SQL migration files must be accessible and readable so security preflights can accurately evaluate database state.',
        remediation: 'Verify file permissions and ensure that SupaGuard has read access to all migration files.',
        filePath: readErr.relativePath || readErr.filename,
      });
    }

    if (migrations.length > 0) {
      try {
        const dbState = await buildMigrationDatabaseState(migrations);

        // Record any SQL syntax failures as HIGH-severity diagnostics (incomplete preflight cannot pass exit 0)
        for (const err of dbState.syntaxErrors) {
          allFindings.push({
            ruleId: 'SEC-MIG-PARSE-ERR',
            ruleTitle: 'SQL Migration Syntax Error',
            severity: 'high',
            category: 'migrations',
            path: `${err.file}:${err.line}`,
            observedValue: err.message,
            rationale: `The migration "${err.file}" contains unparseable SQL syntax at line ${err.line}, column ${err.column}. Security analysis of this migration was incomplete because its SQL statements could not be evaluated.`,
            policyAssumption:
              'Migration files must contain valid PostgreSQL syntax so security preflights can accurately evaluate database state.',
            remediation:
              'Inspect and fix the SQL syntax error in the migration file so that SupaGuard can perform a complete security preflight.',
            filePath: err.file,
            line: err.line,
          });
        }

        // Rule 1: SEC-MIG-RLS-001 (Missing RLS on API-exposed tables)
        const rawSchemas = (config.parsed as any)?.api?.schemas;
        const exposedSchemas = Array.isArray(rawSchemas) ? rawSchemas : ['public'];
        const rlsFindings = checkMissingRls(dbState, { exposedSchemas });
        allFindings.push(...rlsFindings);

        // Rule 2: SEC-MIG-RLS-002 (Suspicious RLS policies)
        const policyFindings = checkSuspiciousPolicies(dbState);
        allFindings.push(...policyFindings);

        // Rule 3: SEC-MIG-VIEW-001 (PostgreSQL View Security)
        const viewFindings = checkViewSecurity(dbState, { exposedSchemas });
        allFindings.push(...viewFindings);
      } catch (err: unknown) {
        const errorObj = err as { message?: string };
        allFindings.push({
          ruleId: 'SEC-MIG-INTERNAL-ERR',
          ruleTitle: 'Migration Analysis Failure',
          severity: 'high',
          category: 'migrations',
          path: '(migrations)',
          observedValue: '(evaluation error)',
          rationale: `Migration analysis encountered an unexpected error: ${errorObj.message || 'Unknown error'}`,
          policyAssumption: 'Migration scanner should execute reliably without internal errors.',
          remediation: 'Verify SQL migration file formats.',
        });
      }
    }
  }

  // Sort findings descending by severity
  allFindings.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity]);

  const critical = allFindings.filter((f) => f.severity === 'critical').length;
  const high = allFindings.filter((f) => f.severity === 'high').length;
  const medium = allFindings.filter((f) => f.severity === 'medium').length;
  const low = allFindings.filter((f) => f.severity === 'low').length;
  const info = allFindings.filter((f) => f.severity === 'info').length;

  // Evaluation criteria:
  // Normal mode: Pass if 0 critical and 0 high findings.
  // Strict mode: Pass only if 0 total findings.
  const passed = strict ? allFindings.length === 0 : critical === 0 && high === 0;

  const summary: ReportSummary = {
    totalRulesEvaluated: rules.length + migrationRulesCount,
    totalFindings: allFindings.length,
    critical,
    high,
    medium,
    low,
    info,
    passed,
  };

  let exitCode: ExitCodeValue = passed ? ExitCode.SUCCESS : ExitCode.SECURITY_FINDINGS;

  // In advisory mode, ordinary security findings do not block execution (exit 0).
  // However, actual execution failures, unreadable inputs, discovery errors,
  // syntax errors, and unexpected internal errors must not be silently hidden.
  if (options.advisory && !strict && exitCode === ExitCode.SECURITY_FINDINGS && !hasExecutionErrors(allFindings)) {
    exitCode = ExitCode.SUCCESS;
  }

  return {
    targetPath: config.filePath,
    strict,
    advisory: options.advisory ?? false,
    timestamp: new Date().toISOString(),
    findings: allFindings,
    summary,
    exitCode,
  };
}
