import { createRuleContext } from '../config/context.js';
import { discoverMigrations } from '../migrations/discover.js';
import { buildMigrationDatabaseState } from '../migrations/state.js';
import type { MigrationFile } from '../migrations/types.js';
import { defaultRegistry } from '../rules/index.js';
import { checkMissingRls } from '../rules/migrations/missing-rls.js';
import { checkSuspiciousPolicies } from '../rules/migrations/suspicious-policies.js';
import { RuleRegistry } from '../rules/registry.js';
import { ExitCode } from '../types/exit-codes.js';
import type { LoadedConfig } from '../types/config.js';
import type { AnalysisResult, ReportSummary } from '../types/report.js';
import type { Finding, Severity } from '../types/rule.js';

export interface AnalyzerOptions {
  registry?: RuleRegistry;
  strict?: boolean;
  /** Explicit directory for SQL migrations (optional) */
  migrationsDir?: string;
  /** In-memory migration files (optional, useful for testing) */
  migrations?: MigrationFile[];
  /** Whether to skip migration scanning entirely (default false) */
  skipMigrations?: boolean;
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
    const migrations =
      options.migrations ??
      discoverMigrations({
        configPath: config.filePath,
        migrationsDir: options.migrationsDir,
      });

    if (migrations.length > 0) {
      migrationRulesCount = 2; // SEC-MIG-RLS-001 and SEC-MIG-RLS-002

      try {
        const dbState = await buildMigrationDatabaseState(migrations);

        // Record any SQL syntax failures gracefully
        for (const err of dbState.syntaxErrors) {
          allFindings.push({
            ruleId: 'SEC-MIG-PARSE-ERR',
            ruleTitle: 'SQL Migration Syntax Error',
            severity: 'medium',
            category: 'migrations',
            path: `${err.file}:${err.line}`,
            observedValue: err.message,
            rationale: `The migration "${err.file}" contains unparseable SQL syntax at line ${err.line}, column ${err.column}. Security analysis could not evaluate statements in this migration.`,
            policyAssumption:
              'Migration files must contain valid PostgreSQL syntax so security preflights can accurately evaluate database state.',
            remediation: 'Inspect and fix the SQL syntax error in the migration file.',
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

  const exitCode = passed ? ExitCode.SUCCESS : ExitCode.SECURITY_FINDINGS;

  return {
    targetPath: config.filePath,
    strict,
    timestamp: new Date().toISOString(),
    findings: allFindings,
    summary,
    exitCode,
  };
}
