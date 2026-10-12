import { createRuleContext } from '../config/context.js';
import { defaultRegistry } from '../rules/index.js';
import { RuleRegistry } from '../rules/registry.js';
import { ExitCode } from '../types/exit-codes.js';
import type { LoadedConfig } from '../types/config.js';
import type { AnalysisResult, ReportSummary } from '../types/report.js';
import type { Finding, Severity } from '../types/rule.js';

export interface AnalyzerOptions {
  registry?: RuleRegistry;
  strict?: boolean;
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Executes registered security rules against a loaded configuration and generates an AnalysisResult.
 */
export function analyzeConfig(config: LoadedConfig, options: AnalyzerOptions = {}): AnalysisResult {
  const registry = options.registry ?? defaultRegistry;
  const strict = options.strict ?? false;

  const context = createRuleContext(config.parsed, config.explicitPaths);
  const rules = registry.getAll();

  const allFindings: Finding[] = [];

  for (const rule of rules) {
    try {
      const findings = rule.check(context);
      if (findings && Array.isArray(findings)) {
        allFindings.push(...findings);
      }
    } catch (err: unknown) {
      // In case an unexpected exception occurs inside a rule, encapsulate safely
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
    totalRulesEvaluated: rules.length,
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
