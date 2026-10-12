// Core Analyzer
export { analyzeConfig, type AnalyzerOptions } from './analyzer/index.js';

// Configuration
export { loadConfig, resolveConfigPath, type LoadOptions } from './config/loader.js';
export { parseConfigToml, collectExplicitPaths, type TomlParseResult } from './config/parser.js';
export { createRuleContext, getByPath } from './config/context.js';

// Rules & Registry
export { RuleRegistry, defaultRegistry } from './rules/registry.js';
export { ALL_BUILTIN_RULES } from './rules/index.js';
export * from './rules/index.js';
export * from './rules/migrations/index.js';

// SQL Migrations
export * from './migrations/index.js';

// Reporters & Formatting
export { formatReport, formatJsonReport, formatTextReport } from './reporter/index.js';
export { maskSensitiveValue, isEnvVarReference, extractEnvVarName, isSensitivePath } from './reporter/mask.js';

// Types
export { ExitCode, type ExitCodeValue } from './types/exit-codes.js';
export type { LoadedConfig, ConfigLoadResult } from './types/config.js';
export type {
  Severity,
  RuleCategory,
  Finding,
  RuleContext,
  SecurityRule,
} from './types/rule.js';
export type {
  ReportFormat,
  ReportSummary,
  AnalysisResult,
} from './types/report.js';

// CLI
export { runCli } from './cli/index.js';
