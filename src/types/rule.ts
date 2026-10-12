/**
 * Severity levels for SupaGuard findings.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Functional domain categories for Supabase configuration.
 */
export type RuleCategory =
  | 'auth'
  | 'api'
  | 'database'
  | 'functions'
  | 'secrets'
  | 'storage';

/**
 * A security finding produced by an active rule.
 */
export interface Finding {
  /** Unique rule identifier, e.g. 'SEC-AUTH-001' */
  ruleId: string;
  /** Human-readable title of the rule */
  ruleTitle: string;
  /** Severity level */
  severity: Severity;
  /** Category */
  category: RuleCategory;
  /** Exact configuration path, e.g. 'auth.enable_refresh_token_rotation' */
  path: string;
  /** Observed value as a safe string (sensitive values masked) */
  observedValue: string;
  /** Detailed rationale explaining why this setting is security-sensitive */
  rationale: string;
  /** Explicit policy assumption made by this rule */
  policyAssumption: string;
  /** Actionable remediation advice */
  remediation: string;
}

/**
 * Context provided to each rule during evaluation.
 */
export interface RuleContext {
  /** Raw parsed TOML object (nested dictionary) */
  rawConfig: Record<string, unknown>;
  /** Set of all dot-separated paths explicitly present in the config file */
  explicitPaths: Set<string>;
  /**
   * Helper to check if a dot-separated path was explicitly set in the config file.
   * Differentiates explicitly configured values from missing/default values.
   */
  hasExplicitPath: (dotPath: string) => boolean;
  /**
   * Helper to safely retrieve an explicitly configured value.
   * Returns undefined if the key was not explicitly present.
   */
  getExplicitValue: <T = unknown>(dotPath: string) => T | undefined;
  /**
   * Helper to get all keys or sub-objects matching a wildcard or prefix.
   */
  getSection: <T = Record<string, unknown>>(sectionPath: string) => T | undefined;
}

/**
 * Definition of an individual, testable security rule.
 */
export interface SecurityRule {
  /** Unique rule identifier, e.g. 'SEC-AUTH-001' */
  id: string;
  /** Short human-readable title */
  title: string;
  /** Category of the rule */
  category: RuleCategory;
  /** Base severity level */
  severity: Severity;
  /** High-level description of what this rule verifies */
  description: string;
  /** Explicit policy assumption */
  policyAssumption: string;
  /** Evaluate the configuration context and return zero or more findings */
  check: (context: RuleContext) => Finding[];
}
