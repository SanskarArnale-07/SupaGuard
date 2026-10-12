import type { RuleContext } from '../types/rule.js';

/**
 * Safely traverses a nested object by dot-separated path.
 */
export function getByPath<T = unknown>(obj: Record<string, unknown>, dotPath: string): T | undefined {
  if (!obj || typeof obj !== 'object') return undefined;

  const parts = dotPath.split('.');
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }

  return current as T;
}

/**
 * Creates a RuleContext from parsed configuration and its explicit path set.
 */
export function createRuleContext(
  rawConfig: Record<string, unknown>,
  explicitPaths: Set<string>
): RuleContext {
  return {
    rawConfig,
    explicitPaths,
    hasExplicitPath: (dotPath: string) => explicitPaths.has(dotPath),
    getExplicitValue: <T = unknown>(dotPath: string): T | undefined => {
      if (!explicitPaths.has(dotPath)) {
        return undefined;
      }
      return getByPath<T>(rawConfig, dotPath);
    },
    getSection: <T = Record<string, unknown>>(sectionPath: string): T | undefined => {
      const section = getByPath<T>(rawConfig, sectionPath);
      if (section && typeof section === 'object' && !Array.isArray(section)) {
        return section;
      }
      return undefined;
    },
  };
}
