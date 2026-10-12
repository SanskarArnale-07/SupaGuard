import { parse as parseToml } from 'smol-toml';

export interface TomlParseSuccess {
  success: true;
  data: Record<string, unknown>;
  explicitPaths: Set<string>;
}

export interface TomlParseError {
  success: false;
  error: {
    message: string;
    line?: number;
    column?: number;
  };
}

export type TomlParseResult = TomlParseSuccess | TomlParseError;

/**
 * Traverses a parsed TOML object to collect all explicit dot-separated paths.
 */
export function collectExplicitPaths(
  obj: unknown,
  prefix = '',
  paths: Set<string> = new Set()
): Set<string> {
  if (obj === null || obj === undefined) {
    return paths;
  }

  if (typeof obj === 'object' && !Array.isArray(obj)) {
    const record = obj as Record<string, unknown>;
    for (const [key, value] of Object.entries(record)) {
      const currentPath = prefix ? `${prefix}.${key}` : key;
      paths.add(currentPath);

      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        collectExplicitPaths(value, currentPath, paths);
      } else if (Array.isArray(value)) {
        // Collect array children if they are objects
        value.forEach((item, index) => {
          if (typeof item === 'object' && item !== null) {
            collectExplicitPaths(item, `${currentPath}[${index}]`, paths);
          }
        });
      }
    }
  }

  return paths;
}

/**
 * Safely parses a TOML string into an object and extracts all explicitly defined keys.
 */
export function parseConfigToml(tomlContent: string): TomlParseResult {
  try {
    const data = parseToml(tomlContent) as Record<string, unknown>;
    const explicitPaths = collectExplicitPaths(data);
    return {
      success: true,
      data,
      explicitPaths,
    };
  } catch (err: unknown) {
    const errorObj = err as { message?: string; line?: number; column?: number };
    return {
      success: false,
      error: {
        message: errorObj.message || 'Unknown TOML parsing error',
        line: errorObj.line,
        column: errorObj.column,
      },
    };
  }
}
