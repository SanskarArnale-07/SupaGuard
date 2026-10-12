/**
 * Represents a parsed and validated Supabase configuration in memory.
 */
export interface LoadedConfig {
  /** Absolute or relative path to the inspected config.toml */
  filePath: string;
  /** Raw content of the TOML file (read-only) */
  rawContent: string;
  /** Parsed JSON representation from TOML parser */
  parsed: Record<string, unknown>;
  /** Set of explicit dot-separated property paths present in the file */
  explicitPaths: Set<string>;
}

/**
 * Result of attempting to load and parse a config file.
 */
export type ConfigLoadResult =
  | { success: true; config: LoadedConfig }
  | {
      success: false;
      error: {
        code: 'FILE_NOT_FOUND' | 'READ_ERROR' | 'INVALID_TOML';
        message: string;
        filePath: string;
        line?: number;
        column?: number;
      };
    };
