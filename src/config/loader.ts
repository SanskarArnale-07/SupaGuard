import * as fs from 'node:fs';
import * as path from 'node:path';
import { sanitizeText } from '../reporter/mask.js';
import type { ConfigLoadResult } from '../types/config.js';
import { parseConfigToml } from './parser.js';

export interface LoadOptions {
  /**
   * Explicit path to config file or project directory.
   * If omitted, defaults to './supabase/config.toml' in the current working directory.
   */
  configPath?: string;
  /**
   * Base working directory for relative paths. Defaults to process.cwd().
   */
  cwd?: string;
}

/**
 * Resolves the target configuration path.
 *
 * Rules:
 * - If target is a directory, checks for `<dir>/supabase/config.toml`, then `<dir>/config.toml`.
 * - If target is a file, uses it directly.
 * - Default is `<cwd>/supabase/config.toml`.
 */
export function resolveConfigPath(options: LoadOptions = {}): string {
  const cwd = options.cwd ?? process.cwd();
  const rawTarget = options.configPath
    ? path.resolve(cwd, options.configPath)
    : path.resolve(cwd, 'supabase', 'config.toml');

  try {
    if (fs.existsSync(rawTarget)) {
      const stat = fs.statSync(rawTarget);
      if (stat.isDirectory()) {
        const nestedSupabase = path.join(rawTarget, 'supabase', 'config.toml');
        if (fs.existsSync(nestedSupabase)) {
          return nestedSupabase;
        }
        const directConfig = path.join(rawTarget, 'config.toml');
        if (fs.existsSync(directConfig)) {
          return directConfig;
        }
        // Fall back to expected standard path inside directory
        return nestedSupabase;
      }
      return rawTarget;
    }
  } catch {
    // If stat fails, return the resolved path so error handling can report it
  }

  return rawTarget;
}

/**
 * Loads and parses supabase/config.toml in a strictly read-only manner.
 *
 * Safety guarantees:
 * - Never modifies configuration files or the filesystem.
 * - Never reads .env files.
 * - Never makes any network calls.
 */
export function loadConfig(options: LoadOptions = {}): ConfigLoadResult {
  const filePath = resolveConfigPath(options);

  if (!fs.existsSync(filePath)) {
    return {
      success: false,
      error: {
        code: 'FILE_NOT_FOUND',
        message: `Configuration file not found at: ${filePath}. Ensure you are in a Supabase project root with a supabase/config.toml file, or specify --config <path>.`,
        filePath,
      },
    };
  }

  let rawContent: string;
  try {
    rawContent = fs.readFileSync(filePath, 'utf-8');
  } catch (err: unknown) {
    const errorObj = err as { message?: string };
    return {
      success: false,
      error: {
        code: 'READ_ERROR',
        message: `Failed to read configuration file: ${errorObj.message || 'Permission denied or unreadable file'}`,
        filePath,
      },
    };
  }

  const parseResult = parseConfigToml(rawContent);
  if (!parseResult.success) {
    const rawMsg = `Malformed TOML syntax in ${filePath}: ${parseResult.error.message}`;
    return {
      success: false,
      error: {
        code: 'INVALID_TOML',
        message: sanitizeText(rawMsg),
        filePath,
        line: parseResult.error.line,
        column: parseResult.error.column,
      },
    };
  }

  return {
    success: true,
    config: {
      filePath,
      rawContent,
      parsed: parseResult.data,
      explicitPaths: parseResult.explicitPaths,
    },
  };
}
