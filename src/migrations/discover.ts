import * as fs from 'node:fs';
import * as path from 'node:path';
import type { MigrationFile, UnreadableMigrationFile, MigrationDiscoveryError } from './types.js';

export interface DiscoveryOptions {
  /** Explicit path to config file */
  configPath?: string;
  /** Explicit custom path to migrations directory */
  migrationsDir?: string;
  /** Working directory fallback */
  cwd?: string;
  /** Custom readFileSync for dependency injection / portable testing */
  readFileSync?: (filePath: string, encoding: 'utf-8') => string;
  /** Custom readdirSync for dependency injection / portable testing */
  readdirSync?: (dirPath: string) => string[];
  /** Custom statSync for dependency injection / portable testing */
  statSync?: (targetPath: string) => fs.Stats;
  /** Custom existsSync for dependency injection / portable testing */
  existsSync?: (targetPath: string) => boolean;
}

export interface DiscoveryResult {
  migrations: MigrationFile[];
  readErrors: UnreadableMigrationFile[];
  discoveryErrors: MigrationDiscoveryError[];
}

/**
 * Resolves the migrations directory path based on the config file or custom path.
 * Throws a descriptive Error if an explicit migrationsDir does not exist or is not a directory.
 */
export function resolveMigrationsDir(options: DiscoveryOptions = {}): string | null {
  const cwd = options.cwd ?? process.cwd();
  const existsFn = options.existsSync ?? fs.existsSync;
  const statFn = options.statSync ?? fs.statSync;

  // 1. Explicit custom migrations directory: strictly validate
  if (options.migrationsDir) {
    const resolvedCustom = path.resolve(cwd, options.migrationsDir);
    if (!existsFn(resolvedCustom)) {
      throw new Error(`Explicit migrations directory not found: "${options.migrationsDir}"`);
    }
    const stat = statFn(resolvedCustom);
    if (!stat.isDirectory()) {
      throw new Error(`Explicit migrations path is not a directory: "${options.migrationsDir}"`);
    }
    return resolvedCustom;
  }

  // 2. Derive from configPath
  if (options.configPath) {
    const resolvedConfig = path.resolve(cwd, options.configPath);
    let configDir: string;
    try {
      configDir = existsFn(resolvedConfig) && statFn(resolvedConfig).isDirectory()
        ? resolvedConfig
        : path.dirname(resolvedConfig);
    } catch {
      configDir = path.dirname(resolvedConfig);
    }

    // If config is inside a supabase directory (e.g. <root>/supabase/config.toml)
    if (path.basename(configDir) === 'supabase') {
      const migrationsSubdir = path.join(configDir, 'migrations');
      if (existsFn(migrationsSubdir)) {
        return migrationsSubdir;
      }
    }

    // Check sibling or nested supabase/migrations
    const nestedMigrations = path.join(configDir, 'supabase', 'migrations');
    if (existsFn(nestedMigrations)) {
      return nestedMigrations;
    }

    const directMigrations = path.join(configDir, 'migrations');
    if (existsFn(directMigrations)) {
      return directMigrations;
    }
  }

  // 3. Fallback to standard cwd paths: ./supabase/migrations
  const standardPath = path.resolve(cwd, 'supabase', 'migrations');
  if (existsFn(standardPath)) {
    return standardPath;
  }

  return null;
}

/**
 * Discovers and loads SQL migration files in deterministic filename order.
 * Tracks and preserves diagnostics for any unreadable migration files.
 * Strictly read-only: never alters any file on disk.
 */
export function discoverMigrations(
  options: DiscoveryOptions = {}
): MigrationFile[] & {
  readErrors: UnreadableMigrationFile[];
  discoveryErrors: MigrationDiscoveryError[];
} {
  const dirPath = resolveMigrationsDir(options);
  const existsFn = options.existsSync ?? fs.existsSync;
  const statFn = options.statSync ?? fs.statSync;
  const readdirFn = options.readdirSync ?? fs.readdirSync;
  const readFn = options.readFileSync ?? fs.readFileSync;
  const cwd = options.cwd ?? process.cwd();

  const makeResult = (
    migs: MigrationFile[],
    reads: UnreadableMigrationFile[],
    discErrors: MigrationDiscoveryError[]
  ): MigrationFile[] & {
    readErrors: UnreadableMigrationFile[];
    discoveryErrors: MigrationDiscoveryError[];
  } => {
    Object.defineProperty(migs, 'readErrors', {
      value: reads,
      enumerable: false,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(migs, 'discoveryErrors', {
      value: discErrors,
      enumerable: false,
      writable: true,
      configurable: true,
    });
    return migs as MigrationFile[] & {
      readErrors: UnreadableMigrationFile[];
      discoveryErrors: MigrationDiscoveryError[];
    };
  };

  if (!dirPath || !existsFn(dirPath)) {
    return makeResult([], [], []);
  }

  try {
    const stat = statFn(dirPath);
    if (!stat.isDirectory()) {
      return makeResult([], [], [
        {
          dirPath,
          error: `Identified migrations path is not a directory: "${dirPath}"`,
        },
      ]);
    }
  } catch (err: unknown) {
    const errObj = err as { code?: string; message?: string };
    const errMessage = errObj.code ? `${errObj.code}: permission or inspection error` : errObj.message || 'Inspection error';
    return makeResult([], [], [
      {
        dirPath,
        error: `Cannot inspect migrations directory: ${errMessage}`,
      },
    ]);
  }

  let entries: string[] = [];
  try {
    entries = readdirFn(dirPath);
  } catch (err: unknown) {
    const errObj = err as { code?: string; message?: string };
    const errMessage = errObj.code ? `${errObj.code}: permission or listing error` : errObj.message || 'Listing error';
    return makeResult([], [], [
      {
        dirPath,
        error: `Cannot list migrations directory: ${errMessage}`,
      },
    ]);
  }

  // Filter for .sql files only and sort deterministically
  const sqlFiles = entries
    .filter((name) => name.toLowerCase().endsWith('.sql'))
    .sort((a, b) => a.localeCompare(b));

  const migrations: MigrationFile[] = [];
  const readErrors: UnreadableMigrationFile[] = [];

  for (const filename of sqlFiles) {
    const absolutePath = path.join(dirPath, filename);
    const relativePath = path.relative(cwd, absolutePath).replace(/\\/g, '/');

    try {
      const stat = statFn(absolutePath);
      if (!stat.isFile()) continue;

      const content = readFn(absolutePath, 'utf-8');

      migrations.push({
        filename,
        absolutePath,
        relativePath,
        content,
      });
    } catch (err: unknown) {
      const errObj = err as { code?: string; message?: string };
      const errMessage = errObj.code ? `${errObj.code}: permission or read error` : errObj.message || 'Read error';
      readErrors.push({
        filename,
        absolutePath,
        relativePath,
        error: `Cannot read file: ${errMessage}`,
      });
    }
  }

  return makeResult(migrations, readErrors, []);
}

/**
 * Convenience helper returning discovered migrations, read errors, and discovery errors explicitly.
 */
export function discoverMigrationsWithDiagnostics(options: DiscoveryOptions = {}): DiscoveryResult {
  const res = discoverMigrations(options);
  return {
    migrations: [...res],
    readErrors: [...res.readErrors],
    discoveryErrors: [...res.discoveryErrors],
  };
}
