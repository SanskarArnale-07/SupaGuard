import * as fs from 'node:fs';
import * as path from 'node:path';
import type { MigrationFile } from './types.js';

export interface DiscoveryOptions {
  /** Explicit path to config file */
  configPath?: string;
  /** Explicit custom path to migrations directory */
  migrationsDir?: string;
  /** Working directory fallback */
  cwd?: string;
}

/**
 * Resolves the migrations directory path based on the config file or custom path.
 */
export function resolveMigrationsDir(options: DiscoveryOptions = {}): string | null {
  const cwd = options.cwd ?? process.cwd();

  // 1. Explicit custom migrations directory
  if (options.migrationsDir) {
    const resolvedCustom = path.resolve(cwd, options.migrationsDir);
    if (fs.existsSync(resolvedCustom)) {
      const stat = fs.statSync(resolvedCustom);
      if (stat.isDirectory()) {
        return resolvedCustom;
      }
    }
    return resolvedCustom; // Return resolved path even if missing so loader handles error
  }

  // 2. Derive from configPath
  if (options.configPath) {
    const resolvedConfig = path.resolve(cwd, options.configPath);
    const configDir = fs.existsSync(resolvedConfig) && fs.statSync(resolvedConfig).isDirectory()
      ? resolvedConfig
      : path.dirname(resolvedConfig);

    // If config is inside a supabase directory (e.g. <root>/supabase/config.toml)
    if (path.basename(configDir) === 'supabase') {
      const migrationsSubdir = path.join(configDir, 'migrations');
      if (fs.existsSync(migrationsSubdir) && fs.statSync(migrationsSubdir).isDirectory()) {
        return migrationsSubdir;
      }
    }

    // Check sibling or nested supabase/migrations
    const nestedMigrations = path.join(configDir, 'supabase', 'migrations');
    if (fs.existsSync(nestedMigrations) && fs.statSync(nestedMigrations).isDirectory()) {
      return nestedMigrations;
    }

    const directMigrations = path.join(configDir, 'migrations');
    if (fs.existsSync(directMigrations) && fs.statSync(directMigrations).isDirectory()) {
      return directMigrations;
    }
  }

  // 3. Fallback to standard cwd paths: ./supabase/migrations
  const standardPath = path.resolve(cwd, 'supabase', 'migrations');
  if (fs.existsSync(standardPath) && fs.statSync(standardPath).isDirectory()) {
    return standardPath;
  }

  return null;
}

/**
 * Discovers and loads SQL migration files in deterministic filename order.
 * Strictly read-only: never alters any file on disk.
 */
export function discoverMigrations(options: DiscoveryOptions = {}): MigrationFile[] {
  const dirPath = resolveMigrationsDir(options);
  if (!dirPath || !fs.existsSync(dirPath)) {
    return [];
  }

  try {
    const stat = fs.statSync(dirPath);
    if (!stat.isDirectory()) {
      return [];
    }
  } catch {
    return [];
  }

  let entries: string[] = [];
  try {
    entries = fs.readdirSync(dirPath);
  } catch {
    return [];
  }

  // Filter for .sql files only and sort deterministically
  const sqlFiles = entries
    .filter((name) => name.toLowerCase().endsWith('.sql'))
    .sort((a, b) => a.localeCompare(b));

  const cwd = options.cwd ?? process.cwd();
  const migrations: MigrationFile[] = [];

  for (const filename of sqlFiles) {
    const absolutePath = path.join(dirPath, filename);
    try {
      const stat = fs.statSync(absolutePath);
      if (!stat.isFile()) continue;

      const content = fs.readFileSync(absolutePath, 'utf-8');
      const relativePath = path.relative(cwd, absolutePath).replace(/\\/g, '/');

      migrations.push({
        filename,
        absolutePath,
        relativePath,
        content,
      });
    } catch {
      // Unreadable file: skip silently or handled by caller
      continue;
    }
  }

  return migrations;
}
