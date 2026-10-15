import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Resolves the version of supa-preflight from the package.json file.
 * Traverses upwards from the module directory to reliably locate the package root
 * in both development (src/cli) and compiled distribution (dist/cli) environments.
 *
 * @param fromDir - Optional directory to start the upward search from (defaults to __dirname or process.cwd()).
 * @returns The version string from package.json, or '0.0.0-unknown' if not found.
 */
export function getPackageVersion(fromDir?: string): string {
  try {
    const startDir = fromDir ?? (typeof __dirname !== 'undefined' ? __dirname : process.cwd());

    // 1. Direct check: package.json is 2 levels up from src/cli or dist/cli
    const directPkgPath = path.resolve(startDir, '..', '..', 'package.json');
    if (fs.existsSync(directPkgPath)) {
      try {
        const content = fs.readFileSync(directPkgPath, 'utf-8');
        const parsed = JSON.parse(content) as { name?: string; version?: string };
        if (typeof parsed.version === 'string' && parsed.version.length > 0) {
          if (parsed.name === 'supa-preflight' || !parsed.name) {
            return parsed.version;
          }
        }
      } catch {
        // Fall through to upward traversal
      }
    }

    // 2. Upward directory traversal search for package.json belonging to supa-preflight
    let currentDir = startDir;
    while (currentDir) {
      const candidatePath = path.join(currentDir, 'package.json');
      if (fs.existsSync(candidatePath)) {
        try {
          const content = fs.readFileSync(candidatePath, 'utf-8');
          const parsed = JSON.parse(content) as { name?: string; version?: string };
          if (parsed.name === 'supa-preflight' && typeof parsed.version === 'string' && parsed.version.length > 0) {
            return parsed.version;
          }
        } catch {
          // Continue walk
        }
      }

      const parentDir = path.dirname(currentDir);
      if (parentDir === currentDir) {
        break;
      }
      currentDir = parentDir;
    }

    // 3. Fallback: check process.cwd() package.json if it is supa-preflight
    const cwdPkgPath = path.resolve(process.cwd(), 'package.json');
    if (fs.existsSync(cwdPkgPath)) {
      try {
        const content = fs.readFileSync(cwdPkgPath, 'utf-8');
        const parsed = JSON.parse(content) as { name?: string; version?: string };
        if (parsed.name === 'supa-preflight' && typeof parsed.version === 'string' && parsed.version.length > 0) {
          return parsed.version;
        }
      } catch {
        // Fall through
      }
    }
  } catch {
    // Return fallback below
  }

  return '0.0.0-unknown';
}
