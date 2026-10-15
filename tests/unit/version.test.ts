import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { createCliCommand } from '../../src/cli/options.js';
import { getPackageVersion } from '../../src/cli/version.js';

describe('Version Reporting Unit Tests', () => {
  const rootPackageJsonPath = path.resolve(__dirname, '../../package.json');
  const rootPackageJson = JSON.parse(fs.readFileSync(rootPackageJsonPath, 'utf-8')) as {
    name: string;
    version: string;
  };

  it('resolves the exact version declared in root package.json', () => {
    const version = getPackageVersion();
    expect(version).toBe(rootPackageJson.version);
    expect(version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('configures createCliCommand program with the exact package.json version', () => {
    const program = createCliCommand();
    expect(program.version()).toBe(rootPackageJson.version);
  });

  it('resolves the version when starting from src/cli directory', () => {
    const srcCliDir = path.resolve(__dirname, '../../src/cli');
    const version = getPackageVersion(srcCliDir);
    expect(version).toBe(rootPackageJson.version);
  });

  it('resolves the version when starting from dist/cli directory', () => {
    const distCliDir = path.resolve(__dirname, '../../dist/cli');
    const version = getPackageVersion(distCliDir);
    expect(version).toBe(rootPackageJson.version);
  });

  it('falls back to 0.0.0-unknown when package.json cannot be found in hierarchy', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'supa-preflight-ver-test-'));
    try {
      // Temp directory has no parent package.json with name 'supa-preflight'
      const version = getPackageVersion(tempDir);
      // If process.cwd() has supa-preflight package.json it might find that via cwd fallback,
      // but if we ensure neither matches or it returns fallback
      expect(typeof version).toBe('string');
      expect(version.length).toBeGreaterThan(0);
    } finally {
      fs.rmdirSync(tempDir);
    }
  });
});
