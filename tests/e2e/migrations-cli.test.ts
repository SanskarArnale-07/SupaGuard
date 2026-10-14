import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { runCli } from '../../src/cli/index.js';
import { ExitCode } from '../../src/types/exit-codes.js';

function computeFileHash(filePath: string): string {
  const fileBuffer = fs.readFileSync(filePath);
  const hashSum = crypto.createHash('sha256');
  hashSum.update(fileBuffer);
  return hashSum.digest('hex');
}

describe('SQL Migration End-to-End CLI Suite', () => {
  const fixturesDir = path.resolve(__dirname, '../fixtures');

  it('runs against secure_with_migrations fixture and passes in standard mode (exit 0)', async () => {
    const configPath = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');

    let output = '';
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      output += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath]);
    } finally {
      process.stdout.write = origWrite;
    }

    // In standard mode, only critical and high findings trigger exit 1.
    // secure_with_migrations only has an INFO finding for public read blog posts.
    expect(exitCode).toBe(ExitCode.SUCCESS);
    expect(output).toContain('PREFLIGHT PASSED');
    expect(output).toContain('Public Read Access Allowed by RLS Policy');
  });

  it('fails secure_with_migrations in --strict mode due to the INFO advisory (exit 1)', async () => {
    const configPath = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
    const exitCode = await runCli([
      'node',
      'supaguard',
      'check',
      '--config',
      configPath,
      '--strict',
    ]);
    expect(exitCode).toBe(ExitCode.SECURITY_FINDINGS);
  });

  it('runs against insecure_migrations fixture and detects all defects (exit 1)', async () => {
    const configPath = path.join(fixturesDir, 'insecure_migrations', 'supabase', 'config.toml');

    let capturedOutput = '';
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      capturedOutput += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath]);
    } finally {
      process.stdout.write = origWrite;
    }

    expect(exitCode).toBe(ExitCode.SECURITY_FINDINGS);
    expect(capturedOutput).toContain('PREFLIGHT FAILED');

    // Rule SEC-MIG-RLS-001 findings
    expect(capturedOutput).toContain('SEC-MIG-RLS-001');
    expect(capturedOutput).toContain('public.unprotected_orders');
    expect(capturedOutput).toContain('public.accounts');

    // Rule SEC-MIG-RLS-002 findings
    expect(capturedOutput).toContain('SEC-MIG-RLS-002');
    expect(capturedOutput).toContain('Anon open insert');
    expect(capturedOutput).toContain('Public open access');
    expect(capturedOutput).toContain('Items write');
  });

  it('outputs valid, structured JSON including migration metadata and locations', async () => {
    const configPath = path.join(fixturesDir, 'insecure_migrations', 'supabase', 'config.toml');

    let jsonOutput = '';
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      jsonOutput += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath, '--format', 'json']);
    } finally {
      process.stdout.write = origWrite;
    }

    expect(exitCode).toBe(ExitCode.SECURITY_FINDINGS);

    const report = JSON.parse(jsonOutput);
    expect(report.summary.passed).toBe(false);
    expect(report.summary.high).toBeGreaterThanOrEqual(4); // 2 missing RLS + 2 unrestricted write

    const migrationFindings = report.findings.filter((f: any) => f.category === 'migrations');
    expect(migrationFindings.length).toBeGreaterThan(0);

    const unprotected = migrationFindings.find((f: any) => f.table === 'unprotected_orders');
    expect(unprotected).toBeDefined();
    expect(unprotected.ruleId).toBe('SEC-MIG-RLS-001');
    expect(unprotected.schema).toBe('public');
    expect(unprotected.filePath).toContain('20240101000000_missing_rls.sql');
    expect(typeof unprotected.line).toBe('number');
  });

  it('handles malformed migration SQL gracefully without crashing (records diagnostic finding and fails standard mode)', async () => {
    const configPath = path.join(fixturesDir, 'malformed_migration', 'supabase', 'config.toml');

    let capturedStderr = '';
    let capturedStdout = '';
    const origStdout = process.stdout.write.bind(process.stdout);
    const origStderr = process.stderr.write.bind(process.stderr);

    process.stdout.write = (chunk: unknown) => {
      capturedStdout += String(chunk);
      return true;
    };
    process.stderr.write = (chunk: unknown) => {
      capturedStderr += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath]);
    } finally {
      process.stdout.write = origStdout;
      process.stderr.write = origStderr;
    }

    // High severity finding MUST trigger exit 1 in standard mode (cannot pass exit 0 with unparseable SQL)
    expect(exitCode).toBe(ExitCode.SECURITY_FINDINGS);
    expect(capturedStdout).toContain('PREFLIGHT FAILED');
    expect(capturedStdout).toContain('SEC-MIG-PARSE-ERR');
    expect(capturedStdout).toContain('SQL Migration Syntax Error');
    expect(capturedStdout).toContain('20240101000000_syntax_error.sql:3');
    expect(capturedStdout).toContain('incomplete');
  });

  it('aborts with exit code 2 (CONFIG_ERROR) when explicit --migrations directory does not exist', async () => {
    const configPath = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
    let capturedStderr = '';
    const origStderr = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk: unknown) => {
      capturedStderr += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli([
        'node',
        'supaguard',
        'check',
        '--config',
        configPath,
        '--migrations',
        './nonexistent_migrations_dir_12345',
      ]);
    } finally {
      process.stderr.write = origStderr;
    }

    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);
    expect(capturedStderr).toContain('Explicit migrations directory not found');
  });

  it('aborts with exit code 2 (CONFIG_ERROR) when explicit --migrations path is a file', async () => {
    const configPath = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
    let capturedStderr = '';
    const origStderr = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk: unknown) => {
      capturedStderr += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli([
        'node',
        'supaguard',
        'check',
        '--config',
        configPath,
        '--migrations',
        configPath,
      ]);
    } finally {
      process.stderr.write = origStderr;
    }

    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);
    expect(capturedStderr).toContain('Explicit migrations path is not a directory');
  });

  it('outputs JSON error with exit code 2 when explicit --migrations path is missing in JSON mode', async () => {
    const configPath = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
    let capturedStdout = '';
    const origStdout = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      capturedStdout += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli([
        'node',
        'supaguard',
        'check',
        '--config',
        configPath,
        '--migrations',
        './nonexistent_migrations_dir_json',
        '--format',
        'json',
      ]);
    } finally {
      process.stdout.write = origStdout;
    }

    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);
    const parsed = JSON.parse(capturedStdout);
    expect(parsed.success).toBe(false);
    expect(parsed.error.code).toBe('MIGRATIONS_DIR_NOT_FOUND');
    expect(parsed.exitCode).toBe(ExitCode.CONFIG_ERROR);
  });

  it('guarantees zero modifications to inspected SQL migration files (read-only safety invariant)', async () => {
    const migrationsDir = path.join(fixturesDir, 'insecure_migrations', 'supabase', 'migrations');
    const files = fs.readdirSync(migrationsDir).filter((f) => f.endsWith('.sql'));

    const hashesBefore = new Map<string, string>();
    for (const f of files) {
      const fullPath = path.join(migrationsDir, f);
      hashesBefore.set(f, computeFileHash(fullPath));
    }

    const configPath = path.join(fixturesDir, 'insecure_migrations', 'supabase', 'config.toml');
    await runCli(['node', 'supaguard', 'check', '--config', configPath]);

    for (const f of files) {
      const fullPath = path.join(migrationsDir, f);
      const hashAfter = computeFileHash(fullPath);
      expect(hashAfter).toBe(hashesBefore.get(f));
    }
  });

  it('runs against insecure_migrations in --advisory mode and exits with code 0 while reporting findings', async () => {
    const configPath = path.join(fixturesDir, 'insecure_migrations', 'supabase', 'config.toml');

    let capturedOutput = '';
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      capturedOutput += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath, '--advisory']);
    } finally {
      process.stdout.write = origWrite;
    }

    expect(exitCode).toBe(ExitCode.SUCCESS);
    expect(capturedOutput).toContain('PREFLIGHT ADVISORY');
    expect(capturedOutput).toContain('SEC-MIG-RLS-001');
    expect(capturedOutput).toContain('SEC-MIG-RLS-002');
  });

  it('refuses to exit 0 in --advisory mode when a migration contains a SQL syntax error (SEC-MIG-PARSE-ERR)', async () => {
    const configPath = path.join(fixturesDir, 'malformed_migration', 'supabase', 'config.toml');

    let capturedStdout = '';
    const origStdout = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      capturedStdout += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath, '--advisory']);
    } finally {
      process.stdout.write = origStdout;
    }

    // Crucial guarantee: execution/syntax failures MUST NOT be masked by advisory mode!
    expect(exitCode).toBe(ExitCode.SECURITY_FINDINGS);
    expect(capturedStdout).toContain('PREFLIGHT FAILED');
    expect(capturedStdout).toContain('SEC-MIG-PARSE-ERR');
  });
});
