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

describe('CLI End-to-End Test Suite', () => {
  const fixturesDir = path.resolve(__dirname, '../fixtures');

  it('runs against normal_secure fixture and exits with code 0', async () => {
    const configPath = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');
    const exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath]);
    expect(exitCode).toBe(ExitCode.SUCCESS);
  });

  it('runs against weakened_security fixture and exits with code 1', async () => {
    const configPath = path.join(fixturesDir, 'weakened_security', 'supabase', 'config.toml');
    const exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath]);
    expect(exitCode).toBe(ExitCode.SECURITY_FINDINGS);
  });

  it('runs against missing_optional fixture and exits with code 0', async () => {
    const configPath = path.join(fixturesDir, 'missing_optional', 'supabase', 'config.toml');
    const exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath]);
    expect(exitCode).toBe(ExitCode.SUCCESS);
  });

  it('returns code 2 for a non-existent configuration file', async () => {
    const nonExistentPath = path.join(fixturesDir, 'ghost_dir', 'supabase', 'config.toml');
    const exitCode = await runCli(['node', 'supaguard', 'check', '--config', nonExistentPath]);
    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);
  });

  it('returns code 2 for invalid malformed TOML syntax', async () => {
    const invalidPath = path.join(fixturesDir, 'invalid_toml', 'supabase', 'config.toml');
    const exitCode = await runCli(['node', 'supaguard', 'check', '--config', invalidPath]);
    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);
  });

  it('runs against unknown_fields fixture without crashing', async () => {
    const unknownPath = path.join(fixturesDir, 'unknown_fields', 'supabase', 'config.toml');
    const exitCode = await runCli(['node', 'supaguard', 'check', '--config', unknownPath]);
    expect(exitCode).toBe(ExitCode.SUCCESS);
  });

  it('runs against env_vars fixture and does not flag env() references as secrets', async () => {
    const envVarsPath = path.join(fixturesDir, 'env_vars', 'supabase', 'config.toml');
    const exitCode = await runCli(['node', 'supaguard', 'check', '--config', envVarsPath]);
    expect(exitCode).toBe(ExitCode.SUCCESS);
  });

  it('detects plaintext secrets and never exposes raw secrets in output', async () => {
    const secretsPath = path.join(fixturesDir, 'plaintext_secrets', 'supabase', 'config.toml');

    let capturedOutput = '';
    const originalWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      capturedOutput += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', secretsPath, '--format', 'json']);
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(exitCode).toBe(ExitCode.SECURITY_FINDINGS);

    // Verify valid JSON
    const parsed = JSON.parse(capturedOutput);
    expect(parsed.summary.critical).toBeGreaterThan(0);

    // Verify raw secrets are strictly redacted
    expect(capturedOutput).not.toContain('FAKE_TEST_SECRET_DO_NOT_USE');
    expect(capturedOutput).not.toContain('FAKE_TEST_SECRET_DO_NOT_USE_GITHUB');
    expect(capturedOutput).not.toContain('FAKE_TEST_SECRET_DO_NOT_USE_OPENAI');
    expect(capturedOutput).not.toContain('FAKE_TEST_SECRET_DO_NOT_USE_SMTP');
    expect(capturedOutput).not.toContain('FAKE_TEST_SECRET_DO_NOT_USE_S3');
    expect(capturedOutput).toContain('[REDACTED_SECRET');
  });

  it('supports --format json emitting valid machine-readable JSON matching the schema', async () => {
    const configPath = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');

    let stdoutData = '';
    const originalWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      stdoutData += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath, '--format', 'json']);
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(exitCode).toBe(ExitCode.SUCCESS);
    const parsed = JSON.parse(stdoutData);
    expect(parsed).toHaveProperty('targetPath');
    expect(parsed).toHaveProperty('summary');
    expect(parsed).toHaveProperty('findings');
    expect(parsed.summary.passed).toBe(true);
    expect(parsed.exitCode).toBe(ExitCode.SUCCESS);
  });

  it('enforces --strict mode by failing on non-blocking findings', async () => {
    // normal_secure has 0 findings so it passes even in strict mode
    const normalPath = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');
    const normalStrictCode = await runCli([
      'node',
      'supaguard',
      'check',
      '--config',
      normalPath,
      '--strict',
    ]);
    expect(normalStrictCode).toBe(ExitCode.SUCCESS);

    // conflicting_auth has medium findings: in standard mode fails or in strict mode fails
    const conflictingPath = path.join(fixturesDir, 'conflicting_auth', 'supabase', 'config.toml');
    const strictCode = await runCli([
      'node',
      'supaguard',
      'check',
      '--config',
      conflictingPath,
      '--strict',
    ]);
    expect(strictCode).toBe(ExitCode.SECURITY_FINDINGS);
  });

  it('guarantees zero modifications to inspected files (safety requirement)', async () => {
    const testFile = path.join(fixturesDir, 'weakened_security', 'supabase', 'config.toml');
    const hashBefore = computeFileHash(testFile);

    await runCli(['node', 'supaguard', 'check', '--config', testFile]);

    const hashAfter = computeFileHash(testFile);
    expect(hashAfter).toBe(hashBefore);
  });

  it('guarantees JSON output never exposes raw credentials when parsing fails', async () => {
    const invalidSecretPath = path.join(fixturesDir, 'invalid_toml_with_secret', 'supabase', 'config.toml');

    let capturedStdout = '';
    const originalWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      capturedStdout += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', invalidSecretPath, '--format', 'json']);
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);

    // Verify valid JSON is emitted
    const parsed = JSON.parse(capturedStdout);
    expect(parsed.success).toBe(false);
    expect(parsed.error.code).toBe('INVALID_TOML');

    // CRITICAL: Raw leaked secret MUST NOT appear anywhere in the output!
    expect(capturedStdout).not.toContain('ghp_leaked_secret_token_12345');
    expect(capturedStdout).toContain('[REDACTED_SECRET]');
  });

  it('guarantees text error output never exposes raw credentials when parsing fails', async () => {
    const invalidSecretPath = path.join(fixturesDir, 'invalid_toml_with_secret', 'supabase', 'config.toml');

    let capturedStderr = '';
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk: unknown) => {
      capturedStderr += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', invalidSecretPath]);
    } finally {
      process.stderr.write = originalWrite;
    }

    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);

    // CRITICAL: Raw leaked secret MUST NOT appear in stderr!
    expect(capturedStderr).not.toContain('ghp_leaked_secret_token_12345');
    expect(capturedStderr).toContain('[REDACTED_SECRET]');
  });

  it('supports --advisory mode by reporting findings but exiting with code 0', async () => {
    const configPath = path.join(fixturesDir, 'weakened_security', 'supabase', 'config.toml');

    let capturedStdout = '';
    const originalWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: unknown) => {
      capturedStdout += String(chunk);
      return true;
    };

    let exitCode: number;
    try {
      exitCode = await runCli(['node', 'supaguard', 'check', '--config', configPath, '--advisory']);
    } finally {
      process.stdout.write = originalWrite;
    }

    // In advisory mode, findings are reported but process exits with code 0
    expect(exitCode).toBe(ExitCode.SUCCESS);
    expect(capturedStdout).toContain('PREFLIGHT ADVISORY');
    expect(capturedStdout).toContain('SEC-AUTH-001');
  });

  it('supports --advisory mode with JSON format emitting advisory flag and exitCode 0', async () => {
    const configPath = path.join(fixturesDir, 'weakened_security', 'supabase', 'config.toml');

    let capturedStdout = '';
    const originalWrite = process.stdout.write.bind(process.stdout);
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
        '--advisory',
        '--format',
        'json',
      ]);
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(exitCode).toBe(ExitCode.SUCCESS);
    const parsed = JSON.parse(capturedStdout);
    expect(parsed.advisory).toBe(true);
    expect(parsed.exitCode).toBe(ExitCode.SUCCESS);
    expect(parsed.summary.passed).toBe(false);
    expect(parsed.summary.high).toBeGreaterThan(0);
    expect(parsed.findings.length).toBeGreaterThan(0);
  });

  it('preserves code 2 (CONFIG_ERROR) in --advisory mode when config file is missing', async () => {
    const nonExistentPath = path.join(fixturesDir, 'ghost_dir', 'supabase', 'config.toml');
    const exitCode = await runCli([
      'node',
      'supaguard',
      'check',
      '--config',
      nonExistentPath,
      '--advisory',
    ]);
    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);
  });

  it('preserves code 2 (CONFIG_ERROR) in --advisory mode when config has invalid TOML', async () => {
    const invalidPath = path.join(fixturesDir, 'invalid_toml', 'supabase', 'config.toml');
    const exitCode = await runCli([
      'node',
      'supaguard',
      'check',
      '--config',
      invalidPath,
      '--advisory',
    ]);
    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);
  });

  it('rejects combining --advisory and --strict options with exit code 2 (CONFIG_ERROR) in text mode', async () => {
    const configPath = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');

    let capturedStderr = '';
    const originalWrite = process.stderr.write.bind(process.stderr);
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
        '--strict',
        '--advisory',
      ]);
    } finally {
      process.stderr.write = originalWrite;
    }

    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);
    expect(capturedStderr).toContain('Cannot combine --advisory and --strict options');
    expect(capturedStderr).toContain('mutually exclusive');
  });

  it('rejects combining --advisory and --strict options with exit code 2 and structured error in JSON mode', async () => {
    const configPath = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');

    let capturedStdout = '';
    const originalWrite = process.stdout.write.bind(process.stdout);
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
        '--strict',
        '--advisory',
        '--format',
        'json',
      ]);
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(exitCode).toBe(ExitCode.CONFIG_ERROR);
    const parsed = JSON.parse(capturedStdout);
    expect(parsed.success).toBe(false);
    expect(parsed.error.code).toBe('CONFLICTING_OPTIONS');
    expect(parsed.error.message).toContain('Cannot combine --advisory and --strict');
    expect(parsed.exitCode).toBe(ExitCode.CONFIG_ERROR);
  });
});
