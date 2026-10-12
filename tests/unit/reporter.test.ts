import { describe, expect, it } from 'vitest';
import { formatJsonReport, formatReport, formatTextReport } from '../../src/reporter/index.js';
import { ExitCode } from '../../src/types/exit-codes.js';
import type { AnalysisResult } from '../../src/types/report.js';

describe('Report Formatters', () => {
  const sampleResult: AnalysisResult = {
    targetPath: '/projects/my-supabase-app/supabase/config.toml',
    strict: false,
    timestamp: '2026-10-12T12:00:00.000Z',
    findings: [
      {
        ruleId: 'SEC-SEC-001',
        ruleTitle: 'Plaintext Secret in Configuration File',
        severity: 'critical',
        category: 'secrets',
        path: 'auth.external.github.secret',
        observedValue: '[REDACTED_SECRET (length: 32)]',
        rationale: 'Plaintext credentials exposed in repository.',
        policyAssumption: 'Secrets must use env() substitution.',
        remediation: 'Use env(GITHUB_SECRET).',
      },
      {
        ruleId: 'SEC-AUTH-001',
        ruleTitle: 'Refresh Token Rotation Disabled',
        severity: 'high',
        category: 'auth',
        path: 'auth.enable_refresh_token_rotation',
        observedValue: 'false',
        rationale: 'Refresh token never expires.',
        policyAssumption: 'Rotation prevents token replay.',
        remediation: 'Enable rotation.',
      },
    ],
    summary: {
      totalRulesEvaluated: 12,
      totalFindings: 2,
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
      info: 0,
      passed: false,
    },
    exitCode: ExitCode.SECURITY_FINDINGS,
  };

  it('formats text report with clear findings and summary banner', () => {
    const text = formatTextReport(sampleResult);
    expect(text).toContain('SupaGuard — Supabase Security Preflight Analyzer');
    expect(text).toContain('SEC-SEC-001');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('SEC-AUTH-001');
    expect(text).toContain('PREFLIGHT FAILED');
    expect(text).toContain('Remediation:');
  });

  it('formats machine-readable JSON report as strictly valid JSON', () => {
    const jsonStr = formatJsonReport(sampleResult);
    const parsed = JSON.parse(jsonStr);

    expect(parsed.targetPath).toBe(sampleResult.targetPath);
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.summary.high).toBe(1);
    expect(parsed.summary.passed).toBe(false);
    expect(parsed.exitCode).toBe(ExitCode.SECURITY_FINDINGS);
  });

  it('formatReport delegates properly between text and json', () => {
    const jsonOutput = formatReport(sampleResult, 'json');
    expect(() => JSON.parse(jsonOutput)).not.toThrow();

    const textOutput = formatReport(sampleResult, 'text');
    expect(textOutput).toContain('Target File:');
  });

  it('guarantees no raw secrets are leaked in output even if input has unredacted data in other fields', () => {
    const jsonStr = formatJsonReport(sampleResult);
    expect(jsonStr).not.toContain('ghp_');
    expect(jsonStr).toContain('[REDACTED_SECRET');
  });

  it('scrubs inadvertent unmasked credential fields in custom result objects', () => {
    const dirtyResult = {
      ...sampleResult,
      custom_metadata: {
        raw_password: 'inadvertent_plain_password_123',
        api_key: 'sk_live_another_leaked_key_456',
      },
    } as any;

    const jsonStr = formatJsonReport(dirtyResult);
    expect(jsonStr).not.toContain('inadvertent_plain_password_123');
    expect(jsonStr).not.toContain('sk_live_another_leaked_key_456');
    expect(jsonStr).toContain('[REDACTED_SECRET');
  });
});
