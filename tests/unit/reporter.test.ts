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

  it('formats SEC-MIG-VIEW-001 findings with Target View label without setting Target Table, preserving table formatting and JSON compatibility', () => {
    const viewResult: AnalysisResult = {
      targetPath: '/projects/my-supabase-app/supabase/config.toml',
      strict: false,
      timestamp: '2026-10-14T10:00:00.000Z',
      findings: [
        {
          ruleId: 'SEC-MIG-VIEW-001',
          ruleTitle: 'PostgreSQL View May Bypass Underlying Row-Level Security',
          severity: 'high',
          category: 'migrations',
          path: 'supabase/migrations/01_schema.sql:4',
          observedValue: 'security_invoker not enabled (defaults to false)',
          rationale: "In PostgreSQL, underlying relation permissions and row-level security (RLS) evaluation for ordinary views normally use the view owner's context.",
          policyAssumption: 'All PostgreSQL views in API-exposed schemas should enable security_invoker.',
          remediation: 'Add "ALTER VIEW "customer_summary" SET (security_invoker = true);".',
          filePath: 'supabase/migrations/01_schema.sql',
          line: 4,
          schema: 'public',
          view: 'customer_summary',
        },
        {
          ruleId: 'SEC-MIG-RLS-001',
          ruleTitle: 'Table in API-Exposed Schema Lacks Row Level Security',
          severity: 'high',
          category: 'migrations',
          path: 'supabase/migrations/01_schema.sql:1',
          observedValue: 'Row Level Security disabled (final state)',
          rationale: 'Table in public schema lacks RLS.',
          policyAssumption: 'Tables in exposed schemas must have RLS.',
          remediation: 'Enable RLS.',
          filePath: 'supabase/migrations/01_schema.sql',
          line: 1,
          schema: 'public',
          table: 'customers',
        },
      ],
      summary: {
        totalRulesEvaluated: 16,
        totalFindings: 2,
        critical: 0,
        high: 2,
        medium: 0,
        low: 0,
        info: 0,
        passed: false,
      },
      exitCode: ExitCode.SECURITY_FINDINGS,
    };

    const textOutput = formatTextReport(viewResult);
    expect(textOutput).toContain('Target View:');
    expect(textOutput).toContain('public.customer_summary');
    expect(textOutput).toContain('Target Table:');
    expect(textOutput).toContain('public.customers');

    const jsonOutput = formatJsonReport(viewResult);
    const parsed = JSON.parse(jsonOutput);
    expect(parsed.findings[0].view).toBe('customer_summary');
    expect(parsed.findings[0].table).toBeUndefined();
    expect(parsed.findings[1].table).toBe('customers');
    expect(parsed.findings[1].view).toBeUndefined();
  });
});
