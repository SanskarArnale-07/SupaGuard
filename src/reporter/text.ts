import pc from 'picocolors';
import type { AnalysisResult } from '../types/report.js';
import type { Finding, Severity } from '../types/rule.js';

function formatBadge(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'high':
      return pc.red(pc.bold('[HIGH]'));
    case 'medium':
      return pc.yellow(pc.bold('[MEDIUM]'));
    case 'low':
      return pc.cyan('[LOW]');
    case 'info':
      return pc.blue('[INFO]');
  }
}

function formatFinding(finding: Finding, index: number, total: number): string {
  const badge = formatBadge(finding.severity);
  const title = pc.bold(finding.ruleTitle);
  const id = pc.dim(`(${finding.ruleId})`);
  const path = pc.cyan(finding.path);
  const observed = pc.white(pc.bold(finding.observedValue));

  const pathLabel = finding.category === 'migrations' ? 'Migration Path:' : 'Config Path:   ';

  const lines = [
    `${pc.dim(`[${index}/${total}]`)} ${badge} ${title} ${id}`,
    `   ${pc.dim(pathLabel)}   ${path}`,
  ];

  if (finding.view) {
    const viewName = finding.schema ? `${finding.schema}.${finding.view}` : finding.view;
    lines.push(`   ${pc.dim('Target View:')}    ${pc.magenta(viewName)}`);
  } else if (finding.schema && finding.table) {
    lines.push(`   ${pc.dim('Target Table:')}   ${pc.magenta(`${finding.schema}.${finding.table}`)}`);
  }

  if (finding.policyName) {
    lines.push(`   ${pc.dim('Policy Name:')}    ${pc.yellow(`"${finding.policyName}"`)}`);
  }

  lines.push(
    `   ${pc.dim('Observed Value:')} ${observed}`,
    `   ${pc.dim('Category:')}       ${finding.category}`,
    `   ${pc.dim('Rationale:')}      ${finding.rationale}`,
    `   ${pc.dim('Policy Assumption:')} ${pc.italic(finding.policyAssumption)}`,
    `   ${pc.green('➜ Remediation:')}    ${finding.remediation}`
  );

  return lines.join('\n');
}

/**
 * Formats an AnalysisResult as human-readable terminal output.
 */
export function formatTextReport(result: AnalysisResult): string {
  const { summary, findings, targetPath, strict } = result;

  const header = [
    pc.bold(pc.cyan('======================================================================')),
    pc.bold(pc.cyan(' SupaGuard — Supabase Security Preflight Analyzer')),
    pc.bold(pc.cyan('======================================================================')),
    `${pc.dim('Target File:')} ${targetPath}`,
    `${pc.dim('Timestamp:')}   ${result.timestamp}`,
    `${pc.dim('Mode:')}        ${strict ? pc.yellow('Strict (all findings fail)') : 'Standard (high/critical fail)'}`,
    `${pc.dim('Rules Checked:')} ${summary.totalRulesEvaluated}`,
    pc.dim('----------------------------------------------------------------------'),
  ].join('\n');

  let body = '';
  if (findings.length === 0) {
    body = `\n${pc.green(pc.bold('✔ No security issues detected in project configuration or migrations!'))}\n`;
  } else {
    body = '\n' + findings.map((f, i) => formatFinding(f, i + 1, findings.length)).join('\n\n') + '\n';
  }

  const breakdown = [
    pc.dim('----------------------------------------------------------------------'),
    pc.bold('Summary Findings:'),
    `  Critical: ${summary.critical > 0 ? pc.red(pc.bold(String(summary.critical))) : pc.dim('0')}`,
    `  High:     ${summary.high > 0 ? pc.red(String(summary.high)) : pc.dim('0')}`,
    `  Medium:   ${summary.medium > 0 ? pc.yellow(String(summary.medium)) : pc.dim('0')}`,
    `  Low:      ${summary.low > 0 ? pc.cyan(String(summary.low)) : pc.dim('0')}`,
    `  Info:     ${summary.info > 0 ? pc.blue(String(summary.info)) : pc.dim('0')}`,
    pc.dim('----------------------------------------------------------------------'),
  ].join('\n');

  let statusBanner = '';
  if (summary.passed) {
    statusBanner = pc.green(pc.bold('✔ PREFLIGHT PASSED: Project configuration meets security policy.'));
  } else {
    const blockingReason = strict
      ? 'Strict mode enabled: non-zero findings trigger failure.'
      : 'One or more high/critical security findings require remediation.';
    statusBanner = pc.red(pc.bold(`✖ PREFLIGHT FAILED: ${blockingReason}`));
  }

  return `${header}\n${body}\n${breakdown}\n${statusBanner}\n`;
}
