import type { ExitCodeValue } from './exit-codes.js';
import type { Finding } from './rule.js';

export type ReportFormat = 'text' | 'json';

export interface ReportSummary {
  totalRulesEvaluated: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  passed: boolean;
}

export interface AnalysisResult {
  targetPath: string;
  strict: boolean;
  advisory?: boolean;
  timestamp: string;
  findings: Finding[];
  summary: ReportSummary;
  exitCode: ExitCodeValue;
}
