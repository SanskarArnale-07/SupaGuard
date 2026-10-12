import { formatJsonReport } from './json.js';
import { formatTextReport } from './text.js';
import type { AnalysisResult, ReportFormat } from '../types/report.js';

export { formatJsonReport, formatTextReport };
export { maskSensitiveValue, isEnvVarReference, extractEnvVarName } from './mask.js';

/**
 * Formats an AnalysisResult using the requested format.
 */
export function formatReport(result: AnalysisResult, format: ReportFormat = 'text'): string {
  if (format === 'json') {
    return formatJsonReport(result);
  }
  return formatTextReport(result);
}
