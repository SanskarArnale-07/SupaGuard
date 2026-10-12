import { deepSanitize } from './mask.js';
import type { AnalysisResult } from '../types/report.js';

/**
 * Formats an AnalysisResult as machine-readable JSON, ensuring deep redaction of all sensitive keys.
 */
export function formatJsonReport(result: AnalysisResult): string {
  const sanitized = deepSanitize(result, false);
  return JSON.stringify(sanitized, null, 2);
}
