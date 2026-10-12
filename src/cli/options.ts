import { Command } from 'commander';
import type { ReportFormat } from '../types/report.js';

export interface CliOptions {
  config?: string;
  format: ReportFormat;
  strict: boolean;
}

export function createCliCommand(onCheck?: (options: CliOptions) => void): Command {
  const program = new Command();

  program
    .name('supaguard')
    .description('SupaGuard — Security preflight CLI for Supabase projects')
    .version('0.1.0')
    .exitOverride();

  const checkCommand = program
    .command('check', { isDefault: true })
    .description('Run local security preflight checks against supabase/config.toml')
    .option(
      '-c, --config <path>',
      'Path to supabase/config.toml or the project root directory (default: ./supabase/config.toml)'
    )
    .option(
      '-f, --format <format>',
      'Output format: text (human readable) or json (machine readable)',
      'text'
    )
    .option(
      '-s, --strict',
      'Strict mode: exits with non-zero code on any finding (including low and info)',
      false
    );

  if (onCheck) {
    checkCommand.action((rawOptions) => {
      onCheck(rawOptions as CliOptions);
    });
  }

  return program;
}
