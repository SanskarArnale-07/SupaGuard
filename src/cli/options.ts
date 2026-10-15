import { Command } from 'commander';
import type { ReportFormat } from '../types/report.js';
import { getPackageVersion } from './version.js';

export interface CliOptions {
  config?: string;
  migrations?: string;
  format: ReportFormat;
  strict: boolean;
  advisory?: boolean;
}

export function createCliCommand(onCheck?: (options: CliOptions) => void | Promise<void>): Command {
  const program = new Command();

  program
    .name('supa-preflight')
    .description('SupaPreflight — Security preflight CLI for Supabase projects')
    .version(getPackageVersion())
    .exitOverride();

  const checkCommand = program
    .command('check', { isDefault: true })
    .description('Run local security preflight checks against supabase/config.toml and migrations')
    .option(
      '-c, --config <path>',
      'Path to supabase/config.toml or the project root directory (default: ./supabase/config.toml)'
    )
    .option(
      '-m, --migrations <path>',
      'Path to migrations directory (default: auto-discovered ./supabase/migrations)'
    )
    .option(
      '-f, --format <format>',
      'Output format: text (human readable) or json (machine readable)',
      'text'
    )
    .option(
      '-s, --strict',
      'Strict mode: exits with non-zero code on any finding (mutually exclusive with --advisory)',
      false
    )
    .option(
      '-a, --advisory',
      'Advisory mode: report security findings without failing the process (mutually exclusive with --strict)',
      false
    );

  if (onCheck) {
    checkCommand.action(async (rawOptions) => {
      await onCheck(rawOptions as CliOptions);
    });
  }

  return program;
}
