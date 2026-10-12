#!/usr/bin/env node

import pc from 'picocolors';
import { analyzeConfig } from '../analyzer/index.js';
import { loadConfig } from '../config/loader.js';
import { formatReport } from '../reporter/index.js';
import { ExitCode, type ExitCodeValue } from '../types/exit-codes.js';
import type { ReportFormat } from '../types/report.js';
import { createCliCommand, type CliOptions } from './options.js';

export async function runCli(argv: string[] = process.argv): Promise<ExitCodeValue> {
  let resolvedExitCode: ExitCodeValue = ExitCode.SUCCESS;

  const handleCheck = (options: CliOptions) => {
    const rawFormat = (options.format || 'text').toLowerCase();
    const format: ReportFormat = rawFormat === 'json' ? 'json' : 'text';
    const strict = Boolean(options.strict);
    const configPath = options.config;

    const loadResult = loadConfig({ configPath });

    if (!loadResult.success) {
      resolvedExitCode = ExitCode.CONFIG_ERROR;

      if (format === 'json') {
        process.stdout.write(
          JSON.stringify(
            {
              success: false,
              error: loadResult.error,
              exitCode: ExitCode.CONFIG_ERROR,
            },
            null,
            2
          ) + '\n'
        );
      } else {
        process.stderr.write(
          `\n${pc.red(pc.bold('✖ SupaGuard Configuration Error:'))} ${loadResult.error.message}\n\n`
        );
        if (loadResult.error.code === 'FILE_NOT_FOUND') {
          process.stderr.write(
            `${pc.dim('Hint:')} Run ${pc.cyan('supabase init')} to create a configuration file, or pass ${pc.cyan('--config <path>')}.\n\n`
          );
        } else if (loadResult.error.code === 'INVALID_TOML') {
          if (loadResult.error.line !== undefined) {
            process.stderr.write(
              `${pc.dim('Location:')} Line ${loadResult.error.line}, Column ${loadResult.error.column ?? '?'}\n\n`
            );
          }
        }
      }
      return;
    }

    const analysis = analyzeConfig(loadResult.config, { strict });
    const output = formatReport(analysis, format);

    process.stdout.write(output + '\n');
    resolvedExitCode = analysis.exitCode;
  };

  const program = createCliCommand(handleCheck);

  try {
    await program.parseAsync(argv);
  } catch (err: unknown) {
    const errorObj = err as { code?: string; exitCode?: number; message?: string };
    if (errorObj.code === 'commander.helpDisplayed' || errorObj.code === 'commander.version') {
      return ExitCode.SUCCESS;
    }
    process.stderr.write(`\n${pc.red('Error:')} ${errorObj.message || 'CLI execution error'}\n`);
    return ExitCode.CONFIG_ERROR;
  }

  return resolvedExitCode;
}

// If invoked directly from terminal
const isMain =
  typeof process !== 'undefined' &&
  Boolean(process.argv[1]) &&
  (process.argv[1].endsWith('index.ts') || process.argv[1].endsWith('index.js'));

if (isMain) {
  runCli().then((code) => {
    process.exit(code);
  });
}
