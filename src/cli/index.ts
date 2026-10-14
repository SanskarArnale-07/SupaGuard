#!/usr/bin/env node

import * as fs from 'node:fs';
import * as path from 'node:path';
import pc from 'picocolors';
import { analyzeConfig } from '../analyzer/index.js';
import { loadConfig } from '../config/loader.js';
import { formatReport } from '../reporter/index.js';
import { ExitCode, type ExitCodeValue } from '../types/exit-codes.js';
import type { ReportFormat } from '../types/report.js';
import { createCliCommand, type CliOptions } from './options.js';

export async function runCli(argv: string[] = process.argv): Promise<ExitCodeValue> {
  let resolvedExitCode: ExitCodeValue = ExitCode.SUCCESS;

  const handleCheck = async (options: CliOptions) => {
    const rawFormat = (options.format || 'text').toLowerCase();
    const format: ReportFormat = rawFormat === 'json' ? 'json' : 'text';
    const strict = Boolean(options.strict);
    const advisory = Boolean(options.advisory);
    const configPath = options.config;
    const migrationsDir = options.migrations;

    // --advisory and --strict are mutually exclusive
    if (strict && advisory) {
      resolvedExitCode = ExitCode.CONFIG_ERROR;
      const message =
        'Cannot combine --advisory and --strict options. Advisory mode (non-blocking reporting) and strict mode (zero-tolerance enforcement) are mutually exclusive.';
      if (format === 'json') {
        process.stdout.write(
          JSON.stringify(
            {
              success: false,
              error: {
                code: 'CONFLICTING_OPTIONS',
                message,
              },
              exitCode: ExitCode.CONFIG_ERROR,
            },
            null,
            2
          ) + '\n'
        );
      } else {
        process.stderr.write(
          `\n${pc.red(pc.bold('✖ SupaGuard Configuration Error:'))} ${message}\n\n`
        );
        process.stderr.write(
          `${pc.dim('Hint:')} Specify either ${pc.cyan('--advisory')} for non-blocking reporting or ${pc.cyan('--strict')} for zero-tolerance enforcement, not both.\n\n`
        );
      }
      return;
    }

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

    // Validate explicit migrations directory if provided
    if (migrationsDir) {
      const resolvedMigrationsPath = path.resolve(process.cwd(), migrationsDir);
      if (!fs.existsSync(resolvedMigrationsPath)) {
        resolvedExitCode = ExitCode.CONFIG_ERROR;
        const message = `Explicit migrations directory not found: "${migrationsDir}"`;
        if (format === 'json') {
          process.stdout.write(
            JSON.stringify(
              {
                success: false,
                error: {
                  code: 'MIGRATIONS_DIR_NOT_FOUND',
                  message,
                },
                exitCode: ExitCode.CONFIG_ERROR,
              },
              null,
              2
            ) + '\n'
          );
        } else {
          process.stderr.write(
            `\n${pc.red(pc.bold('✖ SupaGuard Configuration Error:'))} ${message}\n\n`
          );
          process.stderr.write(
            `${pc.dim('Hint:')} Verify that the path passed to ${pc.cyan('--migrations')} exists, or omit the flag to use default discovery.\n\n`
          );
        }
        return;
      }

      try {
        const stat = fs.statSync(resolvedMigrationsPath);
        if (!stat.isDirectory()) {
          resolvedExitCode = ExitCode.CONFIG_ERROR;
          const message = `Explicit migrations path is not a directory: "${migrationsDir}"`;
          if (format === 'json') {
            process.stdout.write(
              JSON.stringify(
                {
                  success: false,
                  error: {
                    code: 'MIGRATIONS_DIR_NOT_DIRECTORY',
                    message,
                  },
                  exitCode: ExitCode.CONFIG_ERROR,
                },
                null,
                2
              ) + '\n'
            );
          } else {
            process.stderr.write(
              `\n${pc.red(pc.bold('✖ SupaGuard Configuration Error:'))} ${message}\n\n`
            );
            process.stderr.write(
              `${pc.dim('Hint:')} Pass a directory containing SQL migration files, not a single file.\n\n`
            );
          }
          return;
        }
      } catch (err: unknown) {
        resolvedExitCode = ExitCode.CONFIG_ERROR;
        const errObj = err as { message?: string };
        const message = `Cannot access migrations path: ${errObj.message || migrationsDir}`;
        if (format === 'json') {
          process.stdout.write(
            JSON.stringify(
              {
                success: false,
                error: {
                  code: 'MIGRATIONS_DIR_ACCESS_ERROR',
                  message,
                },
                exitCode: ExitCode.CONFIG_ERROR,
              },
              null,
              2
            ) + '\n'
          );
        } else {
          process.stderr.write(
            `\n${pc.red(pc.bold('✖ SupaGuard Configuration Error:'))} ${message}\n\n`
          );
        }
        return;
      }
    }

    const analysis = await analyzeConfig(loadResult.config, {
      strict,
      advisory,
      migrationsDir,
    });
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
    process.exitCode = code;
  });
}
