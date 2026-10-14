/**
 * SupaPreflight CLI process exit codes.
 */
export const ExitCode = {
  /** Analysis completed successfully with no threshold-exceeding findings. */
  SUCCESS: 0,
  /** Security findings detected that meet or exceed the failure threshold. */
  SECURITY_FINDINGS: 1,
  /** Configuration file was not found, unreadable, or malformed TOML. */
  CONFIG_ERROR: 2,
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];
