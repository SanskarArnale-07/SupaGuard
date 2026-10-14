# GitHub Actions CI/CD Integration

This guide describes how to integrate **SupaPreflight** (npm package `supa-preflight`, executable `supa-preflight`) into GitHub Actions workflows to perform automated security preflights on Supabase configuration and database migrations.

---

## Core Safety Principles

- **Offline & Read-Only**: SupaPreflight never connects to live PostgreSQL databases, never executes migrations, never contacts Supabase APIs, and never mutates repository files.
- **Zero Secrets Required**: Runs exclusively against checked-out repository files. **Do not** provide database passwords, database connection strings, or `SUPABASE_SERVICE_ROLE_KEY`.
- **Minimal Permissions**: The workflow requires only `contents: read` permissions.

---

## Advisory Mode vs. Enforcing Mode

SupaPreflight supports two distinct operational modes in CI:

| Mode | Command Flag | Security Findings Exit Code | Operational/Execution Error Exit Code | Best Suited For |
| :--- | :--- | :---: | :---: | :--- |
| **Advisory Mode** | `--advisory` (`-a`) | **`0`** (Passed) | **`1`** or **`2`** (Failed) | Greenfield adoption, existing projects with legacy debt, non-blocking pull request reviews. |
| **Enforcing Mode** (Default) | *(none)* | **`1`** (Failed) | **`1`** or **`2`** (Failed) | Production repositories, blocking pull request gates, compliance enforcement. |
| **Strict Enforcing** | `--strict` (`-s`) | **`1`** (Failed on *any* finding) | **`1`** or **`2`** (Failed) | Zero-tolerance repositories requiring immediate remediation of low and info advisories. |

### How Advisory Mode Behaves

1. **Non-blocking security visibility**: If security issues are found (such as missing Row Level Security, exposed system schemas, or plaintext secrets), SupaPreflight formats and outputs all findings directly into the GitHub Actions step log, but exits with code `0`. Pull requests are not blocked.
2. **Honest error handling**: Advisory mode does **not** suppress genuine execution failures. If `supabase/config.toml` is unreadable or contains malformed TOML syntax (exit code `2`), or if a migration SQL file contains unparseable syntax or cannot be read (exit code `1`), SupaPreflight fails the job. This ensures broken migrations and invalid configurations are never mistakenly passed.

> [!IMPORTANT]
> **Mutual Exclusivity**: `--advisory` and `--strict` are mutually exclusive. Advisory mode represents non-blocking preflight reporting, whereas strict mode represents zero-tolerance build enforcement. Attempting to combine both flags is rejected during argument validation and aborts with exit code `2` (`CONFIG_ERROR`).

---

## Release Prerequisite & Package Installation

> [!NOTE]
> **Package Distribution**: The npm package name is `supa-preflight`, which provides the `supa-preflight` executable.
> Once published to the npm public registry, pin the version in your CI workflow:
> ```bash
> npx --yes supa-preflight@0.1.0 check --advisory
> ```
> (If `supa-preflight` is already listed in your project's `devDependencies`, you can invoke `npx supa-preflight check --advisory` directly).
> Prior to public npm registry publication, install SupaPreflight from source, a private registry, or from a repository build (`npm pack`).

---

## Complete Advisory-Mode Workflow Example

Create `.github/workflows/supa-preflight.yml` in your repository:

```yaml
name: SupaPreflight Security Preflight

on:
  pull_request:
    branches:
      - main
    paths:
      - 'supabase/**'
      - '.github/workflows/supa-preflight.yml'
  push:
    branches:
      - main
    paths:
      - 'supabase/**'
      - '.github/workflows/supa-preflight.yml'

# Strictly enforce read-only token permissions
permissions:
  contents: read

jobs:
  security-preflight:
    name: Supabase Security Preflight
    runs-on: ubuntu-latest

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      # Step 1: Run preflight in advisory mode for clear human-readable terminal output
      - name: Run SupaPreflight Security Preflight (Advisory)
        run: |
          npx --yes supa-preflight@0.1.0 check --advisory

      # Step 2: Generate machine-readable JSON report
      - name: Generate JSON Security Report
        if: always()
        run: |
          npx --yes supa-preflight@0.1.0 check --advisory --format json > supa-preflight-report.json

      # Step 3: Archive JSON report as a downloadable workflow artifact
      - name: Upload Security Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: supa-preflight-security-report
          path: supa-preflight-report.json
          if-no-files-found: warn
          retention-days: 14
```

### Path Filtering Notes

- The `paths` filter (`supabase/**`) ensures the workflow triggers only when relevant configuration or migration files change.
- If your repository uses dynamic path references, symlinks, or custom configuration locations, omit the `paths` block to run on every pull request.

---

## Transitioning to Enforcing Mode

When your team is ready to block pull requests containing critical or high security defects:

1. Remove the `--advisory` flag from the check command:
   ```yaml
   - name: Run SupaPreflight Security Preflight (Enforcing)
     run: |
       npx --yes supa-preflight@0.1.0 check
   ```
2. Any `CRITICAL` finding (e.g. plaintext secret) or `HIGH` finding (e.g. table lacking RLS in an exposed schema) will exit with code `1` and block the merge.
3. For zero-tolerance enforcement (failing on medium, low, or info advisories as well), add `--strict`:
   ```yaml
   - name: Run SupaPreflight Security Preflight (Strict)
     run: |
       npx --yes supa-preflight@0.1.0 check --strict
   ```

---

## Exit Codes Reference

| Exit Code | Meaning | Advisory Mode (`--advisory`) | Enforcing Mode (Default) |
| :---: | :--- | :--- | :--- |
| **`0`** | `SUCCESS` | No findings **or** security findings reported (non-blocking). | Preflight passed (0 critical / 0 high findings). |
| **`1`** | `SECURITY_FINDINGS` / `EXECUTION_ERROR` | Syntax error in migration SQL, unreadable migration, or internal evaluation error. | Security findings detected, or migration syntax/read error. |
| **`2`** | `CONFIG_ERROR` | Target configuration missing, unreadable, invalid TOML syntax, or conflicting options provided. | Target configuration missing, unreadable, invalid TOML syntax, or conflicting options provided. |
