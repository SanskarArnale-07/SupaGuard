# SupaPreflight

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/Tests-237%20passed-brightgreen.svg)]()

> **SupaPreflight** is an offline security preflight CLI for Supabase projects.
> It inspects `supabase/config.toml` and SQL migration files (`supabase/migrations/*.sql`) prior to deployment to detect security-sensitive configurations, missing Row Level Security (RLS), exposed secrets, and overly permissive database access policies.

---

## What SupaPreflight Does

- **Static Configuration Analysis**: Parses `supabase/config.toml` using a strict, spec-compliant TOML 1.0 parser (`smol-toml`).
- **SQL Migration Security Scanning**: Discovers and evaluates `supabase/migrations/*.sql` in deterministic order, building the cumulative final database state across your migration history.
- **Spec-Compliant PostgreSQL Parsing**: Uses the official PostgreSQL parser compiled to WebAssembly (`pgsql-parser`) to parse complex DDL statements, comments, quoted identifiers, and multi-statement files.
- **Built-in Security Rules**:
  - Configuration security rules across Auth, Database, API exposure, Edge Functions, Storage buckets, and Secrets.
  - Database migration rules tracking missing Row Level Security, dangerous or unrestricted RLS policies, and PostgreSQL view security.
- **State-Aware History Tracking**: Correctly accounts for tables created, altered, or dropped in later migrations, as well as policies modified or removed across the migration history.
- **API Schema Correlation**: Cross-references table definitions against PostgREST API-exposed schemas (`api.schemas`) so internal or unexposed schemas do not generate false positives.
- **Comprehensive Secret Redaction**: Masks sensitive credentials (`[REDACTED_SECRET]`) in terminal output, JSON reports, runtime error messages, and syntax error snippets.
- **Environment Reference Recognition**: Treats `env(VARIABLE_NAME)` references as secure parameterizations without reading `.env` files or making network requests.
- **Predictable Exit Codes**: Returns deterministic exit codes (`0`, `1`, `2`) designed for CI/CD pipelines and pre-commit hooks.
- **Strictly Read-Only and Safe**: Never mutates or formats configuration or migration files, never connects to a database, and collects zero telemetry.

---

## What SupaPreflight Does Not Do

- **Does NOT Execute SQL Against a Database**: SupaPreflight is strictly a static analyzer. It never connects to local or remote PostgreSQL instances, never executes migrations, and does not require database credentials.
- **Does NOT Connect to Live Supabase Projects**: SupaPreflight is local-only. It does not contact remote Supabase APIs, project management endpoints, or cloud dashboards.
- **Does NOT Validate Secret Values**: SupaPreflight verifies that secrets use `env(...)` references rather than committed plaintext. It deliberately does not inspect local `.env` files or test whether credentials are valid.
- **Does NOT Guarantee Flawless Business Logic**: Enabling Row Level Security ensures that row-level checks are enforced; it does not replace application integration testing or verify whether your specific business rules match user expectations.
- **Does NOT Modify Files**: SupaPreflight does not auto-fix or rewrite configuration or SQL files.

---

## Runtime Requirements & Dependencies

### Node.js Engine
- **Node.js**: `>= 18.0.0`

### Runtime Dependencies
SupaPreflight relies on five production dependencies:
- [`commander`](https://www.npmjs.com/package/commander) (`^12.1.0`) — CLI option parsing, help formatting, and subcommand routing.
- [`pgsql-parser`](https://www.npmjs.com/package/pgsql-parser) (`^18.2.10`) — PostgreSQL 18 query and DDL parser compiled to WebAssembly for AST analysis of migrations.
- [`smol-toml`](https://www.npmjs.com/package/smol-toml) (`^1.3.1`) — Spec-compliant TOML 1.0 parser with line and column tracking.
- [`picocolors`](https://www.npmjs.com/package/picocolors) (`^1.1.1`) — Lightweight ANSI terminal styling.
- [`zod`](https://www.npmjs.com/package/zod) (`^3.23.8`) — Configuration validation and schema typing.

### Development Dependencies
- [`typescript`](https://www.npmjs.com/package/typescript) (`^5.6.3`) — TypeScript compiler.
- [`vitest`](https://www.npmjs.com/package/vitest) (`^2.1.2`) — Automated test runner.
- [`tsx`](https://www.npmjs.com/package/tsx) (`^4.19.1`) — TypeScript execution for local development checks.
- [`@types/node`](https://www.npmjs.com/package/@types/node) (`^22.7.5`) — Node.js type definitions.

---

## Installation & Developer Quickstart

### Clean Checkout Workflow (for Developers & Contributors)

```bash
# Clone the repository
git clone https://github.com/SanskarArnale-07/SupaPreflight.git
cd SupaPreflight

# Install exact dependencies from lockfile
npm ci

# Build the TypeScript project
npm run build

# Run the complete test suite
npm test

# Verify package distribution tarball
npm pack --dry-run
```

### Installation in a Supabase Project

Install the package as a development dependency:

```bash
# Install as a dev dependency
npm install --save-dev supa-preflight

# Run preflight check
npx supa-preflight check
```

Or execute on-demand without local installation:

```bash
# Run latest release on-demand
npx --yes supa-preflight check

# Or pin to a specific release version
npx --yes supa-preflight@0.1.0 check
```

### Global Installation

```bash
npm install -g supa-preflight

# Run from your Supabase project root
supa-preflight check
```

---

## Command-Line Usage

### Commands and Options

```bash
supa-preflight check [options]
```

| Option | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `--config <path>` | `-c` | `./supabase/config.toml` | Path to `supabase/config.toml` or the project root directory. |
| `--migrations <path>` | `-m` | Auto-discovered | Path to migrations directory (defaults to `./supabase/migrations`). |
| `--format <format>` | `-f` | `text` | Output format: `text` (terminal ANSI) or `json` (machine-readable). |
| `--strict` | `-s` | `false` | Strict mode: exits with code `1` on any finding (including `MEDIUM`, `LOW`, and `INFO`; mutually exclusive with `--advisory`). |
| `--advisory` | `-a` | `false` | Advisory mode: reports security findings without failing the process (exits `0` on findings, non-zero on execution or configuration errors; mutually exclusive with `--strict`). |
| `--help` | `-h` | — | Display command help and available options. |
| `--version` | `-V` | — | Output SupaPreflight version number. |

### Usage Examples

#### 1. Standard Preflight Check
Run from your project root (automatically locates `./supabase/config.toml` and `./supabase/migrations/*.sql`):
```bash
supa-preflight check
```

#### 2. Custom Paths
Specify a direct config path or an explicit migrations folder:
```bash
supa-preflight check --config ./custom/supabase/config.toml --migrations ./custom/supabase/migrations
```

#### 3. Machine-Readable JSON Output
Ideal for CI/CD pipelines, pre-commit hooks, and integration with security dashboards:
```bash
supa-preflight check --format json
```

#### 4. Strict Mode
Fails on any finding, including non-blocking advisories:
```bash
supa-preflight check --strict
```

#### 5. Advisory Mode (CI / Pull Requests)
Reports all security findings in logs without failing the job, while preserving non-zero exits on execution or configuration errors:
```bash
supa-preflight check --advisory
```
For complete GitHub Actions workflow configurations, see [GitHub Actions Integration](docs/github-actions.md).

---

## Exit Codes

SupaPreflight uses deterministic exit codes to integrate cleanly with automated workflows:

| Exit Code | Constant | Meaning | Condition |
| :---: | :--- | :--- | :--- |
| **`0`** | `SUCCESS` | Preflight Passed | **Standard mode**: 0 `CRITICAL` and 0 `HIGH` findings.<br>**Strict mode**: 0 total findings.<br>**Advisory mode**: Security findings reported without blocking (exit 0). |
| **`1`** | `SECURITY_FINDINGS` | Preflight Failed | **Standard mode**: 1 or more `CRITICAL` or `HIGH` findings.<br>**Strict mode**: 1 or more findings of any severity.<br>**Advisory mode**: Returned only if unparseable migration SQL syntax, unreadable migration, or internal evaluation error is encountered. |
| **`2`** | `CONFIG_ERROR` | Execution Aborted | Target configuration file not found, unreadable, or contains invalid TOML syntax; also returned when conflicting options (e.g. `--advisory` and `--strict`) are provided. |

---

## Security Rules & Severity Classification

SupaPreflight evaluates 16 security checks divided between configuration preflights and SQL migration analysis:

### Configuration Rules (Phase 1)

| Rule ID | Title | Severity | Category | Target Setting |
| :--- | :--- | :---: | :---: | :--- |
| **`SEC-SEC-001`** | Plaintext Secret in Config File | `CRITICAL` | `secrets` | `auth.external.<provider>.secret`, `studio.openai_api_key`, `auth.email.smtp.pass`, etc. |
| **`SEC-API-001`** | Internal System Schema in API List | `HIGH` | `api` | `api.schemas` containing `auth`, `vault`, etc. |
| **`SEC-DB-001`** | Session Replication Role Set to Replica | `HIGH` | `database` | `db.settings.session_replication_role = "replica"` |
| **`SEC-AUTH-001`** | Refresh Token Rotation Disabled | `HIGH` | `auth` | `auth.enable_refresh_token_rotation = false` |
| **`SEC-AUTH-002`** | Email Change Double Confirmation Disabled | `HIGH` | `auth` | `auth.email.double_confirm_changes = false` |
| **`SEC-AUTH-003`** | OIDC Nonce Validation Bypassed | `HIGH` | `auth` | `auth.external.<provider>.skip_nonce_check = true` |
| **`SEC-AUTH-004`** | Insecure / Permissive Redirect URL | `HIGH` / `LOW` | `auth` | `auth.additional_redirect_urls` |
| **`SEC-AUTH-005`** | Static Test OTP Configured | `HIGH` | `auth` | `[auth.sms.test_otp]` table present |
| **`SEC-AUTH-006`** | Excessive JWT Expiration Lifetime | `MEDIUM` | `auth` | `auth.jwt_expiry > 86400` (> 24 hours) |
| **`SEC-AUTH-007`** | OAuth Provider Missing Credentials | `MEDIUM` | `auth` | `auth.external.<provider>.enabled = true` with missing/empty secrets |
| **`SEC-FN-001`** | Edge Function JWT Verification Disabled | `MEDIUM` | `functions` | `functions.<name>.verify_jwt = false` |
| **`SEC-AUTH-008`** | Password Re-Authentication Disabled | `LOW` | `auth` | `auth.email.secure_password_change = false` |
| **`SEC-ST-001`** | Storage Bucket Configured for Public Access | `INFO` | `storage` | `storage.buckets.<name>.public = true` |

### SQL Migration Rules (Phase 2)

| Rule ID | Title | Severity | Category | Target Setting / SQL Statement |
| :--- | :--- | :---: | :---: | :--- |
| **`SEC-MIG-RLS-001`** | Table in API-Exposed Schema Lacks Row Level Security | `HIGH` | `migrations` | `CREATE TABLE` without `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` in final state. |
| **`SEC-MIG-RLS-002`** | Suspicious or Overly Permissive Row Level Security Policy | `HIGH` / `MEDIUM` / `INFO` | `migrations` | `CREATE POLICY` / `ALTER POLICY` with unconditionally true predicates (`USING (true)`, `WITH CHECK (true)`). |
| **`SEC-MIG-VIEW-001`** | PostgreSQL View Security Analysis | `HIGH` / `INFO` | `migrations` | `CREATE VIEW` without `security_invoker = true` referencing base tables or untracked relations. |

---

## Detailed SQL Migration Rules & Analysis Model

### Migration Discovery and State Aggregation
1. **Deterministic Processing**: Discovers all `*.sql` files in `supabase/migrations/` and processes them in alphabetical/chronological order.
2. **Cumulative Final State**: Tracks table creation, RLS enablement, RLS disabling, policy definitions, policy alterations, and table drops across migrations.
   - If a table is created without RLS in Migration 1, but has RLS enabled in Migration 2, it is **not flagged**.
   - If a table has RLS enabled, but subsequently disabled in a later migration, it **is flagged**.
   - If a table is created and subsequently dropped in a later migration, it is **not flagged**.
   - If a dangerous policy is created and subsequently dropped or tightened in a later migration, it is **not flagged**.

---

### `SEC-MIG-RLS-001`: Missing Row Level Security on API-Exposed Table (`HIGH`)

- **What it checks**: Detects tables created in API-exposed schemas (such as `public` or schemas listed in `api.schemas`) that do not have Row Level Security enabled in the final represented migration state.
- **Supabase Permission Context**: In Supabase, PostgREST exposes tables in API schemas to `anon` and `authenticated` roles by default. When RLS is disabled, table access is governed solely by PostgreSQL table-level grants (`GRANT SELECT, INSERT...`), completely bypassing row-level filters.
- **What RLS Does and Does Not Establish**:
  - Enabling RLS instructs PostgreSQL to enforce row-level policies. If RLS is enabled and zero policies exist, all access is denied by default (fail-closed).
  - Enabling RLS does not prove that subsequent policies are mathematically correct; rather, it activates row-level policy enforcement.
- **Remediation**:
  ```sql
  ALTER TABLE "public"."your_table" ENABLE ROW LEVEL SECURITY;
  ```

---

### `SEC-MIG-RLS-002`: Suspicious or Overly Permissive RLS Policies

SupaPreflight inspects policy commands (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `ALL`), target roles (`anon`, `authenticated`, `public`), and conditional clauses (`USING`, `WITH CHECK`).

- **Classification Tiers**:
  1. **Unrestricted Write Access for `anon` or `public` (`HIGH`)**:
     - Affects write operations (`INSERT`, `UPDATE`, `DELETE`, `ALL`) with unconditionally true predicates (`USING (true)` or `WITH CHECK (true)`).
     - Allows any anonymous caller on the internet to insert, modify, or delete database rows without validation.
     - *Remediation*: Restrict writes to authenticated users and require row ownership:
       ```sql
       CREATE POLICY "User insert" ON "public"."orders"
         FOR INSERT TO authenticated
         WITH CHECK (auth.uid() = user_id);
       ```
  2. **Unrestricted Mutation across Rows for `authenticated` (`MEDIUM`)**:
     - Affects `UPDATE`, `DELETE`, or `ALL` with unconditionally true predicates for `authenticated`.
     - Allows any logged-in user to modify or delete rows belonging to other users.
     - *Remediation*: Enforce user ownership in the `USING` clause:
       ```sql
       CREATE POLICY "User update own" ON "public"."posts"
         FOR UPDATE TO authenticated
         USING (auth.uid() = author_id);
       ```
  3. **Unconditional INSERT for `authenticated` (`LOW`)**:
     - Advisory for `INSERT` with `WITH CHECK (true)` for authenticated users. Useful to prompt verifying that `user_id` fields cannot be spoofed.
  4. **Public Read-Only Access (`INFO`)**:
     - Affects `FOR SELECT` with `USING (true)`.
     - Intentionally public read access is standard for public assets (catalogs, blogs, documentation). SupaPreflight reports this as an informative advisory to confirm that the table does not store private user records.

---

### Known SQL Parsing Limitations

1. **Procedural Logic Inside Functions**: SupaPreflight statically parses DDL statements. Dynamic SQL executed inside PL/pgSQL functions (`EXECUTE '...'`) is not evaluated.
2. **Unsupported Custom Grammar**: SupaPreflight relies on the official PostgreSQL 18 grammar engine. Non-standard syntax or proprietary third-party preprocessor directives will produce a `SEC-MIG-PARSE-ERR` diagnostic finding without crashing the scan.
3. **External Schema Objects**: Objects created dynamically by external extensions without explicit SQL DDL are outside static migration scope.

---

## Output Examples

### Terminal Output (`--format text`)

```
======================================================================
 SupaPreflight — Supabase Security Preflight Analyzer
======================================================================
Target File: ./supabase/config.toml
Timestamp:   2026-10-12T15:50:00.000Z
Mode:        Standard (high/critical fail)
Rules Checked: 15
----------------------------------------------------------------------

[1/2] [HIGH] Table in API-Exposed Schema Lacks Row Level Security (SEC-MIG-RLS-001)
   Migration Path:   supabase/migrations/20240101000000_init.sql:2
   Target Table:   public.orders
   Observed Value: Row Level Security disabled (final state)
   Category:       migrations
   Rationale:      Table "public.orders" was created in "supabase/migrations/20240101000000_init.sql" (line 2) in schema "public" exposed by PostgREST, but does not have Row Level Security (RLS) enabled.
   Policy Assumption: All persistent database tables in API-exposed schemas must have Row Level Security enabled.
   ➜ Remediation:    Add "ALTER TABLE "orders" ENABLE ROW LEVEL SECURITY;" in a migration.

[2/2] [HIGH] Unrestricted Write Access Allowed by RLS Policy (SEC-MIG-RLS-002)
   Migration Path:   supabase/migrations/20240102000000_feedback.sql:9
   Target Table:   public.feedback
   Policy Name:    "Anon open insert"
   Observed Value: Policy "Anon open insert" allows unrestricted "INSERT" via WITH CHECK (true) to roles: [anon]
   Category:       migrations
   Rationale:      Policy "Anon open insert" on table "public.feedback" grants unrestricted write access to unauthenticated callers.
   Policy Assumption: Write operations must enforce authentication and row ownership checks.
   ➜ Remediation:    Scope policy "Anon open insert" to authenticated users and add row-level ownership checks.

----------------------------------------------------------------------
Summary Findings:
  Critical: 0
  High:     2
  Medium:   0
  Low:      0
  Info:     0
----------------------------------------------------------------------
✖ PREFLIGHT FAILED: One or more high/critical security findings require remediation.
```

### JSON Output (`--format json`)

```json
{
  "targetPath": "D:\\my-project\\supabase\\config.toml",
  "strict": false,
  "timestamp": "2026-10-12T15:50:00.000Z",
  "findings": [
    {
      "ruleId": "SEC-MIG-RLS-001",
      "ruleTitle": "Table in API-Exposed Schema Lacks Row Level Security",
      "severity": "high",
      "category": "migrations",
      "path": "supabase/migrations/20240101000000_init.sql:2",
      "observedValue": "Row Level Security disabled (final state)",
      "rationale": "Table \"public.orders\" was created in \"supabase/migrations/20240101000000_init.sql\" (line 2) in schema \"public\" exposed by PostgREST, but does not have Row Level Security (RLS) enabled in the final migration state.",
      "policyAssumption": "All persistent database tables in API-exposed schemas must have Row Level Security enabled (ALTER TABLE ... ENABLE ROW LEVEL SECURITY).",
      "remediation": "Add \"ALTER TABLE \"orders\" ENABLE ROW LEVEL SECURITY;\" in a migration, and create appropriate policies using CREATE POLICY.",
      "filePath": "supabase/migrations/20240101000000_init.sql",
      "line": 2,
      "schema": "public",
      "table": "orders"
    }
  ],
  "summary": {
    "totalRulesEvaluated": 15,
    "totalFindings": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0,
    "passed": false
  },
  "exitCode": 1
}
```

---

## License

This project is licensed under the [MIT License](LICENSE).