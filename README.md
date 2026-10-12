# SupaGuard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/Tests-70%20passed-brightgreen.svg)]()

> **SupaGuard** is a local security preflight CLI for Supabase projects.
> It inspects `supabase/config.toml` prior to staging or production deployments to detect security-sensitive settings, exposed secrets, unencrypted protocols, and overly permissive configurations.

---

## What SupaGuard Does

- **Static TOML Configuration Analysis**: Parses `supabase/config.toml` using a strict, spec-compliant TOML 1.0 parser (`smol-toml`).
- **13 Built-in Security Rules**: Evaluates configuration settings across Authentication, API schemas, Database, Edge Functions, Storage buckets, and Secrets.
- **Strict Distinction Between Explicit and Default Settings**: Distinguishes explicitly configured settings from unconfigured Supabase CLI defaults. Unconfigured optional settings do not trigger false positive findings.
- **Comprehensive Secret Redaction**: Masks sensitive credentials (`[REDACTED_SECRET]`) in terminal output, JSON reports, runtime error messages, and syntax error snippets.
- **Environment Reference Recognition**: Treats `env(VARIABLE_NAME)` references as secure parameterizations without attempting to read `.env` files or execute network requests.
- **Predictable Exit Codes**: Returns deterministic exit codes (`0`, `1`, `2`) designed for CI/CD pipelines and pre-commit hooks.
- **Standard and Strict Evaluation Modes**: Allows distinguishing between blocking findings (`CRITICAL` and `HIGH`) and non-blocking advisories (`MEDIUM`, `LOW`, and `INFO`).
- **Strictly Read-Only and Safe**: Never mutates or formats configuration files, makes zero network connections, and collects zero telemetry.

---

## What SupaGuard Does Not Do

- **Does NOT Scan SQL Migrations**: SupaGuard Phase 1 only inspects `supabase/config.toml`. It does not analyze SQL migration files or schema definitions (reserved for future phases).
- **Does NOT Connect to Live Supabase Projects**: SupaGuard is entirely local. It does not contact remote Supabase APIs, project management endpoints, or cloud dashboards.
- **Does NOT Validate Secret Values**: SupaGuard verifies that secrets use `env(...)` references rather than committed plaintext. It deliberately does not inspect local `.env` files or test whether credentials are valid.
- **Does NOT Guarantee Total Security**: Passing all 13 preflight checks does not guarantee immunity from application vulnerabilities, flawed Row Level Security (RLS) policies, or runtime infrastructure misconfigurations.
- **Does NOT Modify Files**: SupaGuard does not auto-fix or rewrite configuration files.

---

## Runtime Requirements & Dependencies

### Node.js Engine
- **Node.js**: `>= 18.0.0`

### Runtime Dependencies
SupaGuard relies on a minimal set of four production dependencies:
- [`commander`](https://www.npmjs.com/package/commander) (`^12.1.0`) — CLI option parsing, help text, and subcommand routing.
- [`smol-toml`](https://www.npmjs.com/package/smol-toml) (`^1.3.1`) — Spec-compliant TOML 1.0 parser with line and column tracking.
- [`picocolors`](https://www.npmjs.com/package/picocolors) (`^1.1.1`) — Lightweight ANSI terminal styling.
- [`zod`](https://www.npmjs.com/package/zod) (`^3.23.8`) — Configuration validation and schema typing.

### Development Dependencies
- [`typescript`](https://www.npmjs.com/package/typescript) (`^5.6.3`) — TypeScript compiler.
- [`vitest`](https://www.npmjs.com/package/vitest) (`^2.1.2`) — Automated test runner.
- [`tsx`](https://www.npmjs.com/package/tsx) (`^4.19.1`) — TypeScript execution for local checks.
- [`@types/node`](https://www.npmjs.com/package/@types/node) (`^22.7.5`) — Node.js type definitions.

---

## Installation & Developer Quickstart

### Clean Checkout Workflow (for Developers & Contributors)

```bash
# Clone the repository
git clone https://github.com/SanskarArnale-07/SupaGuard.git
cd SupaGuard

# Install exact dependencies from lockfile
npm ci

# Build the TypeScript project
npm run build

# Run the complete test suite
npm test

# Verify package tarball creation
npm pack --dry-run
```

### Installation in a Supabase Project

```bash
# Install as a dev dependency
npm install --save-dev supaguard

# Run preflight check
npx supaguard check
```

### Global Installation

```bash
npm install -g supaguard

# Run from your Supabase project root
supaguard check
```

---

## Command-Line Usage

### Commands and Options

```bash
supaguard check [options]
```

| Option | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `--config <path>` | `-c` | `./supabase/config.toml` | Path to `supabase/config.toml` or the project root directory. |
| `--format <format>` | `-f` | `text` | Output format: `text` (terminal ANSI) or `json` (machine-readable). |
| `--strict` | `-s` | `false` | Strict mode: exits with code `1` on any finding (including `MEDIUM`, `LOW`, and `INFO`). |
| `--help` | `-h` | — | Display command help and available options. |
| `--version` | `-V` | — | Output SupaGuard version number. |

### Usage Examples

#### 1. Standard Preflight Check
Run from your project root (automatically locates `./supabase/config.toml`):
```bash
supaguard check
```

#### 2. Custom Path
Specify a direct file path or a custom project directory:
```bash
supaguard check --config ./custom/path/to/supabase/config.toml
```

#### 3. Machine-Readable JSON Output
Ideal for CI/CD pipelines, pre-commit hooks, and integration with security dashboards:
```bash
supaguard check --format json
```

#### 4. Strict Mode
Fails on any finding, including non-blocking advisories:
```bash
supaguard check --strict
```

---

## Exit Codes

SupaGuard uses deterministic exit codes to integrate cleanly with automated workflows:

| Exit Code | Constant | Meaning | Condition |
| :---: | :--- | :--- | :--- |
| **`0`** | `SUCCESS` | Preflight Passed | **Standard mode**: 0 `CRITICAL` and 0 `HIGH` findings.<br>**Strict mode**: 0 total findings. |
| **`1`** | `SECURITY_FINDINGS` | Preflight Failed | **Standard mode**: 1 or more `CRITICAL` or `HIGH` findings.<br>**Strict mode**: 1 or more findings of any severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`). |
| **`2`** | `CONFIG_ERROR` | Execution Aborted | Target configuration file not found, unreadable, or contains invalid TOML syntax. |

---

## Security Rules & Severity Classification

SupaGuard includes 13 built-in security rules mapped to specific settings defined in the [official Supabase CLI configuration specification](https://supabase.com/docs/guides/local-development/cli/config):

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

---

## Detailed Rule Explanations & Policy Assumptions

### `SEC-SEC-001`: Plaintext Secrets (`CRITICAL`)
- **What it checks**: Detects unencrypted credentials, static API keys, and passwords committed directly into `config.toml`.
- **Policy Assumption**: Production secrets should never exist in version-controlled files.
- **Remediation**: Use `env(VARIABLE_NAME)` substitution (e.g., `secret = "env(GITHUB_CLIENT_SECRET)"`).

### `SEC-API-001`: Internal System Schema in API List (`HIGH`)
- **What it checks**: Flags internal database schemas (`auth`, `vault`, `pg_catalog`, `information_schema`, `supabase_functions`, etc.) included in `api.schemas`.
- **Nuance & Postgres Permission Model**: Exposing a schema in PostgREST exposes endpoints and OpenAPI definitions. Actual data reading and writing remains governed by PostgreSQL role privileges (`GRANT USAGE`, `GRANT SELECT`) and Row Level Security. However, exposing internal schemas unnecessarily expands the attack surface if database permissions are ever misconfigured.
- **Remediation**: Remove internal schemas from `api.schemas`. Access authentication and secrets via official Supabase client SDKs.

### `SEC-DB-001`: Session Replication Role Set to Replica (`HIGH`)
- **What it checks**: Flags `db.settings.session_replication_role = "replica"`.
- **Impact**: In PostgreSQL, `replica` mode bypasses foreign key checks and user triggers, creating data integrity risks.
- **Remediation**: Remove the setting or set it to `"origin"`.

### `SEC-AUTH-001`: Refresh Token Rotation Disabled (`HIGH`)
- **What it checks**: Flags `auth.enable_refresh_token_rotation = false`.
- **Impact**: Allows intercepted refresh tokens to be replayed indefinitely without invalidation.
- **Remediation**: Enable refresh token rotation (`auth.enable_refresh_token_rotation = true`).

### `SEC-AUTH-002`: Email Change Double Confirmation Disabled (`HIGH`)
- **What it checks**: Flags `auth.email.double_confirm_changes = false`.
- **Impact**: Allows an attacker with temporary session access to redirect the account email to a new address without confirmation from the original mailbox.
- **Remediation**: Enable double confirmation (`auth.email.double_confirm_changes = true`).

### `SEC-AUTH-003`: OIDC Nonce Validation Bypassed (`HIGH`)
- **What it checks**: Flags `skip_nonce_check = true` on external OIDC providers.
- **Impact**: Disables cryptographic nonce validation, enabling token replay attacks.
- **Remediation**: Remove `skip_nonce_check` or set it to `false`.

### `SEC-AUTH-004`: Insecure / Permissive Redirect URLs (`HIGH` / `LOW`)
- **Three-Tier Classification**:
  1. **Unencrypted Remote HTTP** (`HIGH`): Cleartext remote redirect URLs (e.g. `http://my-app.com/callback`) expose authorization codes in transit.
  2. **Open / Unscoped Multi-Tenant Wildcards** (`HIGH`): Broad wildcards (`*`, `https://*`, `https://*.vercel.app/**`, `https://*.netlify.app/**`) allow attackers to register arbitrary subdomains to steal OAuth tokens.
  3. **Scoped Preview Deployment Wildcards** (`LOW`): Scoped patterns (e.g. `https://*-myteam.vercel.app/**`) are officially supported by Supabase for preview branches. They trigger a low-severity advisory recommending exact URLs for production.
- **Allowed**: Exact HTTPS callback URLs and `localhost` development URLs.

### `SEC-AUTH-005`: Static SMS Test OTP Present (`HIGH`)
- **What it checks**: Flags the presence of `[auth.sms.test_otp]`.
- **Impact**: Fixed verification codes permit authentication bypass if carried into staging or production.
- **Remediation**: Remove the `[auth.sms.test_otp]` table before deploying.

### `SEC-AUTH-006`: Excessive JWT Expiration Lifetime (`MEDIUM`)
- **What it checks**: Flags `auth.jwt_expiry` exceeding 86,400 seconds (24 hours).
- **Impact**: JWTs are bearer tokens that cannot be revoked without rotating project JWT secrets.
- **Remediation**: Reduce `auth.jwt_expiry` to 3600 seconds (1 hour) and rely on refresh token rotation.

### `SEC-AUTH-007`: OAuth Provider Missing Credentials (`MEDIUM`)
- **What it checks**: Flags enabled OAuth providers where `client_id` or `secret` is missing or empty.
- **Impact**: Prevents runtime authentication failures in deployed environments.
- **Remediation**: Provide valid `env(...)` references for required credentials.

### `SEC-FN-001`: Edge Function JWT Verification Disabled (`MEDIUM`)
- **What it checks**: Flags Edge Functions configured with `verify_jwt = false`.
- **False-Positive Consideration**: External webhooks (e.g. Stripe, GitHub) intentionally disable JWT verification because they authenticate requests using HMAC signatures. In these cases, this finding serves as a verification prompt rather than an exploitable defect.
- **Remediation**: If the function is not a public webhook, set `verify_jwt = true`. If it is a webhook, confirm that signature verification is implemented in the function code.

### `SEC-AUTH-008`: Password Re-Authentication Disabled (`LOW`)
- **What it checks**: Flags `auth.email.secure_password_change = false`.
- **Impact**: Allows users to change passwords without confirming their current password.
- **Remediation**: Set `auth.email.secure_password_change = true`.

### `SEC-ST-001`: Storage Bucket Configured for Public Access (`INFO`)
- **What it checks**: Notifies when a storage bucket is marked `public = true`.
- **False-Positive Consideration**: Public buckets are a standard feature for hosting publicly accessible assets (such as profile avatars or marketing images). This check is categorized as `INFO` to provide visibility without failing standard preflight checks.
- **Remediation**: Ensure the bucket only contains publicly accessible assets. For sensitive data, set `public = false` and use signed URLs or RLS policies.

---

## Output Formats

### Terminal Output (`--format text`)
Terminal reports display ANSI-colored, formatted findings grouped by severity, complete with configuration path, observed value, rationale, policy assumption, and recommended remediation:

```
======================================================================
 SupaGuard — Supabase Security Preflight Analyzer
======================================================================
Target File: ./supabase/config.toml
Timestamp:   2026-10-12T15:00:00.000Z
Mode:        Standard (high/critical fail)
Rules Checked: 13
----------------------------------------------------------------------

[1/1] [CRITICAL] Plaintext Secret in Configuration File (SEC-SEC-001)
   Config Path:      auth.external.github.secret
   Observed Value:   [REDACTED_SECRET (length: 32)]
   Category:         secrets
   Rationale:        The setting "auth.external.github.secret" contains an unencrypted plaintext credential or literal secret.
   Policy Assumption: All secrets in config.toml must reference environment variables via env(VARIABLE_NAME).
   ➜ Remediation:    Replace the hardcoded secret at "auth.external.github.secret" with an environment variable reference, e.g. 'env(YOUR_SECRET_NAME)'.

----------------------------------------------------------------------
Summary Findings:
  Critical: 1
  High:     0
  Medium:   0
  Low:      0
  Info:     0
----------------------------------------------------------------------
✖ PREFLIGHT FAILED: One or more high/critical security findings require remediation.
```

### JSON Output (`--format json`)
Emits strictly valid JSON structured for programmatic parsing:

```json
{
  "targetPath": "D:\\my-project\\supabase\\config.toml",
  "strict": false,
  "timestamp": "2026-10-12T15:00:00.000Z",
  "findings": [
    {
      "ruleId": "SEC-SEC-001",
      "ruleTitle": "Plaintext Secret in Configuration File",
      "severity": "critical",
      "category": "secrets",
      "path": "auth.external.github.secret",
      "observedValue": "[REDACTED_SECRET (length: 32)]",
      "rationale": "The setting \"auth.external.github.secret\" contains an unencrypted plaintext credential or literal secret.",
      "policyAssumption": "All secrets in config.toml must reference environment variables via env(VARIABLE_NAME).",
      "remediation": "Replace the hardcoded secret at \"auth.external.github.secret\" with an environment variable reference, e.g. 'env(YOUR_SECRET_NAME)'."
    }
  ],
  "summary": {
    "totalRulesEvaluated": 13,
    "totalFindings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "passed": false
  },
  "exitCode": 1
}
```

---

## Known Limitations

1. **Local-Only Configuration Scope**: SupaGuard only inspects `supabase/config.toml`. It does not analyze SQL migration scripts, database permissions, or remote cloud resources.
2. **PostgreSQL Runtime Permissions**: Settings such as `api.schemas` declare routing visibility in PostgREST, but effective database access depends on PostgreSQL table permissions and Row Level Security (RLS) policies.
3. **Secret Presence vs. Secret Validity**: SupaGuard confirms that secrets are parameterized via `env(...)` and not committed as plaintext. It does not verify whether the referenced environment variables exist or contain valid credentials.
4. **No Automatic File Fixes**: SupaGuard is an analyzer and reporter; it never automatically modifies configuration files.

---

## License

This project is licensed under the [MIT License](LICENSE).