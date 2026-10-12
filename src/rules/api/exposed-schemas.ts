import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

const SENSITIVE_SCHEMAS = new Set([
  'auth',
  'vault',
  'pg_catalog',
  'information_schema',
  'supabase_functions',
  'extensions',
  'cron',
  'net',
  'graphql',
]);

export const exposedSchemasRule: SecurityRule = {
  id: 'SEC-API-001',
  title: 'Internal System Schema Configured in API Exposure List',
  category: 'api',
  severity: 'high',
  description:
    'Detects internal or administrative database schemas (such as auth or vault) included in api.schemas.',
  policyAssumption:
    'PostgREST should only expose application data schemas (e.g. "public"). Internal engine schemas manage credentials and system state and must remain unmapped at the API routing layer.',
  check(context: RuleContext): Finding[] {
    const path = 'api.schemas';
    if (!context.hasExplicitPath(path)) {
      return [];
    }

    const schemas = context.getExplicitValue<unknown>(path);
    if (!Array.isArray(schemas)) {
      return [];
    }

    const findings: Finding[] = [];

    for (let i = 0; i < schemas.length; i++) {
      const schemaName = schemas[i];
      if (typeof schemaName !== 'string') continue;

      const normalized = schemaName.trim().toLowerCase();
      if (SENSITIVE_SCHEMAS.has(normalized)) {
        findings.push({
          ruleId: 'SEC-API-001',
          ruleTitle: 'Internal System Schema Configured in API Exposure List',
          severity: 'high',
          category: 'api',
          path: `${path}[${i}]`,
          observedValue: `"${schemaName}"`,
          rationale: `The internal schema "${schemaName}" is listed in "api.schemas". This instructs PostgREST to register HTTP endpoints and expose schema metadata for tables, views, and functions within "${schemaName}". While actual table data reading or writing is still governed by PostgreSQL role privileges (GRANT USAGE/SELECT) and Row Level Security, exposing internal schemas unnecessarily widens the API attack surface and creates severe exposure risks if database permissions are ever granted or misconfigured.`,
          policyAssumption:
            'Internal schemas containing authentication data, encrypted credentials, or system catalogs should never be mapped to PostgREST HTTP routes. Client applications should interact strictly through dedicated service APIs (e.g. Supabase Auth).',
          remediation: `Remove "${schemaName}" from the "api.schemas" array in supabase/config.toml. Use the standard Supabase client SDKs to interact with auth or vault services.`,
        });
      }
    }

    return findings;
  },
};
