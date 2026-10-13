import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { analyzeConfig } from '../../src/analyzer/index.js';
import { discoverMigrations, resolveMigrationsDir } from '../../src/migrations/discover.js';
import { isTenantColumnName, isUnrestrictedPredicate, isUserColumnName, offsetToLineAndColumn, parseMigrationSql } from '../../src/migrations/parser.js';
import { buildMigrationDatabaseState } from '../../src/migrations/state.js';
import type { MigrationFile } from '../../src/migrations/types.js';
import { checkMissingRls } from '../../src/rules/migrations/missing-rls.js';
import { checkSuspiciousPolicies } from '../../src/rules/migrations/suspicious-policies.js';
import { ExitCode } from '../../src/types/exit-codes.js';

describe('SQL Migration Security Scanner Suite', () => {
  const fixturesDir = path.resolve(__dirname, '../fixtures');

  describe('Discovery & Ordering', () => {
    it('discovers migrations and sorts them in deterministic filename order', () => {
      const secureDir = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
      const migrations = discoverMigrations({ configPath: secureDir });

      expect(migrations.length).toBe(4);
      expect(migrations[0].filename).toBe('20240101000000_create_tables.sql');
      expect(migrations[1].filename).toBe('20240102000000_enable_later.sql');
      expect(migrations[2].filename).toBe('20240103000000_alter_and_drop.sql');
      expect(migrations[3].filename).toBe('20240104000000_public_read.sql');
    });

    it('gracefully handles missing migrations directory without error', () => {
      const normalConfig = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');
      const migrations = discoverMigrations({ configPath: normalConfig });
      expect(migrations).toEqual([]);
    });

    it('gracefully handles non-existent config path', () => {
      const ghostConfig = path.join(fixturesDir, 'ghost_dir', 'supabase', 'config.toml');
      const migrations = discoverMigrations({ configPath: ghostConfig });
      expect(migrations).toEqual([]);
    });

    it('throws an error when explicitly supplied migrationsDir does not exist', () => {
      expect(() => {
        discoverMigrations({ migrationsDir: './nonexistent/path/to/migrations' });
      }).toThrow('Explicit migrations directory not found');
    });

    it('throws an error when explicitly supplied migrationsDir points to a file', () => {
      const filePath = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
      expect(() => {
        discoverMigrations({ migrationsDir: filePath });
      }).toThrow('Explicit migrations path is not a directory');
    });

    it('preserves diagnostics for unreadable migration files using dependency injection', () => {
      const secureConfig = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
      const result = discoverMigrations({
        configPath: secureConfig,
        readFileSync: (filePath, encoding) => {
          if (filePath.includes('20240101000000_create_tables.sql')) {
            const err = new Error('Permission denied');
            (err as any).code = 'EACCES';
            throw err;
          }
          return fs.readFileSync(filePath, encoding);
        },
      });

      expect(result.length).toBe(3);
      expect(result.readErrors.length).toBe(1);
      expect(result.readErrors[0].filename).toBe('20240101000000_create_tables.sql');
      expect(result.readErrors[0].error).toContain('EACCES');
    });

    it('emits high severity SEC-MIG-READ-ERR and fails preflight when unreadable migrations exist', async () => {
      const fakeConfig = {
        filePath: '/workspace/supabase/config.toml',
        parsed: { api: { schemas: ['public'] } },
        explicitPaths: new Set(['api.schemas']),
      };
      const analysis = await analyzeConfig(fakeConfig as any, {
        unreadableMigrations: [
          {
            filename: '20240101000000_secret.sql',
            absolutePath: '/workspace/supabase/migrations/20240101000000_secret.sql',
            relativePath: 'supabase/migrations/20240101000000_secret.sql',
            error: 'Cannot read file: EACCES: permission or read error',
          },
        ],
      });

      expect(analysis.summary.passed).toBe(false);
      expect(analysis.exitCode).toBe(ExitCode.SECURITY_FINDINGS);
      const readFinding = analysis.findings.find((f) => f.ruleId === 'SEC-MIG-READ-ERR');
      expect(readFinding).toBeDefined();
      expect(readFinding?.severity).toBe('high');
      expect(readFinding?.rationale).toContain('incomplete');
      expect(readFinding?.observedValue).toBe('Cannot read file: EACCES: permission or read error');
    });

    it('emits high severity SEC-MIG-PARSE-ERR and fails standard mode preflight for syntax errors', async () => {
      const fakeConfig = {
        filePath: '/workspace/supabase/config.toml',
        parsed: { api: { schemas: ['public'] } },
        explicitPaths: new Set(['api.schemas']),
      };
      const analysis = await analyzeConfig(fakeConfig as any, {
        migrations: [
          {
            filename: '20240101000000_bad.sql',
            absolutePath: '/workspace/supabase/migrations/20240101000000_bad.sql',
            relativePath: 'supabase/migrations/20240101000000_bad.sql',
            content: 'CREATE TABLE incomplete (',
          },
        ],
      });

      expect(analysis.summary.passed).toBe(false);
      expect(analysis.exitCode).toBe(ExitCode.SECURITY_FINDINGS);
      const parseFinding = analysis.findings.find((f) => f.ruleId === 'SEC-MIG-PARSE-ERR');
      expect(parseFinding).toBeDefined();
      expect(parseFinding?.severity).toBe('high');
      expect(parseFinding?.rationale).toContain('incomplete');
    });

    it('fails preflight in analyzeConfig when discoveryOptions injects an unreadable migration', async () => {
      const secureConfig = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
      const loaded = {
        filePath: secureConfig,
        parsed: { api: { schemas: ['public'] } },
        explicitPaths: new Set(['api.schemas']),
      };
      const analysis = await analyzeConfig(loaded as any, {
        discoveryOptions: {
          readFileSync: (filePath, encoding) => {
            if (filePath.includes('20240101000000_create_tables.sql')) {
              const err = new Error('Permission denied');
              (err as any).code = 'EACCES';
              throw err;
            }
            return fs.readFileSync(filePath, encoding);
          },
        },
      });

      expect(analysis.summary.passed).toBe(false);
      expect(analysis.exitCode).toBe(ExitCode.SECURITY_FINDINGS);
      const readFinding = analysis.findings.find((f) => f.ruleId === 'SEC-MIG-READ-ERR');
      expect(readFinding).toBeDefined();
      expect(readFinding?.severity).toBe('high');
      expect(readFinding?.path).toContain('20240101000000_create_tables.sql');
    });

    it('captures structured discovery diagnostic when stat on located migrations directory throws', () => {
      const secureConfig = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
      const result = discoverMigrations({
        configPath: secureConfig,
        statSync: (targetPath) => {
          if (targetPath.replace(/\\/g, '/').endsWith('supabase/migrations')) {
            const err = new Error('Permission denied');
            (err as any).code = 'EACCES';
            throw err;
          }
          return fs.statSync(targetPath);
        },
      });

      expect(result.length).toBe(0);
      expect(result.discoveryErrors.length).toBe(1);
      expect(result.discoveryErrors[0].error).toContain('Cannot inspect migrations directory');
      expect(result.discoveryErrors[0].error).toContain('EACCES');
    });

    it('captures structured discovery diagnostic when listing located migrations directory throws', () => {
      const secureConfig = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
      const result = discoverMigrations({
        configPath: secureConfig,
        readdirSync: () => {
          const err = new Error('Permission denied');
          (err as any).code = 'EACCES';
          throw err;
        },
      });

      expect(result.length).toBe(0);
      expect(result.discoveryErrors.length).toBe(1);
      expect(result.discoveryErrors[0].error).toContain('Cannot list migrations directory');
      expect(result.discoveryErrors[0].error).toContain('EACCES');
    });

    it('emits high severity SEC-MIG-DISCOVERY-ERR and fails preflight in analyzeConfig when directory inspection fails', async () => {
      const secureConfig = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
      const loaded = {
        filePath: secureConfig,
        parsed: { api: { schemas: ['public'] } },
        explicitPaths: new Set(['api.schemas']),
      };
      const analysis = await analyzeConfig(loaded as any, {
        discoveryOptions: {
          statSync: (targetPath) => {
            if (targetPath.replace(/\\/g, '/').endsWith('supabase/migrations')) {
              const err = new Error('Permission denied');
              (err as any).code = 'EACCES';
              throw err;
            }
            return fs.statSync(targetPath);
          },
        },
      });

      expect(analysis.summary.passed).toBe(false);
      expect(analysis.exitCode).toBe(ExitCode.SECURITY_FINDINGS);
      const discFinding = analysis.findings.find((f) => f.ruleId === 'SEC-MIG-DISCOVERY-ERR');
      expect(discFinding).toBeDefined();
      expect(discFinding?.severity).toBe('high');
      expect(discFinding?.rationale).toContain('incomplete');
      expect(discFinding?.observedValue).toContain('EACCES');
    });

    it('emits high severity SEC-MIG-DISCOVERY-ERR and fails preflight in analyzeConfig when directory listing fails', async () => {
      const secureConfig = path.join(fixturesDir, 'secure_with_migrations', 'supabase', 'config.toml');
      const loaded = {
        filePath: secureConfig,
        parsed: { api: { schemas: ['public'] } },
        explicitPaths: new Set(['api.schemas']),
      };
      const analysis = await analyzeConfig(loaded as any, {
        discoveryOptions: {
          readdirSync: () => {
            const err = new Error('Permission denied');
            (err as any).code = 'EACCES';
            throw err;
          },
        },
      });

      expect(analysis.summary.passed).toBe(false);
      expect(analysis.exitCode).toBe(ExitCode.SECURITY_FINDINGS);
      const discFinding = analysis.findings.find((f) => f.ruleId === 'SEC-MIG-DISCOVERY-ERR');
      expect(discFinding).toBeDefined();
      expect(discFinding?.severity).toBe('high');
      expect(discFinding?.rationale).toContain('incomplete');
      expect(discFinding?.observedValue).toContain('EACCES');
    });

    it('preserves clean pass without discovery errors for normal project without migrations directory', async () => {
      const normalConfig = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');
      const loaded = {
        filePath: normalConfig,
        parsed: { api: { schemas: ['public'] } },
        explicitPaths: new Set(['api.schemas']),
      };
      const analysis = await analyzeConfig(loaded as any);
      expect(analysis.summary.passed).toBe(true);
      expect(analysis.exitCode).toBe(ExitCode.SUCCESS);
      const discFinding = analysis.findings.find((f) => f.ruleId === 'SEC-MIG-DISCOVERY-ERR');
      expect(discFinding).toBeUndefined();
    });
  });

  describe('SQL Parser & AST Diagnostics', () => {
    it('accurately computes line and column numbers from character offsets', () => {
      const sql = 'SELECT 1;\nSELECT 2;\nSELECT 3;';
      expect(offsetToLineAndColumn(sql, 0)).toEqual({ line: 1, column: 1 });
      expect(offsetToLineAndColumn(sql, 10)).toEqual({ line: 2, column: 1 });
      expect(offsetToLineAndColumn(sql, 20)).toEqual({ line: 3, column: 1 });
    });

    it('detects unconditionally true predicates', () => {
      // Literal boolean true
      expect(isUnrestrictedPredicate({ A_Const: { boolval: { boolval: true } } })).toBe(true);
      // Literal boolean false
      expect(isUnrestrictedPredicate({ A_Const: { boolval: { boolval: false } } })).toBe(false);

      // Tautology: 1 = 1
      const tautologyNode = {
        A_Expr: {
          kind: 'AEXPR_OP',
          name: [{ String: { sval: '=' } }],
          lexpr: { A_Const: { ival: { ival: 1 } } },
          rexpr: { A_Const: { ival: { ival: 1 } } },
        },
      };
      expect(isUnrestrictedPredicate(tautologyNode)).toBe(true);

      // Non-tautology: 1 = 2
      const falseNode = {
        A_Expr: {
          kind: 'AEXPR_OP',
          name: [{ String: { sval: '=' } }],
          lexpr: { A_Const: { ival: { ival: 1 } } },
          rexpr: { A_Const: { ival: { ival: 2 } } },
        },
      };
      expect(isUnrestrictedPredicate(falseNode)).toBe(false);

      // Null or arbitrary expression
      expect(isUnrestrictedPredicate(null)).toBe(false);
      expect(isUnrestrictedPredicate(undefined)).toBe(false);
    });

    it('safely handles syntax errors without throwing exceptions', async () => {
      const result = await parseMigrationSql('CREATE TABLE valid (id int);\nINVALID SQL SYNTAX HERE !!!;');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.line).toBe(2);
        expect(result.error.message).toBeDefined();
      }
    });

    it('ignores commented SQL statements and quoted string literals', async () => {
      const sql = `
        -- ALTER TABLE "public"."users" DISABLE ROW LEVEL SECURITY;
        /*
          CREATE POLICY "hack" ON "public"."users" FOR ALL USING (true);
        */
        CREATE TABLE "public"."notes" (
          id int,
          content text DEFAULT 'ALTER TABLE "public"."notes" DISABLE ROW LEVEL SECURITY'
        );
      `;

      const result = await parseMigrationSql(sql);
      expect(result.success).toBe(true);
      if (result.success) {
        // Only 1 statement should be parsed: the CREATE TABLE statement
        expect(result.statements.length).toBe(1);
        expect(result.statements[0].stmt.CreateStmt).toBeDefined();
      }
    });
  });

  describe('Database State Tracking Across Migration History', () => {
    it('tracks table creation and subsequent RLS enablement across migrations', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_create.sql',
          relativePath: 'supabase/migrations/01_create.sql',
          absolutePath: '/app/supabase/migrations/01_create.sql',
          content: 'CREATE TABLE "public"."users" (id int);',
        },
        {
          filename: '02_enable.sql',
          relativePath: 'supabase/migrations/02_enable.sql',
          absolutePath: '/app/supabase/migrations/02_enable.sql',
          content: 'ALTER TABLE "public"."users" ENABLE ROW LEVEL SECURITY;',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const table = state.tables.get('public.users');

      expect(table).toBeDefined();
      expect(table?.rowLevelSecurityEnabled).toBe(true);
      expect(table?.createdIn.file).toBe('supabase/migrations/01_create.sql');
      expect(table?.rlsChangedIn?.file).toBe('supabase/migrations/02_enable.sql');
    });

    it('tracks subsequent RLS disabling', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_create_and_enable.sql',
          relativePath: 'supabase/migrations/01_create_and_enable.sql',
          absolutePath: '/app/01.sql',
          content: 'CREATE TABLE "public"."orders" (id int);\nALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;',
        },
        {
          filename: '02_disable.sql',
          relativePath: 'supabase/migrations/02_disable.sql',
          absolutePath: '/app/02.sql',
          content: 'ALTER TABLE "public"."orders" DISABLE ROW LEVEL SECURITY;',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const table = state.tables.get('public.orders');

      expect(table?.rowLevelSecurityEnabled).toBe(false);
      expect(table?.rlsChangedIn?.enabled).toBe(false);
      expect(table?.rlsChangedIn?.file).toBe('supabase/migrations/02_disable.sql');
    });

    it('tracks table drops across migrations', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_create.sql',
          relativePath: 'supabase/migrations/01_create.sql',
          absolutePath: '/app/01.sql',
          content: 'CREATE TABLE "public"."temp" (id int);',
        },
        {
          filename: '02_drop.sql',
          relativePath: 'supabase/migrations/02_drop.sql',
          absolutePath: '/app/02.sql',
          content: 'DROP TABLE "public"."temp";',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const table = state.tables.get('public.temp');

      expect(table?.dropped).toBe(true);
      expect(table?.droppedIn?.file).toBe('supabase/migrations/02_drop.sql');
    });

    it('tracks policy creation, modification, and deletion across migrations', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_policy.sql',
          relativePath: 'supabase/migrations/01_policy.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."items" (id int);
            ALTER TABLE "public"."items" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Policy A" ON "public"."items" FOR ALL USING (true);
            CREATE POLICY "Policy B" ON "public"."items" FOR SELECT USING (true);
          `,
        },
        {
          filename: '02_mutate.sql',
          relativePath: 'supabase/migrations/02_mutate.sql',
          absolutePath: '/app/02.sql',
          content: `
            -- Drop Policy A
            DROP POLICY "Policy A" ON "public"."items";
            -- Alter Policy B to be restrictive
            ALTER POLICY "Policy B" ON "public"."items" USING (auth.uid() = id);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const table = state.tables.get('public.items');

      expect(table?.policies.get('Policy A')?.dropped).toBe(true);
      expect(table?.policies.get('Policy B')?.dropped).toBe(false);
      expect(table?.policies.get('Policy B')?.isUnrestrictedUsing).toBe(false);
      expect(table?.policies.get('Policy B')?.modifiedIn?.file).toBe('supabase/migrations/02_mutate.sql');
    });
  });

  describe('Rule SEC-MIG-RLS-001: Missing RLS on API-Exposed Tables', () => {
    it('flags table without RLS in exposed schema', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_unprotected.sql',
          relativePath: 'supabase/migrations/01_unprotected.sql',
          absolutePath: '/app/01.sql',
          content: 'CREATE TABLE "public"."customers" (id int, email text);',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkMissingRls(state, { exposedSchemas: ['public'] });

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-MIG-RLS-001');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].table).toBe('customers');
      expect(findings[0].path).toBe('supabase/migrations/01_unprotected.sql:1');
    });

    it('does NOT flag table with RLS enabled in creation migration', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_protected.sql',
          relativePath: 'supabase/migrations/01_protected.sql',
          absolutePath: '/app/01.sql',
          content: 'CREATE TABLE "public"."customers" (id int);\nALTER TABLE "public"."customers" ENABLE ROW LEVEL SECURITY;',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkMissingRls(state, { exposedSchemas: ['public'] });

      expect(findings).toHaveLength(0);
    });

    it('does NOT flag table whose RLS is enabled in a later migration', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_create.sql',
          relativePath: 'supabase/migrations/01_create.sql',
          absolutePath: '/app/01.sql',
          content: 'CREATE TABLE "public"."customers" (id int);',
        },
        {
          filename: '02_enable.sql',
          relativePath: 'supabase/migrations/02_enable.sql',
          absolutePath: '/app/02.sql',
          content: 'ALTER TABLE "public"."customers" ENABLE ROW LEVEL SECURITY;',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkMissingRls(state, { exposedSchemas: ['public'] });

      expect(findings).toHaveLength(0);
    });

    it('flags table whose RLS is subsequently disabled in a later migration', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_enable.sql',
          relativePath: 'supabase/migrations/01_enable.sql',
          absolutePath: '/app/01.sql',
          content: 'CREATE TABLE "public"."customers" (id int);\nALTER TABLE "public"."customers" ENABLE ROW LEVEL SECURITY;',
        },
        {
          filename: '02_disable.sql',
          relativePath: 'supabase/migrations/02_disable.sql',
          absolutePath: '/app/02.sql',
          content: 'ALTER TABLE "public"."customers" DISABLE ROW LEVEL SECURITY;',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkMissingRls(state, { exposedSchemas: ['public'] });

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-MIG-RLS-001');
    });

    it('does NOT flag table created and later dropped', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_create.sql',
          relativePath: 'supabase/migrations/01_create.sql',
          absolutePath: '/app/01.sql',
          content: 'CREATE TABLE "public"."temp" (id int);',
        },
        {
          filename: '02_drop.sql',
          relativePath: 'supabase/migrations/02_drop.sql',
          absolutePath: '/app/02.sql',
          content: 'DROP TABLE "public"."temp";',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkMissingRls(state, { exposedSchemas: ['public'] });

      expect(findings).toHaveLength(0);
    });

    it('does NOT flag tables in non-exposed schemas', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_private.sql',
          relativePath: 'supabase/migrations/01_private.sql',
          absolutePath: '/app/01.sql',
          content: 'CREATE TABLE "internal_schema"."secrets" (id int);',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkMissingRls(state, { exposedSchemas: ['public'] });

      expect(findings).toHaveLength(0);
    });
  });

  describe('Rule SEC-MIG-RLS-002: Suspicious RLS Policies', () => {
    it('flags unrestricted write policy for anonymous or public roles with HIGH severity', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_write.sql',
          relativePath: 'supabase/migrations/01_write.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."feedback" (id int);
            ALTER TABLE "public"."feedback" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Anon insert" ON "public"."feedback" FOR INSERT TO anon WITH CHECK (true);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-MIG-RLS-002');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].observedValue).toContain('Anon insert');
    });

    it('flags unrestricted update/delete for authenticated role with MEDIUM severity', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_auth_mod.sql',
          relativePath: 'supabase/migrations/01_auth_mod.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."posts" (id int);
            ALTER TABLE "public"."posts" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Auth update all" ON "public"."posts" FOR UPDATE TO authenticated USING (true);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-MIG-RLS-002');
      expect(findings[0].severity).toBe('medium');
    });

    it('reports intentionally public read-only policy as INFO severity advisory', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_public_read.sql',
          relativePath: 'supabase/migrations/01_public_read.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."catalog" (id int);
            ALTER TABLE "public"."catalog" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Public read" ON "public"."catalog" FOR SELECT TO anon, authenticated USING (true);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('SEC-MIG-RLS-002');
      expect(findings[0].severity).toBe('info');
    });

    it('does NOT flag restrictive policies', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_restrictive.sql',
          relativePath: 'supabase/migrations/01_restrictive.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."user_profiles" (id uuid);
            ALTER TABLE "public"."user_profiles" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Owner read" ON "public"."user_profiles" FOR SELECT TO authenticated USING (auth.uid() = id);
            CREATE POLICY "Owner write" ON "public"."user_profiles" FOR UPDATE TO authenticated USING (auth.uid() = id) WITH CHECK (auth.uid() = id);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      expect(findings).toHaveLength(0);
    });

    it('does NOT flag a policy dropped by a later migration', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_create_bad.sql',
          relativePath: 'supabase/migrations/01_create_bad.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."records" (id int);
            ALTER TABLE "public"."records" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Bad write" ON "public"."records" FOR INSERT TO anon WITH CHECK (true);
          `,
        },
        {
          filename: '02_drop_bad.sql',
          relativePath: 'supabase/migrations/02_drop_bad.sql',
          absolutePath: '/app/02.sql',
          content: 'DROP POLICY "Bad write" ON "public"."records";',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      expect(findings).toHaveLength(0);
    });

    it('flags UPDATE policy with permissive USING (true) when WITH CHECK is restrictive as low severity', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_update_checked.sql',
          relativePath: 'supabase/migrations/01_update_checked.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."profiles" (id uuid, user_id uuid, bio text);
            ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Update own profile" ON "public"."profiles"
              FOR UPDATE
              TO authenticated
              USING (true)
              WITH CHECK (auth.uid() = user_id);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe('low');
      expect(findings[0].ruleTitle).toBe('Permissive USING on UPDATE Policy with Restrictive WITH CHECK');
      expect(findings[0].rationale).toContain('cross-row');
    });

    it('flags UPDATE policy with omitted USING clause when WITH CHECK is restrictive', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_update_omitted_using.sql',
          relativePath: 'supabase/migrations/01_update_omitted_using.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."profiles" (id uuid, user_id uuid, bio text);
            ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Update own profile" ON "public"."profiles"
              FOR UPDATE
              TO authenticated
              WITH CHECK (auth.uid() = user_id);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe('low');
      expect(findings[0].ruleTitle).toBe('Permissive USING on UPDATE Policy with Restrictive WITH CHECK');
      expect(findings[0].observedValue).toContain('omitted USING');
    });

    it('flags anon UPDATE policy with permissive USING (true) when WITH CHECK is restrictive as medium severity', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_anon_checked.sql',
          relativePath: 'supabase/migrations/01_anon_checked.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."invite_tokens" (id serial, token text, used boolean);
            ALTER TABLE "public"."invite_tokens" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Redeem token" ON "public"."invite_tokens"
              FOR UPDATE
              TO anon
              USING (true)
              WITH CHECK (used = false);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].ruleTitle).toBe('Permissive USING on UPDATE Policy with Restrictive WITH CHECK');
    });

    it('passes cleanly when UPDATE policy has restrictive USING and restrictive WITH CHECK', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_safe_update.sql',
          relativePath: 'supabase/migrations/01_safe_update.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."profiles" (id uuid, user_id uuid, bio text);
            ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Update own profile" ON "public"."profiles"
              FOR UPDATE
              TO authenticated
              USING (auth.uid() = user_id)
              WITH CHECK (auth.uid() = user_id);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      expect(findings).toHaveLength(0);
    });

    it('passes cleanly when UPDATE policy omits WITH CHECK and has restrictive USING (inheriting USING clause)', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_inherited_update.sql',
          relativePath: 'supabase/migrations/01_inherited_update.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."profiles" (id uuid, user_id uuid, bio text);
            ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Update own profile" ON "public"."profiles"
              FOR UPDATE
              TO authenticated
              USING (auth.uid() = user_id);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      // In Postgres, omitting WITH CHECK on UPDATE inherits USING (auth.uid() = user_id).
      // Both clauses are restrictive, so no findings are emitted.
      expect(findings).toHaveLength(0);
    });

    it('flags ALL policy with permissive USING (true) but restrictive WITH CHECK for unrestricted DELETE', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_all_checked.sql',
          relativePath: 'supabase/migrations/01_all_checked.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."documents" (id uuid, user_id uuid, body text);
            ALTER TABLE "public"."documents" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Manage docs" ON "public"."documents"
              FOR ALL
              TO authenticated
              USING (true)
              WITH CHECK (auth.uid() = user_id);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      // In PostgreSQL, ALL with USING (true) allows unrestricted DELETE (since DELETE ignores WITH CHECK)
      // and world-readable SELECT via USING (true)
      const deleteFinding = findings.find((f) => f.severity === 'medium');
      expect(deleteFinding).toBeDefined();
      expect(deleteFinding?.observedValue).toContain('DELETE');
      expect(deleteFinding?.rationale).toContain('DELETE commands evaluate only the USING clause');

      expect(findings).toHaveLength(1);
    });

    it('flags anon ALL policy with permissive USING (true) but restrictive WITH CHECK for unrestricted DELETE (HIGH)', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_anon_all_checked.sql',
          relativePath: 'supabase/migrations/01_anon_all_checked.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."guest_notes" (id int, note text);
            ALTER TABLE "public"."guest_notes" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Anon all" ON "public"."guest_notes"
              FOR ALL
              TO anon
              USING (true)
              WITH CHECK (note IS NOT NULL);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkSuspiciousPolicies(state);

      const highFinding = findings.find((f) => f.severity === 'high');
      expect(highFinding).toBeDefined();
      expect(highFinding?.observedValue).toContain('DELETE');
      expect(highFinding?.rationale).toContain('DELETE command evaluates only the USING clause');
    });
  });

  describe('Edge Cases: Tables Dropped & Recreated, Quoted Identifiers, Compound Predicates', () => {
    it('flags table dropped and later recreated without RLS', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_create_with_rls.sql',
          relativePath: 'supabase/migrations/01_create_with_rls.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."audit_log" (id int);
            ALTER TABLE "public"."audit_log" ENABLE ROW LEVEL SECURITY;
          `,
        },
        {
          filename: '02_drop.sql',
          relativePath: 'supabase/migrations/02_drop.sql',
          absolutePath: '/app/02.sql',
          content: 'DROP TABLE "public"."audit_log";',
        },
        {
          filename: '03_recreate_without_rls.sql',
          relativePath: 'supabase/migrations/03_recreate_without_rls.sql',
          absolutePath: '/app/03.sql',
          content: 'CREATE TABLE "public"."audit_log" (id int, message text);',
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkMissingRls(state, { exposedSchemas: ['public'] });

      expect(findings).toHaveLength(1);
      expect(findings[0].table).toBe('audit_log');
      expect(findings[0].filePath).toBe('supabase/migrations/03_recreate_without_rls.sql');
    });

    it('does NOT flag table dropped and later recreated WITH RLS enabled', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_create.sql',
          relativePath: 'supabase/migrations/01_create.sql',
          absolutePath: '/app/01.sql',
          content: 'CREATE TABLE "public"."audit_log" (id int);',
        },
        {
          filename: '02_drop.sql',
          relativePath: 'supabase/migrations/02_drop.sql',
          absolutePath: '/app/02.sql',
          content: 'DROP TABLE "public"."audit_log";',
        },
        {
          filename: '03_recreate_with_rls.sql',
          relativePath: 'supabase/migrations/03_recreate_with_rls.sql',
          absolutePath: '/app/03.sql',
          content: `
            CREATE TABLE "public"."audit_log" (id int);
            ALTER TABLE "public"."audit_log" ENABLE ROW LEVEL SECURITY;
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const findings = checkMissingRls(state, { exposedSchemas: ['public'] });

      expect(findings).toHaveLength(0);
    });

    it('handles quoted mixed-case identifiers consistently', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_quoted.sql',
          relativePath: 'supabase/migrations/01_quoted.sql',
          absolutePath: '/app/01.sql',
          content: `
            CREATE TABLE "public"."SpecialUsers" (id int);
            ALTER TABLE "public"."SpecialUsers" ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "AllowRead" ON "public"."SpecialUsers" FOR SELECT USING (true);
          `,
        },
      ];

      const state = await buildMigrationDatabaseState(migrations);
      const table = state.tables.get('public.SpecialUsers');

      expect(table).toBeDefined();
      expect(table?.rowLevelSecurityEnabled).toBe(true);
      expect(table?.policies.get('AllowRead')).toBeDefined();
    });

    it('evaluates type casts and compound boolean expressions (AND/OR tautologies)', () => {
      // 1. TypeCast: true::boolean
      const typeCastNode = {
        TypeCast: {
          arg: { A_Const: { boolval: { boolval: true } } },
          typeName: { names: [{ String: { sval: 'bool' } }] },
        },
      };
      expect(isUnrestrictedPredicate(typeCastNode)).toBe(true);

      // 2. AND_EXPR where all operands are true
      const andAllTrue = {
        BoolExpr: {
          boolop: 'AND_EXPR',
          args: [
            { A_Const: { boolval: { boolval: true } } },
            { A_Const: { boolval: { boolval: true } } },
          ],
        },
      };
      expect(isUnrestrictedPredicate(andAllTrue)).toBe(true);

      // 3. AND_EXPR where one operand is restrictive
      const andOneFalse = {
        BoolExpr: {
          boolop: 'AND_EXPR',
          args: [
            { A_Const: { boolval: { boolval: true } } },
            { ColumnRef: { fields: [{ String: { sval: 'user_id' } }] } },
          ],
        },
      };
      expect(isUnrestrictedPredicate(andOneFalse)).toBe(false);

      // 4. OR_EXPR where one operand is true (tautology)
      const orWithTrue = {
        BoolExpr: {
          boolop: 'OR_EXPR',
          args: [
            { ColumnRef: { fields: [{ String: { sval: 'user_id' } }] } },
            { A_Const: { boolval: { boolval: true } } },
          ],
        },
      };
      expect(isUnrestrictedPredicate(orWithTrue)).toBe(true);
    });

    describe('PostgreSQL Command-Specific Policy Defaulting Semantics (Omitted Clauses)', () => {
      it('correctly models omitted USING on SELECT as defaulting to true (unrestricted read)', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_select_omitted_using.sql',
            relativePath: 'supabase/migrations/01_select_omitted_using.sql',
            content: `
              CREATE TABLE "public"."posts" (id uuid, title text);
              ALTER TABLE "public"."posts" ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Read posts" ON "public"."posts" FOR SELECT TO anon;
            `,
            absolutePath: '/app/01.sql',
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);

        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('info');
        expect(findings[0].ruleTitle).toContain('Read Access Allowed');
        expect(findings[0].observedValue).toContain('omitted USING (defaults to true)');
      });

      it('correctly models omitted WITH CHECK on INSERT as defaulting to true (unrestricted write)', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_insert_omitted_with_check.sql',
            relativePath: 'supabase/migrations/01_insert_omitted_with_check.sql',
            content: `
              CREATE TABLE "public"."leads" (id uuid, email text);
              ALTER TABLE "public"."leads" ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Submit leads" ON "public"."leads" FOR INSERT TO anon;
            `,
            absolutePath: '/app/01.sql',
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);

        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('high');
        expect(findings[0].ruleTitle).toContain('Unrestricted Write Access');
        expect(findings[0].observedValue).toContain('omitted WITH CHECK (defaults to true)');
      });

      it('correctly models omitted USING on DELETE as defaulting to true (unrestricted delete)', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_delete_omitted_using.sql',
            relativePath: 'supabase/migrations/01_delete_omitted_using.sql',
            content: `
              CREATE TABLE "public"."temp_logs" (id uuid, log text);
              ALTER TABLE "public"."temp_logs" ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Purge logs" ON "public"."temp_logs" FOR DELETE TO authenticated;
            `,
            absolutePath: '/app/01.sql',
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);

        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('medium');
        expect(findings[0].ruleTitle).toContain('Unrestricted Mutation Across Rows');
        expect(findings[0].observedValue).toContain('omitted USING (defaults to true)');
      });

      it('correctly models omitted clauses on ALL as defaulting to true for both USING and WITH CHECK', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_all_omitted.sql',
            relativePath: 'supabase/migrations/01_all_omitted.sql',
            content: `
              CREATE TABLE "public"."notes" (id uuid, note text);
              ALTER TABLE "public"."notes" ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "All notes" ON "public"."notes" FOR ALL TO anon;
            `,
            absolutePath: '/app/01.sql',
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);

        expect(findings.length).toBeGreaterThanOrEqual(1);
        const highWriteFinding = findings.find((f) => f.severity === 'high');
        expect(highWriteFinding).toBeDefined();
        expect(highWriteFinding?.observedValue).toContain('omitted USING and WITH CHECK (defaults to true)');
      });

      it('correctly models ALTER POLICY when only USING is modified and WITH CHECK was omitted in CREATE POLICY', async () => {
        // Migration 1:
        // CREATE POLICY user_update ON public.documents FOR UPDATE TO authenticated USING (auth.uid() = user_id);
        // Migration 2:
        // ALTER POLICY user_update ON public.documents USING (true);
        const migrations: MigrationFile[] = [
          {
            filename: '01_create_pol.sql',
            relativePath: 'supabase/migrations/01_create_pol.sql',
            content: `
              CREATE TABLE "public"."documents" (id uuid, user_id uuid);
              ALTER TABLE "public"."documents" ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "user_update" ON "public"."documents" FOR UPDATE TO authenticated USING (auth.uid() = user_id);
            `,
            absolutePath: '/app/01.sql',
          },
          {
            filename: '02_alter_pol.sql',
            relativePath: 'supabase/migrations/02_alter_pol.sql',
            content: `
              ALTER POLICY "user_update" ON "public"."documents" USING (true);
            `,
            absolutePath: '/app/02.sql',
          },
        ];

        // 1. Verify state after Migration 1 alone
        const stateAfterM1 = await buildMigrationDatabaseState([migrations[0]]);
        const policyM1 = stateAfterM1.tables.get('public.documents')?.policies.get('user_update');
        expect(policyM1).toBeDefined();
        // In PostgreSQL CREATE POLICY: omitted WITH CHECK defaults to USING expression
        expect(policyM1?.isUnrestrictedUsing).toBe(false);
        expect(policyM1?.isUnrestrictedWithCheck).toBe(false);
        expect(policyM1?.hasExplicitWithCheck).toBe(false);

        // 2. Verify state after Migration 2
        const stateAfterM2 = await buildMigrationDatabaseState(migrations);
        const policyM2 = stateAfterM2.tables.get('public.documents')?.policies.get('user_update');
        expect(policyM2).toBeDefined();
        // In PostgreSQL ALTER POLICY: specified clause (USING) replaces existing expression;
        // omitted clause (WITH CHECK) retains its existing expression (auth.uid() = user_id).
        expect(policyM2?.isUnrestrictedUsing).toBe(true);
        expect(policyM2?.isUnrestrictedWithCheck).toBe(false);

        // 3. Security Findings: Permissive USING on UPDATE with Restrictive WITH CHECK (low severity)
        const findings = checkSuspiciousPolicies(stateAfterM2);
        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('low');
        expect(findings[0].ruleTitle).toBe('Permissive USING on UPDATE Policy with Restrictive WITH CHECK');
        expect(findings[0].rationale).toContain('cross-row');
      });

      it('correctly models ALTER POLICY when only WITH CHECK is modified', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_create.sql',
            relativePath: 'supabase/migrations/01_create.sql',
            content: `
              CREATE TABLE "public"."documents" (id uuid, user_id uuid);
              ALTER TABLE "public"."documents" ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "user_update" ON "public"."documents" FOR UPDATE TO authenticated USING (auth.uid() = user_id);
            `,
            absolutePath: '/app/01.sql',
          },
          {
            filename: '02_alter_check.sql',
            relativePath: 'supabase/migrations/02_alter_check.sql',
            content: `
              ALTER POLICY "user_update" ON "public"."documents" WITH CHECK (true);
            `,
            absolutePath: '/app/02.sql',
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const policy = state.tables.get('public.documents')?.policies.get('user_update');
        expect(policy?.isUnrestrictedUsing).toBe(false); // Retained from Migration 1
        expect(policy?.isUnrestrictedWithCheck).toBe(true); // Replaced by Migration 2

        // Since USING is restrictive, users cannot target other rows for update
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('correctly models ALTER POLICY when both USING and WITH CHECK are modified', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_create.sql',
            relativePath: 'supabase/migrations/01_create.sql',
            content: `
              CREATE TABLE "public"."documents" (id uuid, user_id uuid);
              ALTER TABLE "public"."documents" ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "user_update" ON "public"."documents" FOR UPDATE TO authenticated USING (auth.uid() = user_id);
            `,
            absolutePath: '/app/01.sql',
          },
          {
            filename: '02_alter_both.sql',
            relativePath: 'supabase/migrations/02_alter_both.sql',
            content: `
              ALTER POLICY "user_update" ON "public"."documents" USING (true) WITH CHECK (true);
            `,
            absolutePath: '/app/02.sql',
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const policy = state.tables.get('public.documents')?.policies.get('user_update');
        expect(policy?.isUnrestrictedUsing).toBe(true);
        expect(policy?.isUnrestrictedWithCheck).toBe(true);

        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('medium');
        expect(findings[0].ruleTitle).toContain('Unrestricted Mutation Across Rows');
      });

      it('correctly models ALTER POLICY when neither expression is modified (e.g. changing roles only)', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_create.sql',
            relativePath: 'supabase/migrations/01_create.sql',
            content: `
              CREATE TABLE "public"."documents" (id uuid, user_id uuid);
              ALTER TABLE "public"."documents" ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "user_update" ON "public"."documents" FOR UPDATE TO authenticated USING (auth.uid() = user_id);
            `,
            absolutePath: '/app/01.sql',
          },
          {
            filename: '02_alter_roles.sql',
            relativePath: 'supabase/migrations/02_alter_roles.sql',
            content: `
              ALTER POLICY "user_update" ON "public"."documents" TO authenticated;
            `,
            absolutePath: '/app/02.sql',
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const policy = state.tables.get('public.documents')?.policies.get('user_update');
        // Both expressions are retained
        expect(policy?.isUnrestrictedUsing).toBe(false);
        expect(policy?.isUnrestrictedWithCheck).toBe(false);

        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('correctly models ALTER POLICY when policy was created with explicit USING and WITH CHECK', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_create_explicit.sql',
            relativePath: 'supabase/migrations/01_create_explicit.sql',
            content: `
              CREATE TABLE "public"."documents" (id uuid, user_id uuid);
              ALTER TABLE "public"."documents" ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "user_update" ON "public"."documents" FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
            `,
            absolutePath: '/app/01.sql',
          },
          {
            filename: '02_alter_using.sql',
            relativePath: 'supabase/migrations/02_alter_using.sql',
            content: `
              ALTER POLICY "user_update" ON "public"."documents" USING (true);
            `,
            absolutePath: '/app/02.sql',
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const policy = state.tables.get('public.documents')?.policies.get('user_update');
        expect(policy?.isUnrestrictedUsing).toBe(true);
        expect(policy?.isUnrestrictedWithCheck).toBe(false); // Retained explicit WITH CHECK

        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('low');
        expect(findings[0].ruleTitle).toBe('Permissive USING on UPDATE Policy with Restrictive WITH CHECK');
      });
    });

    describe('PostgreSQL CREATE TABLE AS SELECT (CreateTableAsStmt) Tracking', () => {
      it('tracks tables created with CREATE TABLE ... AS SELECT and flags missing RLS in exposed schema', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_ctas.sql',
            relativePath: 'supabase/migrations/01_ctas.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE "public"."orders" (id int, amount numeric);
              ALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;
              CREATE TABLE "public"."order_summaries" AS SELECT id, count(*) as count FROM "public"."orders" GROUP BY id;
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        expect(state.tables.has('public.order_summaries')).toBe(true);
        expect(state.tables.get('public.order_summaries')?.rowLevelSecurityEnabled).toBe(false);

        const findings = checkMissingRls(state, { exposedSchemas: ['public'] });
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleId).toBe('SEC-MIG-RLS-001');
        expect(findings[0].schema).toBe('public');
        expect(findings[0].table).toBe('order_summaries');
      });

      it('passes when table created with CREATE TABLE ... AS SELECT has RLS enabled', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_ctas_rls.sql',
            relativePath: 'supabase/migrations/01_ctas_rls.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE "public"."order_summaries" AS SELECT 1 AS id;
              ALTER TABLE "public"."order_summaries" ENABLE ROW LEVEL SECURITY;
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        expect(state.tables.get('public.order_summaries')?.rowLevelSecurityEnabled).toBe(true);

        const findings = checkMissingRls(state, { exposedSchemas: ['public'] });
        expect(findings).toHaveLength(0);
      });

      it('tracks table created with CREATE TABLE ... AS SELECT in one migration and enabled in subsequent migration', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_create.sql',
            relativePath: 'supabase/migrations/01_create.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE "public"."order_summaries" AS SELECT 1 AS id;
            `,
          },
          {
            filename: '02_enable_rls.sql',
            relativePath: 'supabase/migrations/02_enable_rls.sql',
            absolutePath: '/app/02.sql',
            content: `
              ALTER TABLE "public"."order_summaries" ENABLE ROW LEVEL SECURITY;
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        expect(state.tables.get('public.order_summaries')?.rowLevelSecurityEnabled).toBe(true);

        const findings = checkMissingRls(state, { exposedSchemas: ['public'] });
        expect(findings).toHaveLength(0);
      });

      it('passes when table created with CREATE TABLE ... AS SELECT is subsequently dropped', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_ctas_drop.sql',
            relativePath: 'supabase/migrations/01_ctas_drop.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE "public"."temp_export" AS SELECT 1 AS id;
              DROP TABLE "public"."temp_export";
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        expect(state.tables.get('public.temp_export')?.dropped).toBe(true);

        const findings = checkMissingRls(state, { exposedSchemas: ['public'] });
        expect(findings).toHaveLength(0);
      });

      it('ignores tables created with CREATE TABLE ... AS SELECT in non-exposed schema', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_ctas_internal.sql',
            relativePath: 'supabase/migrations/01_ctas_internal.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE SCHEMA IF NOT EXISTS "internal";
              CREATE TABLE "internal"."cached_stats" AS SELECT 1 AS count;
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        expect(state.tables.has('internal.cached_stats')).toBe(true);

        const findings = checkMissingRls(state, { exposedSchemas: ['public'] });
        expect(findings).toHaveLength(0);
      });
    });

    describe('Aggregate RLS Policy Interaction & Combination Analysis', () => {
      it('detects when two permissive SELECT policies combine by OR and broaden access beyond ownership', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_doc.sql',
            relativePath: 'supabase/migrations/01_doc.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Users see own documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Users see active documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);

        expect(findings).toHaveLength(1);
        expect(findings[0].ruleId).toBe('SEC-MIG-RLS-002');
        expect(findings[0].ruleTitle).toBe(
          'Permissive Policy Disjunction Broadens Access Beyond Ownership Boundary'
        );
        expect(findings[0].severity).toBe('low');
        expect(findings[0].table).toBe('documents');
        expect(findings[0].policyName).toBe('Users see active documents');
        expect(findings[0].observedValue).toContain(
          'combines via OR with ownership policy "Users see own documents"'
        );
      });

      it('passes cleanly when two restrictive policies combine by AND without permissive disjunction', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_restrictive_and.sql',
            relativePath: 'supabase/migrations/01_restrictive_and.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                tenant_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Tenant restriction"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING ((auth.jwt()->>'tenant_id')::uuid = tenant_id);
              CREATE POLICY "Status restriction"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING (status = 'active');
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('suppresses false positive world-readable findings when a permissive broad policy is narrowed by an applicable restrictive policy', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_narrowed_permissive.sql',
            relativePath: 'supabase/migrations/01_narrowed_permissive.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                tenant_id uuid
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Open permissive"
                ON public.documents
                FOR SELECT TO authenticated
                USING (true);
              CREATE POLICY "Tenant boundary"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING ((auth.jwt()->>'tenant_id')::uuid = tenant_id);
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('does not combine policies targeted to different roles (anon vs authenticated)', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_roles.sql',
            relativePath: 'supabase/migrations/01_roles.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                is_public boolean
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Public read"
                ON public.documents
                FOR SELECT TO anon
                USING (is_public = true);
              CREATE POLICY "Owner read"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('does not combine policies targeted to different commands (SELECT vs UPDATE)', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_commands.sql',
            relativePath: 'supabase/migrations/01_commands.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Owner read"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Owner update"
                ON public.documents
                FOR UPDATE TO authenticated
                USING (auth.uid() = user_id)
                WITH CHECK (auth.uid() = user_id);
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('detects disjunction widening when an ALL ownership policy interacts with a command-specific broad policy', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_all_interaction.sql',
            relativePath: 'supabase/migrations/01_all_interaction.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Owner all"
                ON public.documents
                FOR ALL TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Active read"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);

        expect(findings).toHaveLength(1);
        expect(findings[0].ruleTitle).toBe(
          'Permissive Policy Disjunction Broadens Access Beyond Ownership Boundary'
        );
        expect(findings[0].policyName).toBe('Active read');
      });

      it('evaluates cumulative state correctly when a broad policy is subsequently dropped in a later migration', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_create_both.sql',
            relativePath: 'supabase/migrations/01_create_both.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Owner read"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Active read"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
            `,
          },
          {
            filename: '02_drop_broad.sql',
            relativePath: 'supabase/migrations/02_drop_broad.sql',
            absolutePath: '/app/02.sql',
            content: `
              DROP POLICY "Active read" ON public.documents;
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('preserves info-severity advisory for legitimate standalone public-read access', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_public_blog.sql',
            relativePath: 'supabase/migrations/01_public_blog.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.blog_posts (
                id uuid,
                title text
              );
              ALTER TABLE public.blog_posts ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Public read"
                ON public.blog_posts
                FOR SELECT TO anon
                USING (true);
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('info');
        expect(findings[0].ruleTitle).toBe('Public Read Access Allowed by RLS Policy');
      });

      it('ignores policies targeted strictly to service_role', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_sr_admin.sql',
            relativePath: 'supabase/migrations/01_sr_admin.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.admin_logs (
                id uuid,
                log text
              );
              ALTER TABLE public.admin_logs ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Admin full"
                ON public.admin_logs
                FOR ALL TO service_role
                USING (true)
                WITH CHECK (true);
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('handles unknown or complex subquery expressions safely without false findings or crashes', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_subquery.sql',
            relativePath: 'supabase/migrations/01_subquery.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.teams (
                id uuid,
                name text
              );
              ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Member read"
                ON public.teams
                FOR SELECT TO authenticated
                USING (
                  EXISTS (
                    SELECT 1 FROM team_members
                    WHERE team_members.team_id = teams.id
                      AND team_members.user_id = auth.uid()
                  )
                );
            `,
          },
        ];

        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });
    });

    describe('Aggregate RLS Policy Analysis and Restrictive Suppression Hardening', () => {
      it('1. classifies auth.uid() = user_id as a row-ownership predicate', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_ownership.sql',
            relativePath: 'supabase/migrations/01_ownership.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (id uuid, user_id uuid);
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Owner select" ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const pol = state.tables.get('public.documents')?.policies.get('Owner select');
        expect(pol?.hasOwnershipCheckUsing).toBe(true);
        expect(pol?.hasTenantCheckUsing).toBe(false);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('2. classifies auth.uid() IS NOT NULL as a non-ownership predicate and detects disjunction widening', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_not_null.sql',
            relativePath: 'supabase/migrations/01_not_null.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (id uuid, user_id uuid);
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Owner read" ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id);
              CREATE POLICY "Any auth read" ON public.documents FOR SELECT TO authenticated USING (auth.uid() IS NOT NULL);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const pol = state.tables.get('public.documents')?.policies.get('Any auth read');
        expect(pol?.hasOwnershipCheckUsing).toBe(false);
        expect(pol?.hasAuthCheckUsing).toBe(true);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleTitle).toBe(
          'Permissive Policy Disjunction Broadens Access Beyond Ownership Boundary'
        );
        expect(findings[0].policyName).toBe('Any auth read');
      });

      it('3. classifies auth.uid() = auth.uid() as a tautology rather than row ownership', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_self_compare.sql',
            relativePath: 'supabase/migrations/01_self_compare.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (id uuid, user_id uuid);
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Owner read" ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id);
              CREATE POLICY "Tautology read" ON public.documents FOR SELECT TO authenticated USING (auth.uid() = auth.uid());
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const pol = state.tables.get('public.documents')?.policies.get('Tautology read');
        expect(pol?.hasOwnershipCheckUsing).toBe(false);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].policyName).toBe('Tautology read');
      });

      it('4. classifies ownership OR broad condition as broad, detecting disjunction', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_or_broad.sql',
            relativePath: 'supabase/migrations/01_or_broad.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (id uuid, user_id uuid, status text);
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Owner read" ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id);
              CREATE POLICY "Owner or active" ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id OR status = 'active');
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const pol = state.tables.get('public.documents')?.policies.get('Owner or active');
        expect(pol?.hasOwnershipCheckUsing).toBe(false);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].policyName).toBe('Owner or active');
      });

      it('5. preserves row-ownership classification when combined via Boolean AND with an additional filter', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_and_filter.sql',
            relativePath: 'supabase/migrations/01_and_filter.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (id uuid, user_id uuid, status text);
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Owner active read" ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id AND status = 'active');
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const pol = state.tables.get('public.documents')?.policies.get('Owner active read');
        expect(pol?.hasOwnershipCheckUsing).toBe(true);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('6. does not suppress disjunction findings when a restrictive policy uses auth.uid() IS NOT NULL', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_reproduce_scenario_3.sql',
            relativePath: 'supabase/migrations/01_reproduce_scenario_3.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Users see own documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Users see active documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
              CREATE POLICY "Require authenticated identity"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING (auth.uid() IS NOT NULL);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleTitle).toBe(
          'Permissive Policy Disjunction Broadens Access Beyond Ownership Boundary'
        );
        expect(findings[0].policyName).toBe('Users see active documents');
        expect(findings[0].severity).toBe('low');
      });

      it('7. does not suppress disjunction findings when a restrictive policy contains OR true and does not flag restrictive policy as granting access', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_restrictive_or_true.sql',
            relativePath: 'supabase/migrations/01_restrictive_or_true.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Users see own documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Users see active documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
              CREATE POLICY "Tautological auth restrictive"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id OR true);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleTitle).toBe(
          'Permissive Policy Disjunction Broadens Access Beyond Ownership Boundary'
        );
        expect(findings[0].policyName).toBe('Users see active documents');
        expect(findings.some((f) => f.policyName === 'Tautological auth restrictive')).toBe(false);
      });

      it('8. reports disjunction widening with calibrated explanation when a tenant boundary is present', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_tenant_disjunction.sql',
            relativePath: 'supabase/migrations/01_tenant_disjunction.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                tenant_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Users see own documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Users see active documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
              CREATE POLICY "Tenant boundary"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING (tenant_id = (auth.jwt()->>'tenant_id')::uuid);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].policyName).toBe('Users see active documents');
        expect(findings[0].observedValue).toContain('(within tenant boundary enforced by "Tenant boundary")');
        expect(findings[0].rationale).toContain('isolates records by tenant');
      });

      it('9. suppresses disjunction finding when an applicable restrictive policy genuinely enforces row ownership', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_restrictive_ownership.sql',
            relativePath: 'supabase/migrations/01_restrictive_ownership.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Users see own documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Users see active documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
              CREATE POLICY "Enforce ownership strictly"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('10. guarantees that a restrictive USING (true) policy cannot independently generate an access-granting finding', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_restrictive_true.sql',
            relativePath: 'supabase/migrations/01_restrictive_true.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (id uuid);
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Restrictive true"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING (true);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('11. handles legitimate public-read and service_role scenarios cleanly without false positives', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_legit.sql',
            relativePath: 'supabase/migrations/01_legit.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.catalog (id uuid, is_public boolean);
              ALTER TABLE public.catalog ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Public items"
                ON public.catalog
                FOR SELECT TO anon
                USING (is_public = true);
              CREATE POLICY "Service full"
                ON public.catalog
                FOR ALL TO service_role
                USING (true)
                WITH CHECK (true);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      it('12. respects role and command scoping so mismatching restrictive policies do not suppress disjunctions', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_mismatch.sql',
            relativePath: 'supabase/migrations/01_mismatch.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Owner read"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Active read"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
              CREATE POLICY "Restrictive update"
                ON public.documents
                AS RESTRICTIVE
                FOR UPDATE TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Restrictive anon"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO anon
                USING (auth.uid() = user_id);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].policyName).toBe('Active read');
      });

      it('13. distinguishes tenant column auth.uid() = tenant_id from individual row ownership and preserves disjunction warning', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_tenant_column.sql',
            relativePath: 'supabase/migrations/01_tenant_column.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                tenant_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Users see own documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Users see active documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
              CREATE POLICY "Restrictive tenant match"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING (auth.uid() = tenant_id);
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const pol = state.tables.get('public.documents')?.policies.get('Restrictive tenant match');
        expect(pol?.hasOwnershipCheckUsing).toBe(false);
        expect(pol?.hasTenantCheckUsing).toBe(false);

        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleTitle).toBe(
          'Permissive Policy Disjunction Broadens Access Beyond Ownership Boundary'
        );
        expect(findings[0].policyName).toBe('Users see active documents');
        expect(findings[0].observedValue).not.toContain('(within tenant boundary');
      });

      it('14. recognizes uncorrelated subqueries as non-ownership and does not suppress disjunction warnings', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_uncorrelated.sql',
            relativePath: 'supabase/migrations/01_uncorrelated.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.documents (
                id uuid,
                user_id uuid,
                status text
              );
              ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Users see own documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (auth.uid() = user_id);
              CREATE POLICY "Users see active documents"
                ON public.documents
                FOR SELECT TO authenticated
                USING (status <> 'archived');
              CREATE POLICY "Restrictive membership check"
                ON public.documents
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING (
                  EXISTS (
                    SELECT 1
                    FROM public.memberships
                    WHERE memberships.user_id = auth.uid()
                  )
                );
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const pol = state.tables.get('public.documents')?.policies.get('Restrictive membership check');
        expect(pol?.hasOwnershipCheckUsing).toBe(false);

        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleTitle).toBe(
          'Permissive Policy Disjunction Broadens Access Beyond Ownership Boundary'
        );
        expect(findings[0].policyName).toBe('Users see active documents');
      });

      it('15. recognizes correlated subqueries that explicitly connect to the protected row and suppresses disjunction safely', async () => {
        const migrations: MigrationFile[] = [
          {
            filename: '01_correlated_suppress.sql',
            relativePath: 'supabase/migrations/01_correlated_suppress.sql',
            absolutePath: '/app/01.sql',
            content: `
              CREATE TABLE public.teams (
                id uuid,
                name text,
                status text
              );
              ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
              CREATE POLICY "Member read"
                ON public.teams
                FOR SELECT TO authenticated
                USING (
                  EXISTS (
                    SELECT 1 FROM team_members
                    WHERE team_members.team_id = teams.id
                      AND team_members.user_id = auth.uid()
                  )
                );
              CREATE POLICY "Active teams"
                ON public.teams
                FOR SELECT TO authenticated
                USING (status <> 'archived');
              CREATE POLICY "Enforce team membership"
                ON public.teams
                AS RESTRICTIVE
                FOR SELECT TO authenticated
                USING (
                  EXISTS (
                    SELECT 1 FROM team_members
                    WHERE team_members.team_id = teams.id
                      AND team_members.user_id = auth.uid()
                  )
                );
            `,
          },
        ];
        const state = await buildMigrationDatabaseState(migrations);
        const pol = state.tables.get('public.teams')?.policies.get('Enforce team membership');
        expect(pol?.hasOwnershipCheckUsing).toBe(true);

        const findings = checkSuspiciousPolicies(state);
        expect(findings).toHaveLength(0);
      });

      describe('Column classification and subquery correlation semantics', () => {
        it('does not treat outer attribute filter (documents.status = active) in subquery as row ownership', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_status_subquery.sql',
              relativePath: 'supabase/migrations/01_status_subquery.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Owner read"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active docs"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Status correlated subquery"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1
                      FROM public.memberships
                      WHERE memberships.user_id = auth.uid()
                        AND documents.status = 'active'
                    )
                  );
              `,
            },
          ];
          const state = await buildMigrationDatabaseState(migrations);
          const pol = state.tables.get('public.documents')?.policies.get('Status correlated subquery');
          expect(pol?.hasOwnershipCheckUsing).toBe(false);
          expect(pol?.hasTenantCheckUsing).toBe(false);

          const findings = checkSuspiciousPolicies(state);
          const disjunctionFindings = findings.filter((f) =>
            f.ruleTitle.includes('Permissive Policy Disjunction')
          );
          expect(disjunctionFindings).toHaveLength(1);
          expect(disjunctionFindings[0].policyName).toBe('Active docs');
        });

        it('treats correctly correlated membership check (memberships.document_id = documents.id) as row ownership', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_entity_correlated.sql',
              relativePath: 'supabase/migrations/01_entity_correlated.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Owner read"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active docs"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Entity membership check"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1
                      FROM public.memberships
                      WHERE memberships.user_id = auth.uid()
                        AND memberships.document_id = documents.id
                    )
                  );
              `,
            },
          ];
          const state = await buildMigrationDatabaseState(migrations);
          const pol = state.tables.get('public.documents')?.policies.get('Entity membership check');
          expect(pol?.hasOwnershipCheckUsing).toBe(true);
          expect(pol?.hasTenantCheckUsing).toBe(false);

          const findings = checkSuspiciousPolicies(state);
          const disjunctionFindings = findings.filter((f) =>
            f.ruleTitle.includes('Permissive Policy Disjunction')
          );
          expect(disjunctionFindings).toHaveLength(0);
        });

        it('treats team-correlated membership check as team/tenant boundary rather than individual row ownership', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_team_correlated.sql',
              relativePath: 'supabase/migrations/01_team_correlated.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  team_id uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Owner read"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active docs"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Team membership check"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1
                      FROM public.team_members
                      WHERE team_members.user_id = auth.uid()
                        AND team_members.team_id = documents.team_id
                    )
                  );
              `,
            },
          ];
          const state = await buildMigrationDatabaseState(migrations);
          const pol = state.tables.get('public.documents')?.policies.get('Team membership check');
          expect(pol?.hasOwnershipCheckUsing).toBe(false);
          expect(pol?.hasTenantCheckUsing).toBe(true);

          const findings = checkSuspiciousPolicies(state);
          const disjunctionFindings = findings.filter((f) =>
            f.ruleTitle.includes('Permissive Policy Disjunction')
          );
          expect(disjunctionFindings).toHaveLength(1);
          expect(disjunctionFindings[0].observedValue).toContain('(within tenant boundary enforced by "Team membership check")');
        });

        it('does not treat uncorrelated membership subquery as row ownership or tenant boundary', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_uncorrelated.sql',
              relativePath: 'supabase/migrations/01_uncorrelated.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Owner read"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active docs"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Uncorrelated check"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1
                      FROM public.memberships
                      WHERE memberships.user_id = auth.uid()
                    )
                  );
              `,
            },
          ];
          const state = await buildMigrationDatabaseState(migrations);
          const pol = state.tables.get('public.documents')?.policies.get('Uncorrelated check');
          expect(pol?.hasOwnershipCheckUsing).toBe(false);
          expect(pol?.hasTenantCheckUsing).toBe(false);

          const findings = checkSuspiciousPolicies(state);
          const disjunctionFindings = findings.filter((f) =>
            f.ruleTitle.includes('Permissive Policy Disjunction')
          );
          expect(disjunctionFindings).toHaveLength(1);
        });

        it('does not treat audit column updated_by as row ownership and preserves disjunction warning', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_updated_by.sql',
              relativePath: 'supabase/migrations/01_updated_by.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  updated_by uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Owner read"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active docs"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Updated by restriction"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = updated_by);
              `,
            },
          ];
          const state = await buildMigrationDatabaseState(migrations);
          const pol = state.tables.get('public.documents')?.policies.get('Updated by restriction');
          expect(pol?.hasOwnershipCheckUsing).toBe(false);

          const findings = checkSuspiciousPolicies(state);
          const disjunctionFindings = findings.filter((f) =>
            f.ruleTitle.includes('Permissive Policy Disjunction')
          );
          expect(disjunctionFindings).toHaveLength(1);
        });

        it('classifies tenant columns (tenant_id, org_id, workspace_id, team_id) as tenant boundaries and not user ownership', () => {
          expect(isTenantColumnName('tenant_id')).toBe(true);
          expect(isTenantColumnName('org_id')).toBe(true);
          expect(isTenantColumnName('workspace_id')).toBe(true);
          expect(isTenantColumnName('team_id')).toBe(true);
          expect(isTenantColumnName('user_id')).toBe(false);
          expect(isTenantColumnName('created_by')).toBe(false);

          expect(isUserColumnName('user_id')).toBe(true);
          expect(isUserColumnName('created_by')).toBe(true);
          expect(isUserColumnName('owner_id')).toBe(true);
          expect(isUserColumnName('updated_by')).toBe(false);
          expect(isUserColumnName('tenant_id')).toBe(false);
          expect(isUserColumnName('org_id')).toBe(false);
          expect(isUserColumnName('workspace_id')).toBe(false);
          expect(isUserColumnName('sub')).toBe(false);
          expect(isUserColumnName('member_id')).toBe(false);
        });

        it('CASE 1: treats auth.uid() = tenant_id as uncertain identity comparison and does not describe as validated tenant isolation', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_case1.sql',
              relativePath: 'supabase/migrations/01_case1.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, user_id uuid, tenant_id uuid, status text);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY p_own ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id);
                CREATE POLICY p_broad ON public.documents FOR SELECT TO authenticated USING (status = 'active');
                CREATE POLICY r ON public.documents AS RESTRICTIVE FOR SELECT TO authenticated USING (auth.uid() = tenant_id);
              `,
            },
          ];
          const state = await buildMigrationDatabaseState(migrations);
          const pol = state.tables.get('public.documents')?.policies.get('r');
          expect(pol?.hasOwnershipCheckUsing).toBe(false);
          expect(pol?.hasTenantCheckUsing).toBe(false);

          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].observedValue).not.toContain('(within tenant boundary');
          expect(disj[0].rationale).not.toContain('isolates records by tenant');
        });

        it('CASE 2: recognizes (auth.jwt()->>\'tenant_id\')::uuid = tenant_id as a validated tenant-claim boundary', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_case2.sql',
              relativePath: 'supabase/migrations/01_case2.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, user_id uuid, tenant_id uuid, status text);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY p_own ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id);
                CREATE POLICY p_broad ON public.documents FOR SELECT TO authenticated USING (status = 'active');
                CREATE POLICY r ON public.documents AS RESTRICTIVE FOR SELECT TO authenticated USING ((auth.jwt()->>'tenant_id')::uuid = tenant_id);
              `,
            },
          ];
          const state = await buildMigrationDatabaseState(migrations);
          const pol = state.tables.get('public.documents')?.policies.get('r');
          expect(pol?.hasOwnershipCheckUsing).toBe(false);
          expect(pol?.hasTenantCheckUsing).toBe(true);

          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].observedValue).toContain('(within tenant boundary enforced by "r")');
          expect(disj[0].rationale).toContain('isolates records by tenant');
        });

        it('CASE 3: does not classify auth.uid() = team_id as a validated team boundary solely because of column name', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_case3.sql',
              relativePath: 'supabase/migrations/01_case3.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, user_id uuid, team_id uuid, status text);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY p_own ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id);
                CREATE POLICY p_broad ON public.documents FOR SELECT TO authenticated USING (status = 'active');
                CREATE POLICY r ON public.documents AS RESTRICTIVE FOR SELECT TO authenticated USING (auth.uid() = team_id);
              `,
            },
          ];
          const state = await buildMigrationDatabaseState(migrations);
          const pol = state.tables.get('public.documents')?.policies.get('r');
          expect(pol?.hasOwnershipCheckUsing).toBe(false);
          expect(pol?.hasTenantCheckUsing).toBe(false);

          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].observedValue).not.toContain('(within tenant boundary');
          expect(disj[0].rationale).not.toContain('isolates records by tenant');
        });

        it('CASE 4: distinguishes (auth.jwt()->>\'team_id\')::uuid = team_id from CASE 3 by recognizing team claim', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_case4.sql',
              relativePath: 'supabase/migrations/01_case4.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, user_id uuid, team_id uuid, status text);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY p_own ON public.documents FOR SELECT TO authenticated USING (auth.uid() = user_id);
                CREATE POLICY p_broad ON public.documents FOR SELECT TO authenticated USING (status = 'active');
                CREATE POLICY r ON public.documents AS RESTRICTIVE FOR SELECT TO authenticated USING ((auth.jwt()->>'team_id')::uuid = team_id);
              `,
            },
          ];
          const state = await buildMigrationDatabaseState(migrations);
          const pol = state.tables.get('public.documents')?.policies.get('r');
          expect(pol?.hasOwnershipCheckUsing).toBe(false);
          expect(pol?.hasTenantCheckUsing).toBe(true);

          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].observedValue).toContain('(within tenant boundary enforced by "r")');
        });
      });

      describe('Ownership boundary precision and column distinction (Test A & Test B)', () => {
        it('TEST A: matching ownership boundary (auth.uid() = user_id) mitigates disjunction and does not cause false warning', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_test_a.sql',
              relativePath: 'supabase/migrations/01_test_a.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Users see own documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Users see active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Enforce ownership strictly"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pOwner = state.tables.get('public.documents')?.policies.get('Users see own documents');
          const pRestr = state.tables.get('public.documents')?.policies.get('Enforce ownership strictly');

          expect(pOwner?.hasOwnershipCheckUsing).toBe(true);
          expect(pOwner?.ownershipColumnsUsing).toEqual(['user_id']);
          expect(pRestr?.hasOwnershipCheckUsing).toBe(true);
          expect(pRestr?.ownershipColumnsUsing).toEqual(['user_id']);

          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('TEST B: mismatching ownership column (auth.uid() = created_by) does NOT suppress disjunction warning', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_test_b.sql',
              relativePath: 'supabase/migrations/01_test_b.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  created_by uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Users see own documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Users see active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Enforce created_by"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = created_by);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pOwner = state.tables.get('public.documents')?.policies.get('Users see own documents');
          const pRestr = state.tables.get('public.documents')?.policies.get('Enforce created_by');

          // Verify representation retains distinct identity-bound columns
          expect(pOwner?.ownershipColumnsUsing).toEqual(['user_id']);
          expect(pRestr?.ownershipColumnsUsing).toEqual(['created_by']);

          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].policyName).toBe('Users see active documents');
          expect(disj[0].observedValue).toContain('(unmitigated by restrictive policy "Enforce created_by" on column "created_by")');
          expect(disj[0].rationale).toContain('it does not verify "user_id" as enforced by policy "Users see own documents"');
        });

        it('does not assume owner_id and author_id establish the same boundary (owner_id permissive, author_id restrictive)', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_owner_author_mismatch.sql',
              relativePath: 'supabase/migrations/01_owner_author_mismatch.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.articles (
                  id uuid,
                  owner_id uuid,
                  author_id uuid,
                  status text
                );
                ALTER TABLE public.articles ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Owner read"
                  ON public.articles
                  FOR SELECT TO authenticated
                  USING (auth.uid() = owner_id);
                CREATE POLICY "Active articles"
                  ON public.articles
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Author restrictive"
                  ON public.articles
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = author_id);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].policyName).toBe('Active articles');
          expect(disj[0].observedValue).toContain('(unmitigated by restrictive policy "Author restrictive" on column "author_id")');
          expect(disj[0].rationale).toContain('it does not verify "owner_id" as enforced by policy "Owner read"');
        });

        it('does not assume user_id and owner_id establish the same boundary (user_id permissive, owner_id restrictive)', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_user_owner_mismatch.sql',
              relativePath: 'supabase/migrations/01_user_owner_mismatch.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.items (
                  id uuid,
                  user_id uuid,
                  owner_id uuid,
                  status text
                );
                ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "User read"
                  ON public.items
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active items"
                  ON public.items
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Owner restrictive"
                  ON public.items
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = owner_id);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].policyName).toBe('Active items');
          expect(disj[0].observedValue).toContain('(unmitigated by restrictive policy "Owner restrictive" on column "owner_id")');
        });

        it('suppresses disjunction warning when matching alternative ownership columns (created_by on both)', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_created_by_match.sql',
              relativePath: 'supabase/migrations/01_created_by_match.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.posts (
                  id uuid,
                  created_by uuid,
                  status text
                );
                ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Creator read"
                  ON public.posts
                  FOR SELECT TO authenticated
                  USING (auth.uid() = created_by);
                CREATE POLICY "Active posts"
                  ON public.posts
                  FOR SELECT TO authenticated
                  USING (status = 'published');
                CREATE POLICY "Creator restrictive"
                  ON public.posts
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = created_by);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('suppresses disjunction warning when matching alternative ownership columns (owner_id on both)', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_owner_id_match.sql',
              relativePath: 'supabase/migrations/01_owner_id_match.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.assets (
                  id uuid,
                  owner_id uuid,
                  status text
                );
                ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Owner read"
                  ON public.assets
                  FOR SELECT TO authenticated
                  USING (auth.uid() = owner_id);
                CREATE POLICY "Active assets"
                  ON public.assets
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Owner restrictive"
                  ON public.assets
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = owner_id);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('suppresses disjunction warning when matching alternative ownership columns (author_id on both)', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_author_id_match.sql',
              relativePath: 'supabase/migrations/01_author_id_match.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.notes (
                  id uuid,
                  author_id uuid,
                  status text
                );
                ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Author read"
                  ON public.notes
                  FOR SELECT TO authenticated
                  USING (auth.uid() = author_id);
                CREATE POLICY "Active notes"
                  ON public.notes
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Author restrictive"
                  ON public.notes
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = author_id);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('suppresses disjunction warning when restrictive policy compound condition includes the owner column', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_compound_restrictive.sql',
              relativePath: 'supabase/migrations/01_compound_restrictive.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  created_by uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Users see own documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Users see active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Compound restrictive"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id AND auth.uid() = created_by);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pRestr = state.tables.get('public.documents')?.policies.get('Compound restrictive');
          expect(pRestr?.ownershipColumnsUsing).toContain('user_id');
          expect(pRestr?.ownershipColumnsUsing).toContain('created_by');

          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('TASK 3: preserves column information across INSERT WITH CHECK and UPDATE policies', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_write_policies.sql',
              relativePath: 'supabase/migrations/01_write_policies.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.records (
                  id uuid,
                  user_id uuid,
                  owner_id uuid
                );
                ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Insert own record"
                  ON public.records
                  FOR INSERT TO authenticated
                  WITH CHECK (auth.uid() = user_id);
                CREATE POLICY "Update owner record"
                  ON public.records
                  FOR UPDATE TO authenticated
                  USING (auth.uid() = owner_id);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pInsert = state.tables.get('public.records')?.policies.get('Insert own record');
          const pUpdate = state.tables.get('public.records')?.policies.get('Update owner record');

          expect(pInsert?.hasOwnershipCheckWithCheck).toBe(true);
          expect(pInsert?.ownershipColumnsWithCheck).toEqual(['user_id']);
          expect(pUpdate?.hasOwnershipCheckUsing).toBe(true);
          expect(pUpdate?.ownershipColumnsUsing).toEqual(['owner_id']);
          // UPDATE omitted WITH CHECK inherits USING ownership columns
          expect(pUpdate?.hasOwnershipCheckWithCheck).toBe(true);
          expect(pUpdate?.ownershipColumnsWithCheck).toEqual(['owner_id']);
        });
      });

      describe('Disjunctive and Ambiguous Restrictive Predicate Analysis (Tasks 1 & 2)', () => {
        it('TASK 1 & TASK 2.4: disjunctive restrictive policy (auth.uid() = user_id OR auth.uid() = created_by) does NOT suppress disjunction finding', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_task1_reproduce.sql',
              relativePath: 'supabase/migrations/01_task1_reproduce.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  created_by uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Own documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Owner or creator"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    auth.uid() = user_id
                    OR auth.uid() = created_by
                  );
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pRestr = state.tables.get('public.documents')?.policies.get('Owner or creator');
          // An OR expression across distinct columns produces an empty common ownership columns list
          expect(pRestr?.hasOwnershipCheckUsing).toBe(true);
          expect(pRestr?.ownershipColumnsUsing).toEqual([]);

          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          // Must NOT suppress finding because the effective condition leaks active rows to non-owners
          expect(disj).toHaveLength(1);
          expect(disj[0].policyName).toBe('Active documents');
          expect(disj[0].observedValue).toContain('(unmitigated by restrictive policy "Owner or creator")');
          expect(disj[0].rationale).toContain('its disjunctive or unconfirmed condition does not guarantee "user_id" as enforced by policy "Own documents"');
        });

        it('TASK 2.1: restrictive auth.uid() = user_id suppresses disjunction finding', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_task2_1_matching.sql',
              relativePath: 'supabase/migrations/01_task2_1_matching.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Own documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Owner restrictive"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('TASK 2.2: restrictive auth.uid() = created_by does NOT suppress disjunction finding', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_task2_2_mismatch.sql',
              relativePath: 'supabase/migrations/01_task2_2_mismatch.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  created_by uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Own documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Creator restrictive"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (auth.uid() = created_by);
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].policyName).toBe('Active documents');
          expect(disj[0].observedValue).toContain('(unmitigated by restrictive policy "Creator restrictive" on column "created_by")');
        });

        it('TASK 2.3: restrictive auth.uid() = user_id AND auth.uid() = created_by suppresses disjunction finding', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_task2_3_conjunctive.sql',
              relativePath: 'supabase/migrations/01_task2_3_conjunctive.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  created_by uuid,
                  status text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Own documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Owner and creator"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    auth.uid() = user_id
                    AND auth.uid() = created_by
                  );
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pRestr = state.tables.get('public.documents')?.policies.get('Owner and creator');
          expect(pRestr?.ownershipColumnsUsing).toContain('user_id');
          expect(pRestr?.ownershipColumnsUsing).toContain('created_by');

          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('TASK 2.5: broad/unclassifiable restrictive predicate does NOT suppress disjunction finding', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_task2_5_broad.sql',
              relativePath: 'supabase/migrations/01_task2_5_broad.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  status text,
                  category text
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Own documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Category filter"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (category = 'internal');
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].policyName).toBe('Active documents');
        });

        it('TASK 2.6: legitimate correlated membership subquery suppresses disjunction finding', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_task2_6_membership.sql',
              relativePath: 'supabase/migrations/01_task2_6_membership.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  user_id uuid,
                  status text
                );
                CREATE TABLE public.memberships (
                  document_id uuid,
                  user_id uuid
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Own documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Member restrictive"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pRestr = state.tables.get('public.documents')?.policies.get('Member restrictive');
          expect(pRestr?.hasEntityMembershipUsing).toBe(true);

          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('TASK 2.6b: entity-correlated membership permissive policy mitigated by matching membership restrictive', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_task2_6b_membership_permissive.sql',
              relativePath: 'supabase/migrations/01_task2_6b_membership_permissive.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (
                  id uuid,
                  status text
                );
                CREATE TABLE public.memberships (
                  document_id uuid,
                  user_id uuid
                );
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Member access"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
                CREATE POLICY "Active documents"
                  ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Member restrictive"
                  ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pMember = state.tables.get('public.documents')?.policies.get('Member access');
          const pRestr = state.tables.get('public.documents')?.policies.get('Member restrictive');
          expect(pMember?.hasEntityMembershipUsing).toBe(true);
          expect(pRestr?.hasEntityMembershipUsing).toBe(true);

          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });
      });

      describe('Targeted Entity-Membership Suppression Verification (Tests A, B, C, D)', () => {
        it('TEST A: valid entity-membership restriction suppresses disjunction warning (SELECT)', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_test_a_select.sql',
              relativePath: 'supabase/migrations/01_test_a_select.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, status text);
                CREATE TABLE public.memberships (document_id uuid, user_id uuid);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Members see documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
                CREATE POLICY "Active documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Strict membership" ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('TEST B: tautological OR (EXISTS (...) OR true) does NOT suppress disjunction warning', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_test_b_tautology.sql',
              relativePath: 'supabase/migrations/01_test_b_tautology.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, status text);
                CREATE TABLE public.memberships (document_id uuid, user_id uuid);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Members see documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
                CREATE POLICY "Active documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Tautological membership" ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    OR true
                  );
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pRestr = state.tables.get('public.documents')?.policies.get('Tautological membership');
          expect(pRestr?.isUnrestrictedUsing).toBe(true);
          expect(pRestr?.hasEntityMembershipUsing).toBe(false);

          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].policyName).toBe('Active documents');
        });

        it('TEST C: broad OR branch (EXISTS (...) OR status = active) does NOT suppress disjunction warning', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_test_c_broad_or.sql',
              relativePath: 'supabase/migrations/01_test_c_broad_or.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, status text);
                CREATE TABLE public.memberships (document_id uuid, user_id uuid);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Members see documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
                CREATE POLICY "Active documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Broad membership or status" ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    OR status = 'active'
                  );
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pRestr = state.tables.get('public.documents')?.policies.get('Broad membership or status');
          // Disjunctive branch with status column must not be classified as strict entity membership
          expect(pRestr?.hasEntityMembershipUsing).toBe(false);
          expect(pRestr?.hasOwnershipCheckUsing).toBe(false);

          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].policyName).toBe('Active documents');
        });

        it('TEST C: broad OR branch alongside permissive user ownership does NOT suppress disjunction warning', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_test_c_ownership_broad_or.sql',
              relativePath: 'supabase/migrations/01_test_c_ownership_broad_or.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, user_id uuid, status text);
                CREATE TABLE public.memberships (document_id uuid, user_id uuid);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Own documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (auth.uid() = user_id);
                CREATE POLICY "Active documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Broad membership or status" ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    OR status = 'active'
                  );
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const findings = checkSuspiciousPolicies(state);
          const disj = findings.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disj).toHaveLength(1);
          expect(disj[0].policyName).toBe('Active documents');
        });

        it('TEST D: required membership with additional filtering (EXISTS (...) AND status = active) preserves restriction', async () => {
          const migrations: MigrationFile[] = [
            {
              filename: '01_test_d_conjunctive.sql',
              relativePath: 'supabase/migrations/01_test_d_conjunctive.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, status text);
                CREATE TABLE public.memberships (document_id uuid, user_id uuid);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Members see documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
                CREATE POLICY "Active documents" ON public.documents
                  FOR SELECT TO authenticated
                  USING (status = 'active');
                CREATE POLICY "Active member documents" ON public.documents
                  AS RESTRICTIVE
                  FOR SELECT TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    AND status = 'active'
                  );
              `,
            },
          ];

          const state = await buildMigrationDatabaseState(migrations);
          const pRestr = state.tables.get('public.documents')?.policies.get('Active member documents');
          expect(pRestr?.hasEntityMembershipUsing).toBe(true);

          const findings = checkSuspiciousPolicies(state);
          expect(findings).toHaveLength(0);
        });

        it('WITH CHECK: Test B and Test C do not suppress INSERT disjunction, while Test A and Test D suppress it', async () => {
          // Verify Test C with INSERT WITH CHECK
          const migrationsBroad: MigrationFile[] = [
            {
              filename: '01_insert_test_c.sql',
              relativePath: 'supabase/migrations/01_insert_test_c.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, status text);
                CREATE TABLE public.memberships (document_id uuid, user_id uuid);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Member insert" ON public.documents
                  FOR INSERT TO authenticated
                  WITH CHECK (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
                CREATE POLICY "Active insert" ON public.documents
                  FOR INSERT TO authenticated
                  WITH CHECK (status = 'active');
                CREATE POLICY "Broad insert restrictive" ON public.documents
                  AS RESTRICTIVE
                  FOR INSERT TO authenticated
                  WITH CHECK (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    OR status = 'active'
                  );
              `,
            },
          ];

          const stateBroad = await buildMigrationDatabaseState(migrationsBroad);
          const findingsBroad = checkSuspiciousPolicies(stateBroad);
          const disjBroad = findingsBroad.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disjBroad).toHaveLength(1);
          expect(disjBroad[0].policyName).toBe('Active insert');

          // Verify Test D with INSERT WITH CHECK
          const migrationsConjunctive: MigrationFile[] = [
            {
              filename: '01_insert_test_d.sql',
              relativePath: 'supabase/migrations/01_insert_test_d.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, status text);
                CREATE TABLE public.memberships (document_id uuid, user_id uuid);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Member insert" ON public.documents
                  FOR INSERT TO authenticated
                  WITH CHECK (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
                CREATE POLICY "Active insert" ON public.documents
                  FOR INSERT TO authenticated
                  WITH CHECK (status = 'active');
                CREATE POLICY "Filtered member insert restrictive" ON public.documents
                  AS RESTRICTIVE
                  FOR INSERT TO authenticated
                  WITH CHECK (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    AND status = 'active'
                  );
              `,
            },
          ];

          const stateConjunctive = await buildMigrationDatabaseState(migrationsConjunctive);
          const findingsConjunctive = checkSuspiciousPolicies(stateConjunctive);
          expect(findingsConjunctive).toHaveLength(0);
        });

        it('UPDATE WITH CHECK & USING: Test C does not suppress UPDATE disjunction, while Test D suppresses it', async () => {
          // Verify Test C with UPDATE
          const migrationsBroad: MigrationFile[] = [
            {
              filename: '01_update_test_c.sql',
              relativePath: 'supabase/migrations/01_update_test_c.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, status text);
                CREATE TABLE public.memberships (document_id uuid, user_id uuid);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Member update" ON public.documents
                  FOR UPDATE TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  )
                  WITH CHECK (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
                CREATE POLICY "Active update" ON public.documents
                  FOR UPDATE TO authenticated
                  USING (status = 'active')
                  WITH CHECK (status = 'active');
                CREATE POLICY "Broad update restrictive" ON public.documents
                  AS RESTRICTIVE
                  FOR UPDATE TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    OR status = 'active'
                  )
                  WITH CHECK (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    OR status = 'active'
                  );
              `,
            },
          ];

          const stateBroad = await buildMigrationDatabaseState(migrationsBroad);
          const findingsBroad = checkSuspiciousPolicies(stateBroad);
          const disjBroad = findingsBroad.filter((f) => f.ruleTitle.includes('Permissive Policy Disjunction'));
          expect(disjBroad).toHaveLength(1);
          expect(disjBroad[0].policyName).toBe('Active update');

          // Verify Test D with UPDATE
          const migrationsConjunctive: MigrationFile[] = [
            {
              filename: '01_update_test_d.sql',
              relativePath: 'supabase/migrations/01_update_test_d.sql',
              absolutePath: '/app/01.sql',
              content: `
                CREATE TABLE public.documents (id uuid, status text);
                CREATE TABLE public.memberships (document_id uuid, user_id uuid);
                ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
                CREATE POLICY "Member update" ON public.documents
                  FOR UPDATE TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  )
                  WITH CHECK (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                  );
                CREATE POLICY "Active update" ON public.documents
                  FOR UPDATE TO authenticated
                  USING (status = 'active')
                  WITH CHECK (status = 'active');
                CREATE POLICY "Filtered member update restrictive" ON public.documents
                  AS RESTRICTIVE
                  FOR UPDATE TO authenticated
                  USING (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    AND status = 'active'
                  )
                  WITH CHECK (
                    EXISTS (
                      SELECT 1 FROM public.memberships
                      WHERE memberships.document_id = documents.id
                        AND memberships.user_id = auth.uid()
                    )
                    AND status = 'active'
                  );
              `,
            },
          ];

          const stateConjunctive = await buildMigrationDatabaseState(migrationsConjunctive);
          const findingsConjunctive = checkSuspiciousPolicies(stateConjunctive);
          expect(findingsConjunctive).toHaveLength(0);
        });
      });
    });
  });
});
