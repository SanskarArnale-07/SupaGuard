import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { discoverMigrations, resolveMigrationsDir } from '../../src/migrations/discover.js';
import { isUnrestrictedPredicate, offsetToLineAndColumn, parseMigrationSql } from '../../src/migrations/parser.js';
import { buildMigrationDatabaseState } from '../../src/migrations/state.js';
import type { MigrationFile } from '../../src/migrations/types.js';
import { checkMissingRls } from '../../src/rules/migrations/missing-rls.js';
import { checkSuspiciousPolicies } from '../../src/rules/migrations/suspicious-policies.js';

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

    it('does NOT flag UPDATE policy with permissive USING (true) when WITH CHECK is restrictive', async () => {
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

      // Permissive USING with restrictive WITH CHECK on UPDATE does not allow unrestricted writes
      expect(findings).toHaveLength(0);
    });

    it('does NOT flag anon UPDATE policy with permissive USING (true) when WITH CHECK is restrictive', async () => {
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
  });
});
