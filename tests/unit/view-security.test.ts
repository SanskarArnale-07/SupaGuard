import { describe, expect, it } from 'vitest';
import { analyzeConfig } from '../../src/analyzer/index.js';
import { buildMigrationDatabaseState } from '../../src/migrations/state.js';
import type { MigrationFile } from '../../src/migrations/types.js';
import {
  checkViewSecurity,
  resolvePhysicalTableDependencies,
} from '../../src/rules/migrations/view-security.js';
import { ExitCode } from '../../src/types/exit-codes.js';
import type { LoadedConfig } from '../../src/types/config.js';

describe('SEC-MIG-VIEW-001: PostgreSQL View Security Analysis', () => {
  const secureConfig: LoadedConfig = {
    filePath: '/app/supabase/config.toml',
    rawToml: '',
    parsed: {
      api: {
        schemas: ['public'],
      },
      db: {
        settings: {
          session_replication_role: 'origin',
        },
      },
      auth: {
        enable_refresh_token_rotation: true,
        jwt_expiry: 3600,
        email: {
          double_confirm_changes: true,
          secure_password_change: true,
        },
      },
    },
    explicitPaths: new Set([
      'api.schemas',
      'db.settings.session_replication_role',
      'auth.enable_refresh_token_rotation',
      'auth.jwt_expiry',
      'auth.email.double_confirm_changes',
      'auth.email.secure_password_change',
    ]),
  };

  // 1. Ordinary exposed view over an RLS-protected table
  it('Scenario 1: reports HIGH finding for ordinary exposed view over an RLS-protected table', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_schema.sql',
        relativePath: 'supabase/migrations/01_schema.sql',
        absolutePath: '/app/supabase/migrations/01_schema.sql',
        content: `
          CREATE TABLE public.customers (id int, email text);
          ALTER TABLE public.customers ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.customer_summary AS
            SELECT id, email FROM public.customers;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(1);
    const f = findings[0];
    expect(f.ruleId).toBe('SEC-MIG-VIEW-001');
    expect(f.severity).toBe('high');
    expect(f.schema).toBe('public');
    expect(f.table).toBeUndefined();
    expect(f.view).toBe('customer_summary');
    expect(f.filePath).toBe('supabase/migrations/01_schema.sql');
    expect(f.line).toBe(4);
    expect(f.path).toBe('supabase/migrations/01_schema.sql:4');
    expect(f.observedValue).toContain('security_invoker not enabled');
    expect(f.rationale).toContain('Row Level Security enabled: "public.customers"');
    expect(f.rationale).toContain("view owner's context");
    expect(f.rationale).toContain("invoking user's context");
    expect(f.rationale).not.toContain('SECURITY DEFINER');
    expect(f.remediation).toContain('ALTER VIEW "customer_summary" SET (security_invoker = true);');
  });

  // 2. security_invoker = true
  it('Scenario 2: produces no finding when security_invoker = true is explicitly set', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_schema.sql',
        relativePath: 'supabase/migrations/01_schema.sql',
        absolutePath: '/app/supabase/migrations/01_schema.sql',
        content: `
          CREATE TABLE public.accounts (id int, balance numeric);
          ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.account_view WITH (security_invoker = true) AS
            SELECT id, balance FROM public.accounts;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(0);
  });

  // 3. View inside an unexposed schema
  it('Scenario 3: produces no finding when view is defined inside an unexposed schema', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_schema.sql',
        relativePath: 'supabase/migrations/01_schema.sql',
        absolutePath: '/app/supabase/migrations/01_schema.sql',
        content: `
          CREATE TABLE public.secrets (id int, token text);
          ALTER TABLE public.secrets ENABLE ROW LEVEL SECURITY;
          CREATE VIEW internal.private_view AS
            SELECT id, token FROM public.secrets;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(0);
  });

  // 4. View over a table without RLS
  it('Scenario 4: emits informational advisory for view over tracked table without RLS', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_schema.sql',
        relativePath: 'supabase/migrations/01_schema.sql',
        absolutePath: '/app/supabase/migrations/01_schema.sql',
        content: `
          CREATE TABLE public.static_pages (id int, title text);
          CREATE VIEW public.page_catalog AS
            SELECT id, title FROM public.static_pages;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(1);
    const f = findings[0];
    expect(f.ruleId).toBe('SEC-MIG-VIEW-001');
    expect(f.severity).toBe('info');
    expect(f.table).toBeUndefined();
    expect(f.view).toBe('page_catalog');
    expect(f.observedValue).toContain('underlying tables do not currently enforce RLS');
    expect(f.rationale).toContain('do not currently have Row Level Security enabled');
    expect(f.remediation).toContain('ALTER VIEW "page_catalog" SET (security_invoker = true);');
  });

  // 5. CREATE OR REPLACE VIEW resetting omitted view options
  it('Scenario 5: CREATE OR REPLACE VIEW resets omitted security_invoker to false', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_view.sql',
        relativePath: 'supabase/migrations/01_view.sql',
        absolutePath: '/app/supabase/migrations/01_view.sql',
        content: `
          CREATE TABLE public.orders (id int, total numeric);
          ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.order_view WITH (security_invoker = true) AS
            SELECT id, total FROM public.orders;
        `,
      },
      {
        filename: '02_replace.sql',
        relativePath: 'supabase/migrations/02_replace.sql',
        absolutePath: '/app/supabase/migrations/02_replace.sql',
        content: `
          -- Replacing without WITH (security_invoker = true) resets reloptions in PostgreSQL
          CREATE OR REPLACE VIEW public.order_view AS
            SELECT id, total FROM public.orders WHERE total > 0;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const view = dbState.views.get('public.order_view');
    expect(view?.securityInvoker).toBe(false);

    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].table).toBeUndefined();
    expect(findings[0].view).toBe('order_view');
    expect(findings[0].filePath).toBe('supabase/migrations/02_replace.sql');
    expect(findings[0].line).toBe(3);
    expect(findings[0].path).toBe('supabase/migrations/02_replace.sql:3');
  });

  // 6. CREATE OR REPLACE VIEW explicitly enabling security_invoker
  it('Scenario 6: CREATE OR REPLACE VIEW explicitly enabling security_invoker removes security risk', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_view.sql',
        relativePath: 'supabase/migrations/01_view.sql',
        absolutePath: '/app/supabase/migrations/01_view.sql',
        content: `
          CREATE TABLE public.items (id int, name text);
          ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.item_view AS
            SELECT id, name FROM public.items;
        `,
      },
      {
        filename: '02_replace.sql',
        relativePath: 'supabase/migrations/02_replace.sql',
        absolutePath: '/app/supabase/migrations/02_replace.sql',
        content: `
          CREATE OR REPLACE VIEW public.item_view WITH (security_invoker = true) AS
            SELECT id, name FROM public.items;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const view = dbState.views.get('public.item_view');
    expect(view?.securityInvoker).toBe(true);

    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });
    expect(findings.length).toBe(0);
  });

  // 7. ALTER VIEW SET (security_invoker = true)
  it('Scenario 7: ALTER VIEW SET (security_invoker = true) enables security_invoker', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_view.sql',
        relativePath: 'supabase/migrations/01_view.sql',
        absolutePath: '/app/supabase/migrations/01_view.sql',
        content: `
          CREATE TABLE public.profiles (id int, bio text);
          ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.profile_view AS
            SELECT id, bio FROM public.profiles;
        `,
      },
      {
        filename: '02_alter.sql',
        relativePath: 'supabase/migrations/02_alter.sql',
        absolutePath: '/app/supabase/migrations/02_alter.sql',
        content: `
          ALTER VIEW public.profile_view SET (security_invoker = 'on');
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const view = dbState.views.get('public.profile_view');
    expect(view?.securityInvoker).toBe(true);

    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });
    expect(findings.length).toBe(0);
  });

  // 8. ALTER VIEW SET (security_invoker = false)
  it('Scenario 8: ALTER VIEW SET (security_invoker = false) disables security_invoker and triggers HIGH finding', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_view.sql',
        relativePath: 'supabase/migrations/01_view.sql',
        absolutePath: '/app/supabase/migrations/01_view.sql',
        content: `
          CREATE TABLE public.secrets (id int, val text);
          ALTER TABLE public.secrets ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.secret_view WITH (security_invoker = true) AS
            SELECT id, val FROM public.secrets;
        `,
      },
      {
        filename: '02_alter.sql',
        relativePath: 'supabase/migrations/02_alter.sql',
        absolutePath: '/app/supabase/migrations/02_alter.sql',
        content: `
          ALTER VIEW public.secret_view SET (security_invoker = false);
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const view = dbState.views.get('public.secret_view');
    expect(view?.securityInvoker).toBe(false);

    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].table).toBeUndefined();
    expect(findings[0].view).toBe('secret_view');
    expect(findings[0].filePath).toBe('supabase/migrations/02_alter.sql');
    expect(findings[0].line).toBe(2);
    expect(findings[0].path).toBe('supabase/migrations/02_alter.sql:2');
  });

  // 9. ALTER VIEW RESET (security_invoker)
  it('Scenario 9: ALTER VIEW RESET (security_invoker) resets security_invoker to false', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_view.sql',
        relativePath: 'supabase/migrations/01_view.sql',
        absolutePath: '/app/supabase/migrations/01_view.sql',
        content: `
          CREATE TABLE public.docs (id int, body text);
          ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.doc_view WITH (security_invoker = 1) AS
            SELECT id, body FROM public.docs;
        `,
      },
      {
        filename: '02_reset.sql',
        relativePath: 'supabase/migrations/02_reset.sql',
        absolutePath: '/app/supabase/migrations/02_reset.sql',
        content: `
          ALTER VIEW public.doc_view RESET (security_invoker);
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const view = dbState.views.get('public.doc_view');
    expect(view?.securityInvoker).toBe(false);

    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].table).toBeUndefined();
    expect(findings[0].view).toBe('doc_view');
    expect(findings[0].filePath).toBe('supabase/migrations/02_reset.sql');
    expect(findings[0].line).toBe(2);
    expect(findings[0].path).toBe('supabase/migrations/02_reset.sql:2');
  });

  // 10. DROP VIEW removing the finding
  it('Scenario 10: DROP VIEW removes the finding from final state', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_view.sql',
        relativePath: 'supabase/migrations/01_view.sql',
        absolutePath: '/app/supabase/migrations/01_view.sql',
        content: `
          CREATE TABLE public.temp (id int);
          ALTER TABLE public.temp ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.temp_view AS SELECT id FROM public.temp;
        `,
      },
      {
        filename: '02_drop.sql',
        relativePath: 'supabase/migrations/02_drop.sql',
        absolutePath: '/app/supabase/migrations/02_drop.sql',
        content: `
          DROP VIEW IF EXISTS public.temp_view;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const view = dbState.views.get('public.temp_view');
    expect(view?.dropped).toBe(true);

    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });
    expect(findings.length).toBe(0);
  });

  // 11. A view joining RLS-protected and non-RLS tables
  it('Scenario 11: detects risk when view joins RLS-protected and non-RLS tables', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_join.sql',
        relativePath: 'supabase/migrations/01_join.sql',
        absolutePath: '/app/supabase/migrations/01_join.sql',
        content: `
          CREATE TABLE public.users (id int, email text);
          ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
          CREATE TABLE public.categories (id int, label text);
          CREATE VIEW public.user_categories AS
            SELECT u.email, c.label
            FROM public.users u
            JOIN public.categories c ON u.id = c.id;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(1);
    const f = findings[0];
    expect(f.severity).toBe('high');
    expect(f.rationale).toContain('"public.users"');
  });

  // 12. CTE aliases not being treated as physical tables
  it('Scenario 12: does not treat CTE aliases as physical relations and extracts base table', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_cte.sql',
        relativePath: 'supabase/migrations/01_cte.sql',
        absolutePath: '/app/supabase/migrations/01_cte.sql',
        content: `
          CREATE TABLE public.finances (id int, amount numeric);
          ALTER TABLE public.finances ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.finance_cte_view AS
            WITH summary_cte AS (
              SELECT id, amount FROM public.finances WHERE amount > 100
            )
            SELECT id, amount FROM summary_cte;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const view = dbState.views.get('public.finance_cte_view');
    expect(view).toBeDefined();

    // Verify CTE alias 'summary_cte' was NOT collected as a physical relation
    const tableRefs = view?.referencedTables.map((r) => r.table);
    expect(tableRefs).toContain('finances');
    expect(tableRefs).not.toContain('summary_cte');

    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].rationale).toContain('"public.finances"');
  });

  // 13. A view referencing another view whose dependency is RLS-protected
  it('Scenario 13: transitively identifies RLS dependency when a view references another view', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_chain.sql',
        relativePath: 'supabase/migrations/01_chain.sql',
        absolutePath: '/app/supabase/migrations/01_chain.sql',
        content: `
          CREATE TABLE public.members (id int, name text);
          ALTER TABLE public.members ENABLE ROW LEVEL SECURITY;
          CREATE VIEW internal.member_v1 AS
            SELECT id, name FROM public.members;
          CREATE VIEW public.member_v2 AS
            SELECT id, name FROM internal.member_v1;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    // internal schema is not exposed, but public is
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(1);
    const f = findings[0];
    expect(f.schema).toBe('public');
    expect(f.table).toBeUndefined();
    expect(f.view).toBe('member_v2');
    expect(f.severity).toBe('high');
    expect(f.rationale).toContain('"public.members"');
  });

  // 14. Multiple levels of view dependency
  it('Scenario 14: resolves multi-level view dependency chains transitively', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_deep.sql',
        relativePath: 'supabase/migrations/01_deep.sql',
        absolutePath: '/app/supabase/migrations/01_deep.sql',
        content: `
          CREATE TABLE public.core_data (id int, val text);
          ALTER TABLE public.core_data ENABLE ROW LEVEL SECURITY;
          CREATE VIEW internal.layer1 AS SELECT * FROM public.core_data;
          CREATE VIEW internal.layer2 AS SELECT * FROM internal.layer1;
          CREATE VIEW internal.layer3 AS SELECT * FROM internal.layer2;
          CREATE VIEW public.api_view AS SELECT * FROM internal.layer3;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(1);
    const f = findings[0];
    expect(f.table).toBeUndefined();
    expect(f.view).toBe('api_view');
    expect(f.severity).toBe('high');
    expect(f.rationale).toContain('"public.core_data"');
  });

  // 15. Dependency cycles or unsupported definitions handled safely
  it('Scenario 15: safely handles dependency cycles between views without crashing or looping', async () => {
    // 15A: Circular dependency where a view in the loop references an RLS table
    const migrationsCycleWithTable: MigrationFile[] = [
      {
        filename: '01_cycle.sql',
        relativePath: 'supabase/migrations/01_cycle.sql',
        absolutePath: '/app/supabase/migrations/01_cycle.sql',
        content: `
          CREATE TABLE public.records (id int);
          ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.cycle_a AS SELECT id FROM public.records;
          CREATE VIEW public.cycle_b AS SELECT r.id FROM public.records r JOIN public.cycle_a a ON r.id = a.id;
          CREATE OR REPLACE VIEW public.cycle_a AS SELECT id FROM public.cycle_b;
        `,
      },
    ];

    const dbStateA = await buildMigrationDatabaseState(migrationsCycleWithTable);
    const viewA = dbStateA.views.get('public.cycle_a')!;
    expect(viewA).toBeDefined();

    const depsA = resolvePhysicalTableDependencies(viewA, dbStateA);
    expect(depsA.hasCycle).toBe(true);
    expect(depsA.physicalTables.length).toBeGreaterThanOrEqual(1);

    const findingsA = checkViewSecurity(dbStateA, { exposedSchemas: ['public'] });
    expect(Array.isArray(findingsA)).toBe(true);
    expect(findingsA.length).toBeGreaterThanOrEqual(1);
    for (const f of findingsA) {
      expect(f.severity).toBe('high');
      expect(f.rationale).toContain('circular reference');
    }

    // 15B: Pure circular dependency without physical tables
    const migrationsPureCycle: MigrationFile[] = [
      {
        filename: '01_pure_cycle.sql',
        relativePath: 'supabase/migrations/01_pure_cycle.sql',
        absolutePath: '/app/supabase/migrations/01_pure_cycle.sql',
        content: `
          CREATE VIEW public.loop_x AS SELECT 1 AS id;
          CREATE VIEW public.loop_y AS SELECT id FROM public.loop_x;
          CREATE OR REPLACE VIEW public.loop_x AS SELECT id FROM public.loop_y;
        `,
      },
    ];

    const dbStateB = await buildMigrationDatabaseState(migrationsPureCycle);
    const viewX = dbStateB.views.get('public.loop_x')!;
    const depsB = resolvePhysicalTableDependencies(viewX, dbStateB);
    expect(depsB.hasCycle).toBe(true);

    const findingsB = checkViewSecurity(dbStateB, { exposedSchemas: ['public'] });
    expect(findingsB.length).toBeGreaterThanOrEqual(1);
    expect(findingsB[0].severity).toBe('info');
    expect(findingsB[0].rationale).toContain('circular reference');
  });

  // 16. Underlying table RLS enabled or disabled by later migrations
  it('Scenario 16: evaluates view against cumulative final state of underlying table RLS', async () => {
    // Case 16A: View created when table has NO RLS, but later migration enables RLS
    const migrationsA: MigrationFile[] = [
      {
        filename: '01_view_first.sql',
        relativePath: 'supabase/migrations/01_view_first.sql',
        absolutePath: '/app/supabase/migrations/01_view_first.sql',
        content: `
          CREATE TABLE public.posts (id int, title text);
          CREATE VIEW public.post_view AS SELECT id, title FROM public.posts;
        `,
      },
      {
        filename: '02_enable_rls.sql',
        relativePath: 'supabase/migrations/02_enable_rls.sql',
        absolutePath: '/app/supabase/migrations/02_enable_rls.sql',
        content: `
          ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;
        `,
      },
    ];

    const dbStateA = await buildMigrationDatabaseState(migrationsA);
    const findingsA = checkViewSecurity(dbStateA, { exposedSchemas: ['public'] });
    expect(findingsA.length).toBe(1);
    expect(findingsA[0].severity).toBe('high');

    // Case 16B: View created when table HAS RLS, but later migration disables RLS
    const migrationsB: MigrationFile[] = [
      {
        filename: '01_view_rls.sql',
        relativePath: 'supabase/migrations/01_view_rls.sql',
        absolutePath: '/app/supabase/migrations/01_view_rls.sql',
        content: `
          CREATE TABLE public.drafts (id int, title text);
          ALTER TABLE public.drafts ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.draft_view AS SELECT id, title FROM public.drafts;
        `,
      },
      {
        filename: '02_disable_rls.sql',
        relativePath: 'supabase/migrations/02_disable_rls.sql',
        absolutePath: '/app/supabase/migrations/02_disable_rls.sql',
        content: `
          ALTER TABLE public.drafts DISABLE ROW LEVEL SECURITY;
        `,
      },
    ];

    const dbStateB = await buildMigrationDatabaseState(migrationsB);
    const findingsB = checkViewSecurity(dbStateB, { exposedSchemas: ['public'] });
    // In final state, drafts has no RLS, so finding severity is info advisory (not high)
    expect(findingsB.length).toBe(1);
    expect(findingsB[0].severity).toBe('info');
  });

  // 17. A legitimate public-data view
  it('Scenario 17: legitimate public-data view with security_invoker = true passes preflight cleanly', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_public.sql',
        relativePath: 'supabase/migrations/01_public.sql',
        absolutePath: '/app/supabase/migrations/01_public.sql',
        content: `
          CREATE TABLE public.announcements (id int, headline text);
          ALTER TABLE public.announcements ENABLE ROW LEVEL SECURITY;
          CREATE POLICY "Public read announcements" ON public.announcements
            FOR SELECT TO anon, authenticated USING (true);
          CREATE VIEW public.active_announcements WITH (security_invoker = true) AS
            SELECT id, headline FROM public.announcements;
        `,
      },
    ];

    const result = await analyzeConfig(secureConfig, {
      migrations,
      strict: false,
    });

    // View is secure, no HIGH findings for the view
    const viewFindings = result.findings.filter((f) => f.ruleId === 'SEC-MIG-VIEW-001');
    expect(viewFindings.length).toBe(0);
    expect(result.exitCode).toBe(ExitCode.SUCCESS);
  });

  // 18. A view with unknown owner or privilege information
  it('Scenario 18: carefully words finding for views with unknown owner privileges and notes FORCE RLS nuance', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_unknown_owner.sql',
        relativePath: 'supabase/migrations/01_unknown_owner.sql',
        absolutePath: '/app/supabase/migrations/01_unknown_owner.sql',
        content: `
          CREATE TABLE public.billing (id int, amount numeric);
          ALTER TABLE public.billing ENABLE ROW LEVEL SECURITY;
          ALTER TABLE public.billing FORCE ROW LEVEL SECURITY;
          CREATE VIEW public.billing_view AS
            SELECT id, amount FROM public.billing;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(1);
    const f = findings[0];
    expect(f.ruleId).toBe('SEC-MIG-VIEW-001');
    expect(f.severity).toBe('high');
    expect(f.schema).toBe('public');
    expect(f.table).toBeUndefined();
    expect(f.view).toBe('billing_view');
    expect(f.filePath).toBe('supabase/migrations/01_unknown_owner.sql');
    expect(f.line).toBe(5);

    // Assert that owner uncertainty and FORCE ROW LEVEL SECURITY are articulated
    expect(f.rationale).toContain('FORCE ROW LEVEL SECURITY');
    expect(f.rationale).toContain('BYPASSRLS');
    expect(f.rationale).toContain('potential risk of RLS bypass rather than a guaranteed bypass');
    expect(f.rationale).toContain('view owner is not explicitly declared');
    expect(f.policyAssumption).toContain('security_invoker');
    expect(f.remediation).toContain('ALTER VIEW "billing_view" SET (security_invoker = true);');
  });

  // 19. Retains original creation location when subsequent migration only alters owner
  it('Scenario 19: retains original creation location when a later migration alters owner without changing security_invoker', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_view.sql',
        relativePath: 'supabase/migrations/01_view.sql',
        absolutePath: '/app/supabase/migrations/01_view.sql',
        content: `
          CREATE TABLE public.payments (id int, amount numeric);
          ALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;
          CREATE VIEW public.payment_view AS
            SELECT id, amount FROM public.payments;
        `,
      },
      {
        filename: '02_owner.sql',
        relativePath: 'supabase/migrations/02_owner.sql',
        absolutePath: '/app/supabase/migrations/02_owner.sql',
        content: `
          ALTER VIEW public.payment_view OWNER TO app_admin;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(1);
    const f = findings[0];
    expect(f.severity).toBe('high');
    expect(f.view).toBe('payment_view');
    expect(f.table).toBeUndefined();
    // Insecure state originated at 01_view.sql:4 (not 02_owner.sql)
    expect(f.filePath).toBe('supabase/migrations/01_view.sql');
    expect(f.line).toBe(4);
    expect(f.path).toBe('supabase/migrations/01_view.sql:4');
  });

  // 20. Exposed pre-existing view appearing only through ALTER VIEW
  it('Scenario 20: emits informational finding for exposed pre-existing view appearing only in ALTER VIEW', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_alter_only.sql',
        relativePath: 'supabase/migrations/01_alter_only.sql',
        absolutePath: '/app/supabase/migrations/01_alter_only.sql',
        content: `
          ALTER VIEW public.pre_existing_view OWNER TO app_admin;
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(1);
    const f = findings[0];
    expect(f.ruleId).toBe('SEC-MIG-VIEW-001');
    expect(f.severity).toBe('info');
    expect(f.view).toBe('pre_existing_view');
    expect(f.table).toBeUndefined();
    expect(f.filePath).toBe('supabase/migrations/01_alter_only.sql');
    expect(f.line).toBe(2);
    expect(f.path).toBe('supabase/migrations/01_alter_only.sql:2');
    expect(f.observedValue).toContain('underlying view definition and dependencies untracked');
    expect(f.rationale).toContain('preceding CREATE VIEW statement in tracked migrations');
    expect(f.rationale).not.toContain('SECURITY DEFINER');
    expect(f.remediation).toContain('ALTER VIEW "pre_existing_view" SET (security_invoker = true);');
  });

  // 21. ALTER VIEW SET (security_invoker = true) on pre-existing view produces no finding
  it('Scenario 21: ALTER VIEW SET (security_invoker = true) on pre-existing view produces no finding', async () => {
    const migrations: MigrationFile[] = [
      {
        filename: '01_secure_alter.sql',
        relativePath: 'supabase/migrations/01_secure_alter.sql',
        absolutePath: '/app/supabase/migrations/01_secure_alter.sql',
        content: `
          ALTER VIEW public.legacy_view SET (security_invoker = true);
        `,
      },
    ];

    const dbState = await buildMigrationDatabaseState(migrations);
    const findings = checkViewSecurity(dbState, { exposedSchemas: ['public'] });

    expect(findings.length).toBe(0);
  });

  // Additional end-to-end integration test with analyzeConfig
  describe('Analyzer Pipeline Integration', () => {
    it('evaluates rule count = 3 for migrations and blocks preflight on view security finding', async () => {
      const migrations: MigrationFile[] = [
        {
          filename: '01_leak.sql',
          relativePath: 'supabase/migrations/01_leak.sql',
          absolutePath: '/app/supabase/migrations/01_leak.sql',
          content: `
            CREATE TABLE public.clients (id int, ssn text);
            ALTER TABLE public.clients ENABLE ROW LEVEL SECURITY;
            CREATE POLICY "Own client" ON public.clients
              FOR SELECT TO authenticated USING (auth.uid() = id);
            CREATE VIEW public.exposed_clients AS
              SELECT id, ssn FROM public.clients;
          `,
        },
      ];

      const result = await analyzeConfig(secureConfig, {
        migrations,
        strict: false,
      });

      // 13 builtin TOML rules + 3 migration rules = 16 rules evaluated
      expect(result.summary.totalRulesEvaluated).toBe(16);
      expect(result.exitCode).toBe(ExitCode.SECURITY_FINDINGS);
      expect(result.summary.high).toBeGreaterThanOrEqual(1);

      const viewFinding = result.findings.find((f) => f.ruleId === 'SEC-MIG-VIEW-001');
      expect(viewFinding).toBeDefined();
      expect(viewFinding?.severity).toBe('high');
    });
  });
});
