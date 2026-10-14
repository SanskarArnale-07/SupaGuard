import {
  extractRowOwnershipColumns,
  extractViewReferencedTables,
  hasAuthReference,
  hasEntityMembershipSubquery,
  hasRowOwnershipPredicate,
  hasTenantBoundaryPredicate,
  isNarrowingRestrictivePredicate,
  isUnrestrictedPredicate,
  parseBooleanOptionArg,
  parseMigrationSql,
  parseSecurityInvokerOption,
} from './parser.js';
import type {
  MigrationDatabaseState,
  MigrationFile,
  PolicyCommand,
  PolicyState,
  TableState,
  ViewState,
} from './types.js';

function extractRoles(rolesList: any[] | undefined): string[] {
  if (!rolesList || !Array.isArray(rolesList) || rolesList.length === 0) {
    return ['public'];
  }

  const result: string[] = [];
  for (const item of rolesList) {
    const roleSpec = item?.RoleSpec;
    if (!roleSpec) continue;

    if (roleSpec.roletype === 'ROLESPEC_PUBLIC') {
      result.push('public');
    } else if (typeof roleSpec.rolename === 'string') {
      result.push(roleSpec.rolename.trim().toLowerCase());
    }
  }

  return result.length > 0 ? result : ['public'];
}

function getTableKey(schema: string, name: string): string {
  return `${schema.trim().toLowerCase()}.${name.trim()}`;
}

/**
 * Builds the final represented database state across a deterministic sequence of SQL migrations.
 */
export async function buildMigrationDatabaseState(
  migrations: MigrationFile[]
): Promise<MigrationDatabaseState> {
  const tables = new Map<string, TableState>();
  const views = new Map<string, ViewState>();
  const syntaxErrors: Array<{
    file: string;
    line: number;
    column: number;
    message: string;
  }> = [];
  const migrationsProcessed: string[] = [];

  for (const migration of migrations) {
    const parseResult = await parseMigrationSql(migration.content);

    if (!parseResult.success) {
      syntaxErrors.push({
        file: migration.relativePath,
        line: parseResult.error.line,
        column: parseResult.error.column,
        message: parseResult.error.message,
      });
      // Continue processing other migrations rather than crashing
      continue;
    }

    migrationsProcessed.push(migration.relativePath);

    for (const parsed of parseResult.statements) {
      const stmt = parsed.stmt;
      const file = migration.relativePath;
      const line = parsed.line;

      // 1. CREATE TABLE / CREATE TABLE AS SELECT
      if (stmt.CreateStmt) {
        const createStmt = stmt.CreateStmt;
        const schema = createStmt.relation?.schemaname || 'public';
        const name = createStmt.relation?.relname;
        if (!name) continue;

        const key = getTableKey(schema, name);

        // Create or replace table state (if recreated after being dropped)
        const tableState: TableState = {
          schema,
          name,
          createdIn: { file, line },
          rowLevelSecurityEnabled: false,
          dropped: false,
          policies: new Map<string, PolicyState>(),
        };

        tables.set(key, tableState);
      } else if (stmt.CreateTableAsStmt) {
        const ctasStmt = stmt.CreateTableAsStmt;
        if (ctasStmt.objtype === 'OBJECT_TABLE' || !ctasStmt.objtype) {
          const schema = ctasStmt.into?.rel?.schemaname || 'public';
          const name = ctasStmt.into?.rel?.relname;
          if (name) {
            const key = getTableKey(schema, name);
            const tableState: TableState = {
              schema,
              name,
              createdIn: { file, line },
              rowLevelSecurityEnabled: false,
              dropped: false,
              policies: new Map<string, PolicyState>(),
            };
            tables.set(key, tableState);
          }
        }
      }

      // 2. CREATE VIEW / CREATE OR REPLACE VIEW
      else if (stmt.ViewStmt) {
        const viewStmt = stmt.ViewStmt;
        const schema = (viewStmt.view?.schemaname || 'public').trim().toLowerCase();
        const name = (viewStmt.view?.relname || '').trim();
        if (name) {
          const key = getTableKey(schema, name);
          const isReplace = viewStmt.replace === true;
          const hasExplicitOptions = Array.isArray(viewStmt.options);
          const securityInvoker = hasExplicitOptions
            ? parseSecurityInvokerOption(viewStmt.options)
            : false; // In PostgreSQL, omitted options default to false (and reset on replace)

          const referencedTables = extractViewReferencedTables(viewStmt.query);

          const existing = views.get(key);
          if (existing && isReplace) {
            // In PostgreSQL, CREATE OR REPLACE VIEW replaces reloptions and query definition
            existing.securityInvoker = securityInvoker;
            existing.referencedTables = referencedTables;
            existing.dropped = false;
            existing.definitionUntracked = false;
            existing.modifiedIn = { file, line };
          } else {
            views.set(key, {
              schema,
              name,
              securityInvoker,
              referencedTables,
              createdIn: { file, line },
              dropped: false,
            });
          }
        }
      }

      // 3. ALTER TABLE / ALTER VIEW
      else if (stmt.AlterTableStmt) {
        const alterStmt = stmt.AlterTableStmt;

        if (alterStmt.objtype === 'OBJECT_VIEW') {
          const schema = (alterStmt.relation?.schemaname || 'public').trim().toLowerCase();
          const name = (alterStmt.relation?.relname || '').trim();
          if (name) {
            const key = getTableKey(schema, name);
            let view = views.get(key);

            if (!view) {
              view = {
                schema,
                name,
                securityInvoker: false,
                referencedTables: [],
                definitionUntracked: true,
                createdIn: { file, line },
                dropped: false,
              };
              views.set(key, view);
            }

            if (Array.isArray(alterStmt.cmds)) {
              for (const cmdItem of alterStmt.cmds) {
                const cmd = cmdItem?.AlterTableCmd;
                if (!cmd) continue;

                if (cmd.subtype === 'AT_SetRelOptions' && Array.isArray(cmd.def?.List?.items)) {
                  for (const item of cmd.def.List.items) {
                    const def = item?.DefElem;
                    if (def?.defname?.toLowerCase() === 'security_invoker') {
                      view.securityInvoker = parseBooleanOptionArg(def.arg);
                      view.modifiedIn = { file, line };
                    }
                  }
                } else if (cmd.subtype === 'AT_ResetRelOptions' && Array.isArray(cmd.def?.List?.items)) {
                  for (const item of cmd.def.List.items) {
                    const def = item?.DefElem;
                    if (def?.defname?.toLowerCase() === 'security_invoker') {
                      view.securityInvoker = false;
                      view.modifiedIn = { file, line };
                    }
                  }
                } else if (cmd.subtype === 'AT_ChangeOwner' && cmd.newowner?.rolename) {
                  view.owner = cmd.newowner.rolename.trim().toLowerCase();
                }
              }
            }
          }
        } else {
          // Table alteration (ENABLE/DISABLE/FORCE ROW LEVEL SECURITY, OWNER TO)
          const schema = alterStmt.relation?.schemaname || 'public';
          const name = alterStmt.relation?.relname;
          if (name) {
            const key = getTableKey(schema, name);
            let table = tables.get(key);

            if (!table) {
              // Table created prior or outside parsed migrations, track it
              table = {
                schema,
                name,
                createdIn: { file, line },
                rowLevelSecurityEnabled: false,
                dropped: false,
                policies: new Map<string, PolicyState>(),
              };
              tables.set(key, table);
            }

            if (Array.isArray(alterStmt.cmds)) {
              for (const cmdItem of alterStmt.cmds) {
                const cmd = cmdItem?.AlterTableCmd;
                if (!cmd) continue;

                if (cmd.subtype === 'AT_EnableRowSecurity') {
                  table.rowLevelSecurityEnabled = true;
                  table.rlsChangedIn = { file, line, enabled: true };
                } else if (cmd.subtype === 'AT_DisableRowSecurity') {
                  table.rowLevelSecurityEnabled = false;
                  table.rlsChangedIn = { file, line, enabled: false };
                } else if (cmd.subtype === 'AT_ForceRowSecurity') {
                  table.forceRowLevelSecurity = true;
                  table.rlsChangedIn = { file, line, enabled: table.rowLevelSecurityEnabled };
                } else if (cmd.subtype === 'AT_NoForceRowSecurity') {
                  table.forceRowLevelSecurity = false;
                  table.rlsChangedIn = { file, line, enabled: table.rowLevelSecurityEnabled };
                } else if (cmd.subtype === 'AT_ChangeOwner' && cmd.newowner?.rolename) {
                  table.owner = cmd.newowner.rolename.trim().toLowerCase();
                }
              }
            }
          }
        }
      }

      // 4. CREATE POLICY
      else if (stmt.CreatePolicyStmt) {
        const createPol = stmt.CreatePolicyStmt;
        const policyName = createPol.policy_name;
        const schema = createPol.table?.schemaname || 'public';
        const tableName = createPol.table?.relname;
        if (!policyName || !tableName) continue;

        const key = getTableKey(schema, tableName);
        let table = tables.get(key);

        if (!table) {
          table = {
            schema,
            name: tableName,
            createdIn: { file, line },
            rowLevelSecurityEnabled: false,
            dropped: false,
            policies: new Map<string, PolicyState>(),
          };
          tables.set(key, table);
        }

        const rawCmd = (createPol.cmd_name || 'all').toLowerCase() as PolicyCommand;
        const roles = extractRoles(createPol.roles);
        const permissive = createPol.permissive === true;
        const hasExplicitUsing = createPol.qual !== undefined;
        const hasExplicitWithCheck = createPol.with_check !== undefined;

        // PostgreSQL command-specific default semantics:
        // 1. USING clause:
        //    - Applicable commands: ALL, SELECT, UPDATE, DELETE.
        //    - If qual is provided: evaluate predicate.
        //    - If qual is omitted: PostgreSQL defaults to unconditionally true (USING (true)).
        //    - For INSERT: USING is not applicable.
        let isUnrestrictedUsing = false;
        if (rawCmd === 'all' || rawCmd === 'select' || rawCmd === 'update' || rawCmd === 'delete') {
          isUnrestrictedUsing = hasExplicitUsing
            ? isUnrestrictedPredicate(createPol.qual)
            : true;
        }

        // 2. WITH CHECK clause:
        //    - For INSERT:
        //      If with_check is provided: evaluate predicate.
        //      If with_check is omitted: PostgreSQL defaults to unconditionally true (WITH CHECK (true)).
        //    - For UPDATE and ALL:
        //      If with_check is provided: evaluate predicate.
        //      If with_check is omitted: PostgreSQL inherits the USING clause expression!
        //    - For SELECT and DELETE: WITH CHECK is not applicable.
        let isUnrestrictedWithCheck = false;
        if (rawCmd === 'insert') {
          isUnrestrictedWithCheck = hasExplicitWithCheck
            ? isUnrestrictedPredicate(createPol.with_check)
            : true;
        } else if (rawCmd === 'update' || rawCmd === 'all') {
          isUnrestrictedWithCheck = hasExplicitWithCheck
            ? isUnrestrictedPredicate(createPol.with_check)
            : isUnrestrictedUsing;
        }

        const hasAuthCheckUsing = hasExplicitUsing ? hasAuthReference(createPol.qual) : false;
        let hasAuthCheckWithCheck = false;
        if (rawCmd === 'insert') {
          hasAuthCheckWithCheck = hasExplicitWithCheck
            ? hasAuthReference(createPol.with_check)
            : false;
        } else if (rawCmd === 'update' || rawCmd === 'all') {
          hasAuthCheckWithCheck = hasExplicitWithCheck
            ? hasAuthReference(createPol.with_check)
            : hasAuthCheckUsing;
        }

        const hasOwnershipCheckUsing = hasExplicitUsing
          ? hasRowOwnershipPredicate(createPol.qual, tableName)
          : false;
        let hasOwnershipCheckWithCheck = false;
        if (rawCmd === 'insert') {
          hasOwnershipCheckWithCheck = hasExplicitWithCheck
            ? hasRowOwnershipPredicate(createPol.with_check, tableName)
            : false;
        } else if (rawCmd === 'update' || rawCmd === 'all') {
          hasOwnershipCheckWithCheck = hasExplicitWithCheck
            ? hasRowOwnershipPredicate(createPol.with_check, tableName)
            : hasOwnershipCheckUsing;
        }

        const ownershipColumnsUsing = hasExplicitUsing
          ? extractRowOwnershipColumns(createPol.qual, tableName)
          : [];
        let ownershipColumnsWithCheck: string[] = [];
        if (rawCmd === 'insert') {
          ownershipColumnsWithCheck = hasExplicitWithCheck
            ? extractRowOwnershipColumns(createPol.with_check, tableName)
            : [];
        } else if (rawCmd === 'update' || rawCmd === 'all') {
          ownershipColumnsWithCheck = hasExplicitWithCheck
            ? extractRowOwnershipColumns(createPol.with_check, tableName)
            : ownershipColumnsUsing;
        }

        const hasEntityMembershipUsing = hasExplicitUsing
          ? hasEntityMembershipSubquery(createPol.qual, tableName)
          : false;
        let hasEntityMembershipWithCheck = false;
        if (rawCmd === 'insert') {
          hasEntityMembershipWithCheck = hasExplicitWithCheck
            ? hasEntityMembershipSubquery(createPol.with_check, tableName)
            : false;
        } else if (rawCmd === 'update' || rawCmd === 'all') {
          hasEntityMembershipWithCheck = hasExplicitWithCheck
            ? hasEntityMembershipSubquery(createPol.with_check, tableName)
            : hasEntityMembershipUsing;
        }

        const hasTenantCheckUsing = hasExplicitUsing
          ? hasTenantBoundaryPredicate(createPol.qual, tableName)
          : false;
        let hasTenantCheckWithCheck = false;
        if (rawCmd === 'insert') {
          hasTenantCheckWithCheck = hasExplicitWithCheck
            ? hasTenantBoundaryPredicate(createPol.with_check, tableName)
            : false;
        } else if (rawCmd === 'update' || rawCmd === 'all') {
          hasTenantCheckWithCheck = hasExplicitWithCheck
            ? hasTenantBoundaryPredicate(createPol.with_check, tableName)
            : hasTenantCheckUsing;
        }

        const isNarrowingUsing = hasExplicitUsing
          ? isNarrowingRestrictivePredicate(createPol.qual, tableName)
          : false;
        let isNarrowingWithCheck = false;
        if (rawCmd === 'insert') {
          isNarrowingWithCheck = hasExplicitWithCheck
            ? isNarrowingRestrictivePredicate(createPol.with_check, tableName)
            : false;
        } else if (rawCmd === 'update' || rawCmd === 'all') {
          isNarrowingWithCheck = hasExplicitWithCheck
            ? isNarrowingRestrictivePredicate(createPol.with_check, tableName)
            : isNarrowingUsing;
        }

        const policyState: PolicyState = {
          name: policyName,
          schema,
          table: tableName,
          command: rawCmd,
          roles,
          permissive,
          isUnrestrictedUsing,
          isUnrestrictedWithCheck,
          hasExplicitUsing,
          hasExplicitWithCheck,
          hasAuthCheckUsing,
          hasAuthCheckWithCheck,
          hasOwnershipCheckUsing,
          hasOwnershipCheckWithCheck,
          ownershipColumnsUsing,
          ownershipColumnsWithCheck,
          hasEntityMembershipUsing,
          hasEntityMembershipWithCheck,
          hasTenantCheckUsing,
          hasTenantCheckWithCheck,
          isNarrowingUsing,
          isNarrowingWithCheck,
          createdIn: { file, line },
          dropped: false,
        };

        table.policies.set(policyName, policyState);
      }

      // 4. ALTER POLICY
      else if (stmt.AlterPolicyStmt) {
        const alterPol = stmt.AlterPolicyStmt;
        const policyName = alterPol.policy_name;
        const schema = alterPol.table?.schemaname || 'public';
        const tableName = alterPol.table?.relname;
        if (!policyName || !tableName) continue;

        const key = getTableKey(schema, tableName);
        const table = tables.get(key);
        if (!table) continue;

        const existingPolicy = table.policies.get(policyName);
        if (existingPolicy && !existingPolicy.dropped) {
          if (alterPol.roles) {
            existingPolicy.roles = extractRoles(alterPol.roles);
          }
          if (alterPol.qual !== undefined) {
            existingPolicy.isUnrestrictedUsing = isUnrestrictedPredicate(alterPol.qual);
            existingPolicy.hasExplicitUsing = true;
            existingPolicy.hasAuthCheckUsing = hasAuthReference(alterPol.qual);
            existingPolicy.hasOwnershipCheckUsing = hasRowOwnershipPredicate(alterPol.qual, tableName);
            existingPolicy.ownershipColumnsUsing = extractRowOwnershipColumns(alterPol.qual, tableName);
            existingPolicy.hasEntityMembershipUsing = hasEntityMembershipSubquery(alterPol.qual, tableName);
            existingPolicy.hasTenantCheckUsing = hasTenantBoundaryPredicate(alterPol.qual, tableName);
            existingPolicy.isNarrowingUsing = isNarrowingRestrictivePredicate(alterPol.qual, tableName);
          }
          if (alterPol.with_check !== undefined) {
            existingPolicy.isUnrestrictedWithCheck = isUnrestrictedPredicate(alterPol.with_check);
            existingPolicy.hasExplicitWithCheck = true;
            existingPolicy.hasAuthCheckWithCheck = hasAuthReference(alterPol.with_check);
            existingPolicy.hasOwnershipCheckWithCheck = hasRowOwnershipPredicate(alterPol.with_check, tableName);
            existingPolicy.ownershipColumnsWithCheck = extractRowOwnershipColumns(alterPol.with_check, tableName);
            existingPolicy.hasEntityMembershipWithCheck = hasEntityMembershipSubquery(alterPol.with_check, tableName);
            existingPolicy.hasTenantCheckWithCheck = hasTenantBoundaryPredicate(alterPol.with_check, tableName);
            existingPolicy.isNarrowingWithCheck = isNarrowingRestrictivePredicate(alterPol.with_check, tableName);
          }
          existingPolicy.modifiedIn = { file, line };
        }
      }

      // 5. DROP TABLE & DROP POLICY
      else if (stmt.DropStmt) {
        const dropStmt = stmt.DropStmt;

        if (dropStmt.removeType === 'OBJECT_TABLE' && Array.isArray(dropStmt.objects)) {
          for (const obj of dropStmt.objects) {
            const items = obj?.List?.items;
            if (!Array.isArray(items) || items.length === 0) continue;

            let schema = 'public';
            let tableName = '';

            if (items.length === 1) {
              tableName = items[0]?.String?.sval || '';
            } else if (items.length >= 2) {
              schema = items[0]?.String?.sval || 'public';
              tableName = items[1]?.String?.sval || '';
            }

            if (tableName) {
              const key = getTableKey(schema, tableName);
              const table = tables.get(key);
              if (table) {
                table.dropped = true;
                table.droppedIn = { file, line };
              }
            }
          }
        } else if (dropStmt.removeType === 'OBJECT_POLICY' && Array.isArray(dropStmt.objects)) {
          for (const obj of dropStmt.objects) {
            const items = obj?.List?.items;
            if (!Array.isArray(items) || items.length < 2) continue;

            let schema = 'public';
            let tableName = '';
            let policyName = '';

            if (items.length === 2) {
              // DROP POLICY "pol" ON "table"
              tableName = items[0]?.String?.sval || '';
              policyName = items[1]?.String?.sval || '';
            } else if (items.length >= 3) {
              // DROP POLICY "pol" ON "schema"."table"
              schema = items[0]?.String?.sval || 'public';
              tableName = items[1]?.String?.sval || '';
              policyName = items[2]?.String?.sval || '';
            }

            if (tableName && policyName) {
              const key = getTableKey(schema, tableName);
              const table = tables.get(key);
              if (table) {
                const pol = table.policies.get(policyName);
                if (pol) {
                  pol.dropped = true;
                  pol.droppedIn = { file, line };
                }
              }
            }
          }
        } else if (dropStmt.removeType === 'OBJECT_VIEW' && Array.isArray(dropStmt.objects)) {
          for (const obj of dropStmt.objects) {
            const items = obj?.List?.items;
            if (!Array.isArray(items) || items.length === 0) continue;

            let schema = 'public';
            let viewName = '';

            if (items.length === 1) {
              viewName = items[0]?.String?.sval || '';
            } else if (items.length >= 2) {
              schema = items[0]?.String?.sval || 'public';
              viewName = items[1]?.String?.sval || '';
            }

            if (viewName) {
              const key = getTableKey(schema, viewName);
              const view = views.get(key);
              if (view) {
                view.dropped = true;
                view.droppedIn = { file, line };
              }
            }
          }
        }
      }
    }
  }

  return {
    tables,
    views,
    migrationsProcessed,
    syntaxErrors,
  };
}
