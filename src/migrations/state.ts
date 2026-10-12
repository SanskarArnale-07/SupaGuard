import { isUnrestrictedPredicate, parseMigrationSql } from './parser.js';
import type {
  MigrationDatabaseState,
  MigrationFile,
  PolicyCommand,
  PolicyState,
  TableState,
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

      // 1. CREATE TABLE
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
      }

      // 2. ALTER TABLE ... ENABLE / DISABLE ROW LEVEL SECURITY
      else if (stmt.AlterTableStmt) {
        const alterStmt = stmt.AlterTableStmt;
        const schema = alterStmt.relation?.schemaname || 'public';
        const name = alterStmt.relation?.relname;
        if (!name) continue;

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
            }
          }
        }
      }

      // 3. CREATE POLICY
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
        const permissive = createPol.permissive !== false;
        const hasExplicitUsing = createPol.qual !== undefined;
        const hasExplicitWithCheck = createPol.with_check !== undefined;
        const isUnrestrictedUsing = isUnrestrictedPredicate(createPol.qual);
        const isUnrestrictedWithCheck = isUnrestrictedPredicate(createPol.with_check);

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
          }
          if (alterPol.with_check !== undefined) {
            existingPolicy.isUnrestrictedWithCheck = isUnrestrictedPredicate(alterPol.with_check);
            existingPolicy.hasExplicitWithCheck = true;
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
        }
      }
    }
  }

  return {
    tables,
    migrationsProcessed,
    syntaxErrors,
  };
}
