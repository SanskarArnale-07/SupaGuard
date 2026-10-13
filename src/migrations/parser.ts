import { parse } from 'pgsql-parser';

export interface ParsedStatement {
  stmt: Record<string, any>;
  stmtLocation: number;
  line: number;
  column: number;
}

export interface SqlParseSuccess {
  success: true;
  statements: ParsedStatement[];
}

export interface SqlParseFailure {
  success: false;
  error: {
    message: string;
    line: number;
    column: number;
  };
}

export type SqlParseResult = SqlParseSuccess | SqlParseFailure;

/**
 * Converts a 0-based character offset in a text file into 1-based line and column numbers.
 */
export function offsetToLineAndColumn(content: string, offset: number): { line: number; column: number } {
  if (offset <= 0) {
    return { line: 1, column: 1 };
  }
  const safeOffset = Math.min(offset, content.length);
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < safeOffset; i++) {
    if (content[i] === '\n') {
      line++;
      lastNewline = i;
    }
  }
  const column = safeOffset - lastNewline;
  return { line, column };
}

/**
 * Checks if an AST node in a USING or WITH CHECK clause represents an unconditionally true predicate.
 * Supports:
 * - Literal `true` (`A_Const.boolval.boolval === true`)
 * - TypeCast on boolean true (`true::boolean`)
 * - Compound boolean expressions (`true AND true`, `... OR true`)
 * - Tautologies like `1 = 1` (`A_Expr` with `=` and identical operands)
 */
export function isUnrestrictedPredicate(node: any): boolean {
  if (!node || typeof node !== 'object') {
    return false;
  }

  // 1. Literal boolean TRUE: USING (true) or WITH CHECK (true)
  if (node.A_Const?.boolval?.boolval === true) {
    return true;
  }

  // 2. TypeCast on an unrestricted predicate: true::boolean
  if (node.TypeCast?.arg) {
    return isUnrestrictedPredicate(node.TypeCast.arg);
  }

  // 3. Boolean compound expressions: AND_EXPR and OR_EXPR
  if (node.BoolExpr && Array.isArray(node.BoolExpr.args)) {
    if (node.BoolExpr.boolop === 'AND_EXPR') {
      return (
        node.BoolExpr.args.length > 0 &&
        node.BoolExpr.args.every((arg: any) => isUnrestrictedPredicate(arg))
      );
    }
    if (node.BoolExpr.boolop === 'OR_EXPR') {
      return node.BoolExpr.args.some((arg: any) => isUnrestrictedPredicate(arg));
    }
  }

  // 4. Tautological equality: 1 = 1, 'a' = 'a', true = true
  if (node.A_Expr && node.A_Expr.kind === 'AEXPR_OP') {
    const opNames = node.A_Expr.name;
    const isEquals =
      Array.isArray(opNames) &&
      opNames.some((op: any) => op?.String?.sval === '=');

    if (isEquals) {
      const left = node.A_Expr.lexpr?.A_Const;
      const right = node.A_Expr.rexpr?.A_Const;

      if (left && right) {
        // Integer equality: 1 = 1
        if (
          left.ival?.ival !== undefined &&
          left.ival?.ival === right.ival?.ival
        ) {
          return true;
        }
        // String equality: 'a' = 'a'
        if (
          left.sval?.sval !== undefined &&
          left.sval?.sval === right.sval?.sval
        ) {
          return true;
        }
        // Boolean equality: true = true
        if (
          left.boolval?.boolval !== undefined &&
          left.boolval?.boolval === right.boolval?.boolval
        ) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Checks if an AST node in a USING or WITH CHECK clause references user authentication
 * or session identity functions/fields (e.g. auth.uid(), auth.jwt(), current_user, etc.).
 */
export function hasAuthReference(node: any): boolean {
  if (!node || typeof node !== 'object') {
    return false;
  }

  // 1. FuncCall to auth schema or identity functions
  if (node.FuncCall && Array.isArray(node.FuncCall.funcname)) {
    const parts = node.FuncCall.funcname
      .map((item: any) => item?.String?.sval?.toLowerCase())
      .filter(Boolean);
    if (parts.length >= 2 && parts[0] === 'auth') {
      return true;
    }
    if (parts.includes('current_user') || parts.includes('session_user')) {
      return true;
    }
    if (parts[0] === 'current_setting') {
      return true;
    }
  }

  // 2. ColumnRef with auth schema qualification (e.g. auth.uid)
  if (node.ColumnRef && Array.isArray(node.ColumnRef.fields)) {
    const fields = node.ColumnRef.fields
      .map((item: any) => item?.String?.sval?.toLowerCase())
      .filter(Boolean);
    if (fields.length >= 2 && fields[0] === 'auth') {
      return true;
    }
  }

  // 3. Recursively inspect all child nodes and arrays
  for (const key of Object.keys(node)) {
    const val = node[key];
    if (val && typeof val === 'object') {
      if (hasAuthReference(val)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Unwraps TypeCast nodes to access the underlying AST expression.
 */
export function unwrapExpression(node: any): any {
  if (!node || typeof node !== 'object') return node;
  if (node.TypeCast && node.TypeCast.arg) {
    return unwrapExpression(node.TypeCast.arg);
  }
  return node;
}

/**
 * Checks whether an AST node is a ColumnRef referencing a table column (not an auth schema reference).
 */
export function isTableColumnRef(node: any): boolean {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return false;
  if (unwrapped.ColumnRef && Array.isArray(unwrapped.ColumnRef.fields) && unwrapped.ColumnRef.fields.length > 0) {
    const firstField = unwrapped.ColumnRef.fields[0]?.String?.sval?.toLowerCase();
    if (firstField === 'auth') return false;
    return true;
  }
  return false;
}

/**
 * Checks whether an AST node references at least one table column (or contains a subquery).
 */
export function hasTableColumnReference(node: any): boolean {
  if (!node || typeof node !== 'object') return false;
  if (isTableColumnRef(node)) return true;
  if (node.SubLink) return true;
  for (const key of Object.keys(node)) {
    const val = node[key];
    if (val && typeof val === 'object') {
      if (hasTableColumnReference(val)) return true;
    }
  }
  return false;
}

/**
 * Checks whether an expression represents the acting user's ID (e.g. auth.uid(), (auth.jwt()->>'sub')).
 */
export function isAuthUidCall(node: any): boolean {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return false;

  // FuncCall auth.uid()
  if (unwrapped.FuncCall && Array.isArray(unwrapped.FuncCall.funcname)) {
    const parts = unwrapped.FuncCall.funcname
      .map((item: any) => item?.String?.sval?.toLowerCase())
      .filter(Boolean);
    if (parts.length >= 2 && parts[0] === 'auth' && parts[1] === 'uid') {
      return true;
    }
  }

  // ColumnRef auth.uid
  if (unwrapped.ColumnRef && Array.isArray(unwrapped.ColumnRef.fields)) {
    const fields = unwrapped.ColumnRef.fields
      .map((item: any) => item?.String?.sval?.toLowerCase())
      .filter(Boolean);
    if (fields.length >= 2 && fields[0] === 'auth' && fields[1] === 'uid') {
      return true;
    }
  }

  // auth.jwt()->>'sub'
  if (unwrapped.A_Expr && unwrapped.A_Expr.kind === 'AEXPR_OP') {
    const op = unwrapped.A_Expr.name?.[0]?.String?.sval;
    if (op === '->>' || op === '->') {
      const lexpr = unwrapExpression(unwrapped.A_Expr.lexpr);
      const rexpr = unwrapExpression(unwrapped.A_Expr.rexpr);
      if (lexpr?.FuncCall && Array.isArray(lexpr.FuncCall.funcname)) {
        const parts = lexpr.FuncCall.funcname.map((i: any) => i?.String?.sval?.toLowerCase()).filter(Boolean);
        if (parts[0] === 'auth' && parts[1] === 'jwt') {
          const constVal = rexpr?.A_Const?.sval?.sval?.toLowerCase();
          if (constVal === 'sub') return true;
        }
      }
    }
  }

  return false;
}

/**
 * Checks whether an expression extracts a tenant identifier claim (e.g. (auth.jwt()->>'tenant_id')).
 */
export function isTenantClaimCall(node: any): boolean {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return false;

  if (unwrapped.A_Expr && unwrapped.A_Expr.kind === 'AEXPR_OP') {
    const op = unwrapped.A_Expr.name?.[0]?.String?.sval;
    if (op === '->>' || op === '->') {
      const lexpr = unwrapExpression(unwrapped.A_Expr.lexpr);
      const rexpr = unwrapExpression(unwrapped.A_Expr.rexpr);

      let rootCall = lexpr;
      while (
        rootCall?.A_Expr &&
        (rootCall.A_Expr.name?.[0]?.String?.sval === '->' || rootCall.A_Expr.name?.[0]?.String?.sval === '->>')
      ) {
        rootCall = unwrapExpression(rootCall.A_Expr.lexpr);
      }

      if (rootCall?.FuncCall && Array.isArray(rootCall.FuncCall.funcname)) {
        const parts = rootCall.FuncCall.funcname.map((i: any) => i?.String?.sval?.toLowerCase()).filter(Boolean);
        if (parts[0] === 'auth' && parts[1] === 'jwt') {
          const constVal = rexpr?.A_Const?.sval?.sval?.toLowerCase();
          if (
            constVal &&
            (constVal.includes('tenant') ||
              constVal.includes('org') ||
              constVal.includes('account') ||
              constVal.includes('team') ||
              constVal.includes('workspace') ||
              constVal.includes('company') ||
              constVal.includes('group'))
          ) {
            return true;
          }
        }
      }
    }
  }

  if (unwrapped.ColumnRef && Array.isArray(unwrapped.ColumnRef.fields)) {
    const fields = unwrapped.ColumnRef.fields.map((i: any) => i?.String?.sval?.toLowerCase()).filter(Boolean);
    if (fields.length >= 2 && fields[0] === 'auth' && isTenantColumnName(fields[1])) {
      return true;
    }
  }

  return false;
}

export function getColumnName(node: any): string | null {
  const unwrapped = unwrapExpression(node);
  if (unwrapped?.ColumnRef && Array.isArray(unwrapped.ColumnRef.fields)) {
    const fields = unwrapped.ColumnRef.fields;
    const lastField = fields[fields.length - 1]?.String?.sval?.toLowerCase();
    return lastField || null;
  }
  return null;
}

export function parseColumnRef(
  node: any
): { schema?: string; table?: string; column: string } | null {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return null;
  if (unwrapped.ColumnRef && Array.isArray(unwrapped.ColumnRef.fields)) {
    const fields = unwrapped.ColumnRef.fields
      .map((f: any) => f?.String?.sval?.toLowerCase())
      .filter(Boolean);
    if (fields.length === 0) return null;
    if (fields[0] === 'auth') return null;
    if (fields.length === 1) {
      return { column: fields[0] };
    }
    if (fields.length === 2) {
      return { table: fields[0], column: fields[1] };
    }
    if (fields.length >= 3) {
      return { schema: fields[0], table: fields[1], column: fields[2] };
    }
  }
  return null;
}

export function isTenantColumnName(name?: string | null): boolean {
  if (!name) return false;
  const lower = name.toLowerCase();
  return (
    lower.includes('tenant') ||
    lower.includes('org') ||
    lower.includes('organization') ||
    lower.includes('workspace') ||
    lower.includes('company') ||
    lower.includes('team') ||
    lower.includes('group')
  );
}

export function isUserColumnName(name?: string | null, tableName?: string): boolean {
  if (!name) return false;
  const lower = name.toLowerCase();
  if (isTenantColumnName(lower)) return false;

  const tableLower = tableName ? tableName.toLowerCase() : '';
  if ((tableLower === 'users' || tableLower === 'profiles' || tableLower === 'accounts') && lower === 'id') {
    return true;
  }

  return (
    lower === 'user_id' ||
    lower === 'owner_id' ||
    lower === 'author_id' ||
    lower === 'creator_id' ||
    lower === 'created_by' ||
    lower === 'profile_id' ||
    lower === 'user' ||
    lower === 'owner' ||
    lower === 'author' ||
    lower === 'creator'
  );
}

function getFromClauseTableNames(fromClause: any[] | undefined): Set<string> {
  const names = new Set<string>();
  if (!Array.isArray(fromClause)) return names;
  function visit(node: any) {
    if (!node || typeof node !== 'object') return;
    if (node.RangeVar?.relname) {
      names.add(node.RangeVar.relname.toLowerCase());
    }
    if (node.JoinExpr) {
      visit(node.JoinExpr.larg);
      visit(node.JoinExpr.rarg);
    }
  }
  for (const item of fromClause) {
    visit(item);
  }
  return names;
}

function extractColumnRefs(node: any, result: string[][] = []): string[][] {
  if (!node || typeof node !== 'object') return result;
  if (node.ColumnRef && Array.isArray(node.ColumnRef.fields)) {
    const fields = node.ColumnRef.fields
      .map((f: any) => f?.String?.sval?.toLowerCase())
      .filter(Boolean);
    if (fields.length > 0 && fields[0] !== 'auth') {
      result.push(fields);
    }
  }
  for (const key of Object.keys(node)) {
    const val = node[key];
    if (val && typeof val === 'object') {
      extractColumnRefs(val, result);
    }
  }
  return result;
}

function extractEqualities(node: any): Array<{ left: any; right: any }> {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return [];

  if (unwrapped.A_Expr && unwrapped.A_Expr.kind === 'AEXPR_OP') {
    const op = unwrapped.A_Expr.name?.[0]?.String?.sval;
    if (op === '=') {
      return [
        {
          left: unwrapExpression(unwrapped.A_Expr.lexpr),
          right: unwrapExpression(unwrapped.A_Expr.rexpr),
        },
      ];
    }
  }

  if (unwrapped.BoolExpr) {
    const list: Array<{ left: any; right: any }> = [];
    if (Array.isArray(unwrapped.BoolExpr.args)) {
      for (const arg of unwrapped.BoolExpr.args) {
        list.push(...extractEqualities(arg));
      }
    }
    return list;
  }

  return [];
}

function analyzeSubqueryCorrelation(
  sublinkNode: any,
  targetTableName?: string
): {
  isCorrelated: boolean;
  isEntityRowCorrelation: boolean;
  isTenantGroupCorrelation: boolean;
  hasUserBinding: boolean;
} {
  const selectStmt = sublinkNode?.SubLink?.subselect?.SelectStmt;
  if (!selectStmt) {
    return {
      isCorrelated: false,
      isEntityRowCorrelation: false,
      isTenantGroupCorrelation: false,
      hasUserBinding: false,
    };
  }

  const subqueryTables = getFromClauseTableNames(selectStmt.fromClause);
  const whereClause = selectStmt.whereClause;
  if (!whereClause) {
    return {
      isCorrelated: false,
      isEntityRowCorrelation: false,
      isTenantGroupCorrelation: false,
      hasUserBinding: false,
    };
  }

  const allCols = extractColumnRefs(whereClause);
  const targetLower = targetTableName ? targetTableName.toLowerCase() : null;

  // Find columns that refer to the outer/target table
  const outerCols = allCols.filter((fields) => {
    if (fields.length >= 2) {
      const qualifier = fields[0];
      if (targetLower && qualifier === targetLower) return true;
      if (!subqueryTables.has(qualifier)) return true;
      return false;
    }
    return false;
  });

  const isCorrelated = outerCols.length > 0;

  // Extract all equalities in the subquery
  const equalities = extractEqualities(whereClause);

  let hasUserBinding = false;
  let isEntityRowCorrelation = false;
  let isTenantGroupCorrelation = false;

  for (const eq of equalities) {
    const leftUid = isAuthUidCall(eq.left);
    const rightUid = isAuthUidCall(eq.right);

    // Check for user identity check: inner_table.user_id = auth.uid()
    if (leftUid && !rightUid) {
      const colRef = parseColumnRef(eq.right);
      if (colRef && isUserColumnName(colRef.column)) {
        if (!colRef.table || subqueryTables.has(colRef.table)) {
          hasUserBinding = true;
        }
      }
    } else if (rightUid && !leftUid) {
      const colRef = parseColumnRef(eq.left);
      if (colRef && isUserColumnName(colRef.column)) {
        if (!colRef.table || subqueryTables.has(colRef.table)) {
          hasUserBinding = true;
        }
      }
    }

    // Check for correlation equijoin between outer and inner tables
    const colLeft = parseColumnRef(eq.left);
    const colRight = parseColumnRef(eq.right);

    if (colLeft && colRight) {
      let outerCol: { table?: string; column: string } | null = null;
      let innerCol: { table?: string; column: string } | null = null;

      const leftIsOuter =
        (targetLower !== null && colLeft.table === targetLower) ||
        (colLeft.table !== undefined && !subqueryTables.has(colLeft.table));
      const rightIsOuter =
        (targetLower !== null && colRight.table === targetLower) ||
        (colRight.table !== undefined && !subqueryTables.has(colRight.table));

      const leftIsInner =
        (colLeft.table !== undefined && subqueryTables.has(colLeft.table)) ||
        (!colLeft.table && !leftIsOuter);
      const rightIsInner =
        (colRight.table !== undefined && subqueryTables.has(colRight.table)) ||
        (!colRight.table && !rightIsOuter);

      if (leftIsOuter && rightIsInner) {
        outerCol = colLeft;
        innerCol = colRight;
      } else if (rightIsOuter && leftIsInner) {
        outerCol = colRight;
        innerCol = colLeft;
      }

      if (outerCol && innerCol) {
        const outName = outerCol.column.toLowerCase();
        // Check if joining on the target row's entity identifier (e.g. documents.id = memberships.document_id)
        if (outName === 'id' || (targetLower && outName === `${targetLower}_id`)) {
          isEntityRowCorrelation = true;
        } else if (isTenantColumnName(outName)) {
          isTenantGroupCorrelation = true;
        }
      }
    }
  }

  return {
    isCorrelated,
    isEntityRowCorrelation,
    isTenantGroupCorrelation,
    hasUserBinding,
  };
}

function getRowOwnershipEqualityColumn(node: any, targetTableName?: string): string | null {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return null;

  if (unwrapped.A_Expr && unwrapped.A_Expr.kind === 'AEXPR_OP') {
    const op = unwrapped.A_Expr.name?.[0]?.String?.sval;
    if (op === '=') {
      const left = unwrapExpression(unwrapped.A_Expr.lexpr);
      const right = unwrapExpression(unwrapped.A_Expr.rexpr);

      const leftIsUid = isAuthUidCall(left);
      const rightIsUid = isAuthUidCall(right);

      // Comparison between two identity calls (e.g. auth.uid() = auth.uid()) is NOT row ownership
      if (leftIsUid && rightIsUid) return null;

      const leftIsCol = isTableColumnRef(left);
      const rightIsCol = isTableColumnRef(right);

      if (leftIsUid && rightIsCol) {
        const colName = getColumnName(right);
        if (colName && !isTenantColumnName(colName) && isUserColumnName(colName, targetTableName)) {
          return colName.toLowerCase();
        }
        return null;
      }

      if (leftIsCol && rightIsUid) {
        const colName = getColumnName(left);
        if (colName && !isTenantColumnName(colName) && isUserColumnName(colName, targetTableName)) {
          return colName.toLowerCase();
        }
        return null;
      }
    }
  }

  return null;
}

function isRowOwnershipEquality(node: any, targetTableName?: string): boolean {
  return getRowOwnershipEqualityColumn(node, targetTableName) !== null;
}

/**
 * Extracts specific table column names that are directly bound to auth identity (e.g. ['user_id']).
 * For Boolean AND, collects all distinct ownership columns.
 * For Boolean OR, returns only columns present in all branches where every branch enforces ownership.
 */
export function extractRowOwnershipColumns(node: any, targetTableName?: string): string[] {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return [];

  const directCol = getRowOwnershipEqualityColumn(unwrapped, targetTableName);
  if (directCol) {
    return [directCol];
  }

  if (unwrapped.BoolExpr && Array.isArray(unwrapped.BoolExpr.args)) {
    const op = unwrapped.BoolExpr.boolop;
    if (op === 'AND_EXPR') {
      const cols = new Set<string>();
      for (const arg of unwrapped.BoolExpr.args) {
        for (const col of extractRowOwnershipColumns(arg, targetTableName)) {
          cols.add(col);
        }
      }
      return Array.from(cols);
    }
    if (op === 'OR_EXPR') {
      if (
        unwrapped.BoolExpr.args.length > 0 &&
        unwrapped.BoolExpr.args.every((arg: any) => hasRowOwnershipPredicate(arg, targetTableName))
      ) {
        const branchColSets: Set<string>[] = unwrapped.BoolExpr.args.map((arg: any) =>
          new Set<string>(extractRowOwnershipColumns(arg, targetTableName))
        );
        if (branchColSets.length === 0) return [];
        const commonCols: string[] = Array.from(branchColSets[0]).filter((col: string) =>
          branchColSets.every((s: Set<string>) => s.has(col))
        );
        return commonCols;
      }
      return [];
    }
  }

  return [];
}

function isTenantBoundaryEquality(node: any, targetTableName?: string): boolean {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return false;

  if (unwrapped.A_Expr && unwrapped.A_Expr.kind === 'AEXPR_OP') {
    const op = unwrapped.A_Expr.name?.[0]?.String?.sval;
    if (op === '=') {
      const left = unwrapExpression(unwrapped.A_Expr.lexpr);
      const right = unwrapExpression(unwrapped.A_Expr.rexpr);

      const leftIsTenant = isTenantClaimCall(left);
      const rightIsTenant = isTenantClaimCall(right);

      if (leftIsTenant && rightIsTenant) return false;

      const leftIsCol = isTableColumnRef(left);
      const rightIsCol = isTableColumnRef(right);

      if (leftIsTenant && rightIsCol && isTenantColumnName(getColumnName(right))) {
        return true;
      }
      if (leftIsCol && rightIsTenant && isTenantColumnName(getColumnName(left))) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Checks whether an AST predicate enforces individual row ownership (e.g. auth.uid() = user_id).
 * For Boolean OR, every branch must enforce ownership.
 * For Boolean AND, at least one branch must enforce ownership.
 * For subqueries, the subquery must be correlated to the protected table and bind user identity.
 */
export function hasRowOwnershipPredicate(node: any, targetTableName?: string): boolean {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return false;

  if (isRowOwnershipEquality(unwrapped, targetTableName)) return true;

  if (unwrapped.SubLink) {
    const { isEntityRowCorrelation, hasUserBinding } = analyzeSubqueryCorrelation(
      unwrapped,
      targetTableName
    );
    return isEntityRowCorrelation && hasUserBinding;
  }

  if (unwrapped.BoolExpr && Array.isArray(unwrapped.BoolExpr.args)) {
    const op = unwrapped.BoolExpr.boolop;
    if (op === 'AND_EXPR') {
      return unwrapped.BoolExpr.args.some((arg: any) => hasRowOwnershipPredicate(arg, targetTableName));
    }
    if (op === 'OR_EXPR') {
      return (
        unwrapped.BoolExpr.args.length > 0 &&
        unwrapped.BoolExpr.args.every((arg: any) => hasRowOwnershipPredicate(arg, targetTableName))
      );
    }
  }

  return false;
}

/**
 * Checks whether an AST predicate enforces row-level access control via an entity-correlated membership subquery
 * (e.g. EXISTS (SELECT 1 FROM memberships WHERE memberships.document_id = documents.id AND memberships.user_id = auth.uid())).
 */
export function hasEntityMembershipSubquery(node: any, targetTableName?: string): boolean {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return false;

  if (unwrapped.SubLink) {
    const { isEntityRowCorrelation, hasUserBinding } = analyzeSubqueryCorrelation(
      unwrapped,
      targetTableName
    );
    return isEntityRowCorrelation && hasUserBinding;
  }

  if (unwrapped.BoolExpr && Array.isArray(unwrapped.BoolExpr.args)) {
    const op = unwrapped.BoolExpr.boolop;
    if (op === 'AND_EXPR') {
      return unwrapped.BoolExpr.args.some((arg: any) => hasEntityMembershipSubquery(arg, targetTableName));
    }
    if (op === 'OR_EXPR') {
      return (
        unwrapped.BoolExpr.args.length > 0 &&
        unwrapped.BoolExpr.args.every((arg: any) => hasEntityMembershipSubquery(arg, targetTableName))
      );
    }
  }

  return false;
}

/**
 * Checks whether an AST predicate enforces tenant-level isolation (e.g. tenant_id = (auth.jwt()->>'tenant_id')::uuid).
 * Distinct from individual user row ownership.
 */
export function hasTenantBoundaryPredicate(node: any, targetTableName?: string): boolean {
  const unwrapped = unwrapExpression(node);
  if (!unwrapped || typeof unwrapped !== 'object') return false;

  if (isTenantBoundaryEquality(unwrapped, targetTableName)) return true;

  if (unwrapped.SubLink) {
    const { isEntityRowCorrelation, isTenantGroupCorrelation, hasUserBinding } = analyzeSubqueryCorrelation(
      unwrapped,
      targetTableName
    );
    return isTenantGroupCorrelation && !isEntityRowCorrelation && hasUserBinding;
  }

  if (unwrapped.BoolExpr && Array.isArray(unwrapped.BoolExpr.args)) {
    const op = unwrapped.BoolExpr.boolop;
    if (op === 'AND_EXPR') {
      return unwrapped.BoolExpr.args.some((arg: any) => hasTenantBoundaryPredicate(arg, targetTableName));
    }
    if (op === 'OR_EXPR') {
      return (
        unwrapped.BoolExpr.args.length > 0 &&
        unwrapped.BoolExpr.args.every((arg: any) => hasTenantBoundaryPredicate(arg, targetTableName))
      );
    }
  }

  return false;
}

/**
 * Checks whether a restrictive policy expression demonstrably narrows row accessibility.
 * Rejects unconditionally true predicates, identity existence checks without column binding
 * (e.g. auth.uid() IS NOT NULL), tautologies, and uncorrelated subqueries.
 */
export function isNarrowingRestrictivePredicate(node: any, targetTableName?: string): boolean {
  if (!node || typeof node !== 'object') return false;
  if (isUnrestrictedPredicate(node)) return false;

  const unwrapped = unwrapExpression(node);

  if (unwrapped.SubLink) {
    const { isCorrelated } = analyzeSubqueryCorrelation(unwrapped, targetTableName);
    return isCorrelated;
  }

  if (unwrapped.BoolExpr && Array.isArray(unwrapped.BoolExpr.args)) {
    const op = unwrapped.BoolExpr.boolop;
    if (op === 'OR_EXPR') {
      return (
        unwrapped.BoolExpr.args.length > 0 &&
        unwrapped.BoolExpr.args.every((arg: any) => isNarrowingRestrictivePredicate(arg, targetTableName))
      );
    }
    if (op === 'AND_EXPR') {
      return unwrapped.BoolExpr.args.some((arg: any) => isNarrowingRestrictivePredicate(arg, targetTableName));
    }
  }

  return hasTableColumnReference(unwrapped);
}

/**
 * Parses a migration's SQL content into a list of typed statements using pgsql-parser.
 * Gracefully captures syntax errors without throwing exceptions.
 */
export async function parseMigrationSql(content: string): Promise<SqlParseResult> {
  // Empty or whitespace-only files parse cleanly with 0 statements
  if (!content.trim()) {
    return {
      success: true,
      statements: [],
    };
  }

  try {
    const result = await parse(content);
    const statements: ParsedStatement[] = [];

    if (result && Array.isArray(result.stmts)) {
      for (const raw of result.stmts) {
        const stmtLocation = typeof raw.stmt_location === 'number' && raw.stmt_location >= 0
          ? raw.stmt_location
          : 0;

        const { line, column } = offsetToLineAndColumn(content, stmtLocation);

        if (!raw.stmt) continue;

        statements.push({
          stmt: raw.stmt as Record<string, any>,
          stmtLocation,
          line,
          column,
        });
      }
    }

    return {
      success: true,
      statements,
    };
  } catch (err: any) {
    const cursor = err?.sqlDetails?.cursorPosition;
    const offset = typeof cursor === 'number' && cursor >= 0 ? cursor : 0;
    const { line, column } = offsetToLineAndColumn(content, offset);

    return {
      success: false,
      error: {
        message: err?.message || 'PostgreSQL syntax error',
        line,
        column,
      },
    };
  }
}
