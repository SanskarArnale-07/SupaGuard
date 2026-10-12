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
