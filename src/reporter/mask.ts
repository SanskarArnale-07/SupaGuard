/**
 * Set of known configuration path suffixes and names that hold sensitive credentials or keys.
 */
const SENSITIVE_PATH_PATTERNS = [
  /(^|\.)(?:.*_)?secrets?$/i,
  /(^|\.)(?:.*_)?secret_?keys?$/i,
  /(^|\.)(?:.*_)?api_?keys?$/i,
  /(^|\.)(?:.*_)?access_?keys?$/i,
  /(^|\.)(?:.*_)?auth_?tokens?$/i,
  /(^|\.)(?:.*_)?bearer_?tokens?$/i,
  /(^|\.)(?:.*_)?bot_?tokens?$/i,
  /(^|\.)(?:.*_)?encryption_?keys?$/i,
  /(^|\.)(?:.*_)?signing_?keys?$/i,
  /(^|\.)(?:.*_)?passwords?$/i,
  /(^|\.)pass$/i,
  /(^|\.)(?:.*_)?service_?role_?key$/i,
  /(^|\.)(?:.*_)?jwt_?secret$/i,
  /(^|\.)(?:.*_)?private_?key$/i,
  /(^|\.)test_otp($|\.)/i,
];

/**
 * Checks if a given configuration dot-path points to a sensitive secret.
 */
export function isSensitivePath(dotPath: string): boolean {
  return SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(dotPath));
}

/**
 * Checks if an individual property key name indicates a sensitive secret.
 */
export function isSensitiveKey(key: string): boolean {
  return isSensitivePath(key);
}

/**
 * Checks if a string value is an environment variable reference (e.g. "env(SECRET)").
 */
export function isEnvVarReference(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  return /^env\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)$/.test(value.trim());
}

/**
 * Extracts the environment variable name from an "env(VAR_NAME)" string, if present.
 */
export function extractEnvVarName(value: string): string | null {
  const match = value.trim().match(/^env\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)$/);
  return match ? match[1] : null;
}

/**
 * Recursively sanitizes any JavaScript value (primitives, nested objects, arrays)
 * ensuring that sensitive keys and values are masked and never exposed in plaintext.
 */
export function deepSanitize(value: unknown, isSensitiveContext = false): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  // Preserve valid env() references
  if (typeof value === 'string' && isEnvVarReference(value)) {
    return value.trim();
  }

  // If in a sensitive context (e.g. field is a secret)
  if (isSensitiveContext) {
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (trimmed.length === 0) {
        return '[EMPTY_STRING]';
      }
      return `[REDACTED_SECRET (length: ${value.length})]`;
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
      return '[REDACTED_SECRET]';
    }
  }

  // Handle Arrays
  if (Array.isArray(value)) {
    return value.map((item) => deepSanitize(item, isSensitiveContext));
  }

  // Handle Objects
  if (typeof value === 'object') {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const keyIsSensitive = isSensitiveKey(k) || isSensitiveContext;
      sanitizedObj[k] = deepSanitize(v, keyIsSensitive);
    }
    return sanitizedObj;
  }

  return value;
}

/**
 * Safely masks a value for reporting and logging.
 *
 * Guarantees:
 * - Secret values are NEVER revealed.
 * - Environment variable references are displayed as env(VAR_NAME) without resolving them.
 * - Plaintext secrets are replaced with a redaction marker indicating length.
 * - Nested objects and arrays are recursively sanitized.
 */
export function maskSensitiveValue(value: unknown, isSensitive = false): string {
  if (value === null || value === undefined) {
    return 'null';
  }

  // If it's an env() reference, display the reference as-is (unresolved)
  if (typeof value === 'string' && isEnvVarReference(value)) {
    return value.trim();
  }

  // If marked sensitive directly
  if (isSensitive) {
    if (typeof value === 'string') {
      if (value.trim().length === 0) {
        return '[EMPTY_STRING]';
      }
      return `[REDACTED_SECRET (length: ${value.length})]`;
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
      return `[REDACTED_SECRET (type: ${typeof value})]`;
    }
    if (typeof value === 'object') {
      return JSON.stringify(deepSanitize(value, true));
    }
    return '[REDACTED_SECRET]';
  }

  // Non-sensitive primitives
  if (typeof value === 'string') {
    return `"${value}"`;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  if (Array.isArray(value)) {
    const sanitized = deepSanitize(value, false);
    return JSON.stringify(sanitized);
  }

  if (typeof value === 'object') {
    const sanitized = deepSanitize(value, false);
    return JSON.stringify(sanitized);
  }

  return String(value);
}

/**
 * Sanitizes an arbitrary text string (such as parser error messages, stack traces,
 * or code snippets) by replacing any raw assignment to a sensitive key with a redaction marker.
 */
export function sanitizeText(text: string): string {
  if (!text || typeof text !== 'string') return text;

  // Pattern matching: key = "secret_value" or key: 'secret_value'
  // Where key is a known sensitive credential name
  const sensitiveAssignRegex =
    /(\b(?:secrets?|pass|password|api_?key|access_?key|auth_?token|bearer_?token|bot_?token|encryption_?key|signing_?key|secret_?key|private_?key|service_?role_?key|jwt_?secret)\s*[:=]\s*)(["'])(?:(?!\2).)*\2/gi;

  let sanitized = text.replace(sensitiveAssignRegex, (match, prefix, quote) => {
    // Check if the matched value was an env() reference
    if (/env\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)/i.test(match)) {
      return match;
    }
    return `${prefix}${quote}[REDACTED_SECRET]${quote}`;
  });

  // Also sanitize unquoted literal assignments if present: key = value
  const unquotedAssignRegex =
    /(\b(?:secrets?|pass|password|api_?key|access_?key|auth_?token|bearer_?token|bot_?token|encryption_?key|signing_?key|secret_?key|private_?key|service_?role_?key|jwt_?secret)\s*=\s*)([^\s\r\n,"'#]+)/gi;

  sanitized = sanitized.replace(unquotedAssignRegex, (match, prefix, rawVal) => {
    if (/^env\(.*\)$/i.test(rawVal.trim())) {
      return match;
    }
    return `${prefix}[REDACTED_SECRET]`;
  });

  return sanitized;
}
