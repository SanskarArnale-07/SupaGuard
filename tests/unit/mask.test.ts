import { describe, expect, it } from 'vitest';
import {
  deepSanitize,
  extractEnvVarName,
  isEnvVarReference,
  isSensitiveKey,
  isSensitivePath,
  maskSensitiveValue,
  sanitizeText,
} from '../../src/reporter/mask.js';

describe('Masking and Sanitization Utilities', () => {
  it('identifies environment variable references accurately', () => {
    expect(isEnvVarReference('env(MY_SECRET)')).toBe(true);
    expect(isEnvVarReference('  env(DATABASE_URL)  ')).toBe(true);
    expect(isEnvVarReference('env(FOO_BAR_123)')).toBe(true);
    expect(isEnvVarReference('my-plaintext-secret')).toBe(false);
    expect(isEnvVarReference('')).toBe(false);
    expect(isEnvVarReference(12345)).toBe(false);
    expect(isEnvVarReference(null)).toBe(false);
  });

  it('extracts environment variable names correctly', () => {
    expect(extractEnvVarName('env(GITHUB_SECRET)')).toBe('GITHUB_SECRET');
    expect(extractEnvVarName('  env(SUPABASE_AUTH_KEY) ')).toBe('SUPABASE_AUTH_KEY');
    expect(extractEnvVarName('not_an_env_call')).toBeNull();
  });

  it('detects standard and unusual sensitive configuration paths', () => {
    // Standard paths
    expect(isSensitivePath('auth.external.github.secret')).toBe(true);
    expect(isSensitivePath('studio.openai_api_key')).toBe(true);
    expect(isSensitivePath('auth.email.smtp.pass')).toBe(true);
    expect(isSensitivePath('auth.sms.twilio.auth_token')).toBe(true);
    expect(isSensitivePath('experimental.s3_secret_key')).toBe(true);
    expect(isSensitivePath('experimental.s3_access_key')).toBe(true);
    expect(isSensitivePath('auth.sms.test_otp')).toBe(true);

    // Unusual / alternative names & plural forms
    expect(isSensitivePath('auth.hook.my_hook.secrets')).toBe(true);
    expect(isSensitivePath('custom.third_party.apiKey')).toBe(true);
    expect(isSensitivePath('custom.third_party.api_key')).toBe(true);
    expect(isSensitivePath('custom.service.authToken')).toBe(true);
    expect(isSensitivePath('custom.service.access_key')).toBe(true);
    expect(isSensitivePath('custom.keys.private_key')).toBe(true);
    expect(isSensitivePath('custom.keys.privateKey')).toBe(true);
    expect(isSensitivePath('custom.auth.password')).toBe(true);
    expect(isSensitivePath('auth.bearer_token')).toBe(true);
    expect(isSensitivePath('custom.slack.bot_token')).toBe(true);
    expect(isSensitivePath('vault.encryption_key')).toBe(true);
    expect(isSensitivePath('jwt.signing_key')).toBe(true);

    // Non-sensitive paths
    expect(isSensitivePath('auth.site_url')).toBe(false);
    expect(isSensitivePath('api.schemas')).toBe(false);
    expect(isSensitivePath('auth.jwt_expiry')).toBe(false);
    expect(isSensitivePath('auth.enable_refresh_token_rotation')).toBe(false);
  });

  it('redacts plaintext secrets without revealing character content', () => {
    const rawSecret = 'ghp_very_secret_token_1234567890';
    const masked = maskSensitiveValue(rawSecret, true);

    expect(masked).toContain('[REDACTED_SECRET (length: 32)]');
    expect(masked).not.toContain('ghp_');
    expect(masked).not.toContain('1234567890');
  });

  it('preserves env() references as unmasked references without resolving', () => {
    const envRef = 'env(GITHUB_SECRET)';
    const result = maskSensitiveValue(envRef, true);
    expect(result).toBe('env(GITHUB_SECRET)');
  });

  it('handles empty strings for sensitive fields', () => {
    expect(maskSensitiveValue('', true)).toBe('[EMPTY_STRING]');
    expect(maskSensitiveValue('   ', true)).toBe('[EMPTY_STRING]');
  });

  it('formats non-sensitive primitives properly', () => {
    expect(maskSensitiveValue('public', false)).toBe('"public"');
    expect(maskSensitiveValue(3600, false)).toBe('3600');
    expect(maskSensitiveValue(true, false)).toBe('true');
    expect(maskSensitiveValue(null, false)).toBe('null');
  });

  describe('Nested Configuration Masking & Deep Sanitization', () => {
    it('recursively sanitizes nested objects containing secrets', () => {
      const nestedConfig = {
        app_name: 'Supabase App',
        database: {
          host: 'db.example.com',
          port: 5432,
          password: 'super_secret_db_password_12345',
        },
        auth: {
          external: {
            github: {
              client_id: 'client_123',
              secret: 'ghp_secret_token_to_mask',
              nested_token: {
                apiKey: 'nested_secret_api_key',
                env_token: 'env(SAFE_TOKEN)',
              },
            },
          },
        },
      };

      const sanitized = deepSanitize(nestedConfig) as any;

      expect(sanitized.app_name).toBe('Supabase App');
      expect(sanitized.database.host).toBe('db.example.com');
      expect(sanitized.database.password).toContain('[REDACTED_SECRET (length: 30)]');
      expect(sanitized.database.password).not.toContain('super_secret');

      expect(sanitized.auth.external.github.client_id).toBe('client_123');
      expect(sanitized.auth.external.github.secret).toContain('[REDACTED_SECRET (length: 24)]');
      expect(sanitized.auth.external.github.nested_token.apiKey).toContain('[REDACTED_SECRET (length: 21)]');
      expect(sanitized.auth.external.github.nested_token.env_token).toBe('env(SAFE_TOKEN)');
    });

    it('sanitizes arrays of secrets and nested structures', () => {
      const arr = [
        'normal_value',
        { secret: 'array_secret_token', public_name: 'hello' },
        'env(VALID_TOKEN)',
      ];

      const sanitized = deepSanitize(arr) as any[];
      expect(sanitized[0]).toBe('normal_value');
      expect(sanitized[1].secret).toContain('[REDACTED_SECRET');
      expect(sanitized[1].public_name).toBe('hello');
      expect(sanitized[2]).toBe('env(VALID_TOKEN)');
    });
  });

  describe('Malformed Values Masking', () => {
    it('safely handles numeric, boolean, or unusual types in secret positions', () => {
      expect(maskSensitiveValue(12345678, true)).toContain('[REDACTED_SECRET');
      expect(maskSensitiveValue(12345678, true)).not.toContain('12345678');

      expect(maskSensitiveValue(true, true)).toContain('[REDACTED_SECRET');

      const objVal = { token: 'raw_secret_value' };
      const maskedObj = maskSensitiveValue(objVal, true);
      expect(maskedObj).toContain('[REDACTED_SECRET');
      expect(maskedObj).not.toContain('raw_secret_value');
    });
  });

  describe('Text Sanitization for Error Messages & Parser Snippets', () => {
    it('redacts raw credentials in malformed TOML parser error snippets', () => {
      const parserErrorSnippet = `
Invalid TOML document: expected newline after value
3:  [auth.external.github]
4:  secret = "ghp_my_secret_token_123456" broken_syntax
             ^
      `;

      const sanitized = sanitizeText(parserErrorSnippet);
      expect(sanitized).not.toContain('ghp_my_secret_token_123456');
      expect(sanitized).toContain('secret = "[REDACTED_SECRET]" broken_syntax');
    });

    it('redacts unquoted assignments and passwords in error messages', () => {
      const errText = 'Syntax error near password = secret_password_value in line 5';
      const sanitized = sanitizeText(errText);
      expect(sanitized).not.toContain('secret_password_value');
      expect(sanitized).toContain('password = [REDACTED_SECRET]');
    });

    it('preserves env(...) references inside error text without corrupting them', () => {
      const text = 'Notice: secret = "env(MY_KEY)" followed by syntax error';
      const sanitized = sanitizeText(text);
      expect(sanitized).toContain('secret = "env(MY_KEY)"');
    });

    it('redacts tokens and cryptographic keys in error snippets', () => {
      const snippet =
        'Error near encryption_key = "raw_enc_key_123" and bot_token = "xoxb-123456" and bearer_token = "secret_bearer_token" and signing_key = "raw_signing_key"';
      const sanitized = sanitizeText(snippet);
      expect(sanitized).not.toContain('raw_enc_key_123');
      expect(sanitized).not.toContain('xoxb-123456');
      expect(sanitized).not.toContain('secret_bearer_token');
      expect(sanitized).not.toContain('raw_signing_key');
      expect(sanitized).toContain('encryption_key = "[REDACTED_SECRET]"');
      expect(sanitized).toContain('bot_token = "[REDACTED_SECRET]"');
      expect(sanitized).toContain('bearer_token = "[REDACTED_SECRET]"');
      expect(sanitized).toContain('signing_key = "[REDACTED_SECRET]"');
    });

    it('redacts unquoted assignments for sensitive keys in parser diagnostics', () => {
      const snippet = 'Diagnostic: bearer_token = secret_raw_token and signing_key = raw_signing_val';
      const sanitized = sanitizeText(snippet);
      expect(sanitized).not.toContain('secret_raw_token');
      expect(sanitized).not.toContain('raw_signing_val');
      expect(sanitized).toContain('bearer_token = [REDACTED_SECRET]');
      expect(sanitized).toContain('signing_key = [REDACTED_SECRET]');
    });
  });
});
