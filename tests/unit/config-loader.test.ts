import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadConfig, resolveConfigPath } from '../../src/config/loader.js';
import { parseConfigToml } from '../../src/config/parser.js';

describe('Configuration Loader & TOML Parser', () => {
  const fixturesDir = path.resolve(__dirname, '../fixtures');

  it('resolves direct file path correctly', () => {
    const directPath = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');
    const resolved = resolveConfigPath({ configPath: directPath });
    expect(resolved).toBe(directPath);
  });

  it('resolves project directory by finding nested supabase/config.toml', () => {
    const projectDir = path.join(fixturesDir, 'normal_secure');
    const resolved = resolveConfigPath({ configPath: projectDir });
    expect(resolved).toBe(path.join(projectDir, 'supabase', 'config.toml'));
  });

  it('loads and parses normal configuration successfully', () => {
    const configPath = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');
    const result = loadConfig({ configPath });

    expect(result.success).toBe(true);
    if (!result.success) return;

    expect(result.config.filePath).toBe(configPath);
    expect(result.config.parsed.project_id).toBe('test-project-normal');
    expect(result.config.explicitPaths.has('project_id')).toBe(true);
    expect(result.config.explicitPaths.has('auth.enable_refresh_token_rotation')).toBe(true);
    expect(result.config.explicitPaths.has('auth.non_existent_key')).toBe(false);
  });

  it('handles missing configuration file predictably with FILE_NOT_FOUND', () => {
    const missingPath = path.join(fixturesDir, 'non_existent_project', 'supabase', 'config.toml');
    const result = loadConfig({ configPath: missingPath });

    expect(result.success).toBe(false);
    if (result.success) return;

    expect(result.error.code).toBe('FILE_NOT_FOUND');
    expect(result.error.message).toContain('Configuration file not found');
  });

  it('handles invalid malformed TOML syntax with line and column numbers', () => {
    const invalidPath = path.join(fixturesDir, 'invalid_toml', 'supabase', 'config.toml');
    const result = loadConfig({ configPath: invalidPath });

    expect(result.success).toBe(false);
    if (result.success) return;

    expect(result.error.code).toBe('INVALID_TOML');
    expect(result.error.line).toBeDefined();
    expect(typeof result.error.line).toBe('number');
  });

  it('handles unknown configuration fields gracefully without crashing', () => {
    const unknownPath = path.join(fixturesDir, 'unknown_fields', 'supabase', 'config.toml');
    const result = loadConfig({ configPath: unknownPath });

    expect(result.success).toBe(true);
    if (!result.success) return;

    expect(result.config.parsed.custom_random_flag).toBe(true);
    expect(result.config.explicitPaths.has('custom_random_flag')).toBe(true);
    expect(result.config.explicitPaths.has('database_unknown_section.magic_setting')).toBe(true);
  });

  it('never modifies the target configuration file (read-only)', () => {
    const configPath = path.join(fixturesDir, 'normal_secure', 'supabase', 'config.toml');
    const contentBefore = fs.readFileSync(configPath, 'utf-8');
    const statBefore = fs.statSync(configPath);

    const result = loadConfig({ configPath });
    expect(result.success).toBe(true);

    const contentAfter = fs.readFileSync(configPath, 'utf-8');
    const statAfter = fs.statSync(configPath);

    expect(contentAfter).toBe(contentBefore);
    expect(statAfter.mtimeMs).toBe(statBefore.mtimeMs);
  });

  it('collects explicit paths accurately distinguishing configured from unconfigured', () => {
    const toml = `
      [auth]
      enabled = true
      [auth.email]
      enable_signup = false
    `;

    const parsed = parseConfigToml(toml);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;

    expect(parsed.explicitPaths.has('auth.enabled')).toBe(true);
    expect(parsed.explicitPaths.has('auth.email.enable_signup')).toBe(true);
    expect(parsed.explicitPaths.has('auth.enable_refresh_token_rotation')).toBe(false);
    expect(parsed.explicitPaths.has('auth.jwt_expiry')).toBe(false);
  });
});
