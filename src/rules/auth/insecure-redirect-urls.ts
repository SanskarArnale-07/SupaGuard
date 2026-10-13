import type { Finding, RuleContext, SecurityRule } from '../../types/rule.js';

function isLocalhostHost(host: string): boolean {
  return (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '0.0.0.0' ||
    host.endsWith('.localhost')
  );
}

/**
 * Patterns that represent completely open wildcards or unscoped multi-tenant hosting platforms.
 * Anyone on these platforms can claim an un-prefixed subdomain (e.g. attacker.vercel.app).
 */
const UNSCOPED_MULTI_TENANT_PATTERNS = [
  /^https?:\/\/\*\.vercel\.app(?:\/.*)?$/i,
  /^https?:\/\/\*\*\.vercel\.app(?:\/.*)?$/i,
  /^https?:\/\/\*\.netlify\.app(?:\/.*)?$/i,
  /^https?:\/\/\*\*\.netlify\.app(?:\/.*)?$/i,
  /^https?:\/\/\*\.github\.io(?:\/.*)?$/i,
  /^https?:\/\/\*\.pages\.dev(?:\/.*)?$/i,
  /^https?:\/\/\*\.firebaseapp\.com(?:\/.*)?$/i,
  /^https?:\/\/\*\.azurewebsites\.net(?:\/.*)?$/i,
  /^https?:\/\/\*\.onrender\.com(?:\/.*)?$/i,
  /^https?:\/\/\*\*\.onrender\.com(?:\/.*)?$/i,
  /^https?:\/\/\*\.up\.railway\.app(?:\/.*)?$/i,
  /^https?:\/\/\*\*\.up\.railway\.app(?:\/.*)?$/i,
  /^https?:\/\/\*\.fly\.dev(?:\/.*)?$/i,
  /^https?:\/\/\*\*\.fly\.dev(?:\/.*)?$/i,
  /^https?:\/\/\*\.amplifyapp\.com(?:\/.*)?$/i,
  /^https?:\/\/\*\*\.amplifyapp\.com(?:\/.*)?$/i,
];

function isExcessivelyPermissiveWildcard(url: string): boolean {
  const trimmed = url.trim();
  // Open wildcards: *, **, https://*, http://*, https://**
  if (trimmed === '*' || trimmed === '**') return true;
  if (/^https?:\/\/\*+\/?(\*\*?)?$/i.test(trimmed)) return true;
  // Unscoped multi-tenant root wildcards without team/project scope
  if (UNSCOPED_MULTI_TENANT_PATTERNS.some((pattern) => pattern.test(trimmed))) return true;
  return false;
}

function checkRemoteHttpUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'http:' && !isLocalhostHost(parsed.hostname)) {
      return true;
    }
  } catch {
    if (
      url.startsWith('http://') &&
      !url.includes('localhost') &&
      !url.includes('127.0.0.1')
    ) {
      return true;
    }
  }
  return false;
}

export const insecureRedirectUrlsRule: SecurityRule = {
  id: 'SEC-AUTH-004',
  title: 'Insecure or Excessively Permissive Authentication Redirect URL',
  category: 'auth',
  severity: 'high',
  description:
    'Detects open wildcard redirect URLs, unscoped multi-tenant platform wildcards, and unencrypted HTTP endpoints.',
  policyAssumption:
    'Authentication redirect allowlists should enforce exact HTTPS endpoints. While scoped wildcards are officially supported by Supabase for preview branches, completely open or unscoped wildcards risk OAuth token leakage.',
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    // 1. Inspect primary auth.site_url
    const siteUrlPath = 'auth.site_url';
    if (context.hasExplicitPath(siteUrlPath)) {
      const siteUrl = context.getExplicitValue<unknown>(siteUrlPath);
      if (typeof siteUrl === 'string') {
        const trimmed = siteUrl.trim();
        if (checkRemoteHttpUrl(trimmed)) {
          findings.push({
            ruleId: 'SEC-AUTH-004',
            ruleTitle: 'Unencrypted HTTP Site URL',
            severity: 'high',
            category: 'auth',
            path: siteUrlPath,
            observedValue: `"${trimmed}"`,
            rationale: `The primary site URL "${trimmed}" uses an unencrypted HTTP scheme for a remote destination. In Supabase Auth, site_url is the default redirect destination for password resets, email confirmations, and magic links. Transmitting authentication tokens or verification codes over cleartext HTTP exposes them to network interception.`,
            policyAssumption:
              'All remote application site URLs must enforce TLS/HTTPS encryption to protect credentials in transit.',
            remediation: `Change "auth.site_url" to use the "https://" protocol, or use localhost for local development.`,
          });
        }
      }
    }

    // 2. Inspect auth.additional_redirect_urls
    const path = 'auth.additional_redirect_urls';
    if (context.hasExplicitPath(path)) {
      const urls = context.getExplicitValue<unknown>(path);
      if (Array.isArray(urls)) {
        for (let i = 0; i < urls.length; i++) {
          const urlItem = urls[i];
          if (typeof urlItem !== 'string') continue;

          const trimmed = urlItem.trim();

          // 2a. Check for unencrypted remote HTTP (cleartext tokens in transit)
          if (checkRemoteHttpUrl(trimmed)) {
            findings.push({
              ruleId: 'SEC-AUTH-004',
              ruleTitle: 'Unencrypted HTTP Authentication Redirect URL',
              severity: 'high',
              category: 'auth',
              path: `${path}[${i}]`,
              observedValue: `"${trimmed}"`,
              rationale: `The redirect URL "${trimmed}" uses an unencrypted HTTP scheme for a remote destination. Authentication authorization codes and session tokens transmitted over cleartext HTTP can be intercepted by on-path network adversaries.`,
              policyAssumption:
                'All remote authentication redirect URLs must enforce TLS/HTTPS encryption to protect credentials in transit.',
              remediation: `Change "${trimmed}" to use the "https://" protocol.`,
            });
            continue;
          }

          // 2b. Check for open or unscoped multi-tenant wildcards (high risk open redirect)
          if (isExcessivelyPermissiveWildcard(trimmed)) {
            findings.push({
              ruleId: 'SEC-AUTH-004',
              ruleTitle: 'Excessively Permissive or Open Wildcard Authentication Redirect URL',
              severity: 'high',
              category: 'auth',
              path: `${path}[${i}]`,
              observedValue: `"${trimmed}"`,
              rationale: `The redirect URL pattern "${trimmed}" is an open or unscoped wildcard. On multi-tenant hosting platforms (e.g. *.vercel.app), anyone can register an arbitrary subdomain, allowing an attacker to harvest authorization codes and access tokens via open redirect.`,
              policyAssumption:
                'Wildcard redirect patterns must never be completely open or unscoped on shared multi-tenant hosting platforms.',
              remediation: `Scope the wildcard pattern to a dedicated organization or project prefix (e.g. "https://*-myteam.vercel.app/**") or specify exact HTTPS callback URLs.`,
            });
            continue;
          }

          // 2c. Check for scoped preview deployment wildcards (low severity advisory)
          if (trimmed.includes('*')) {
            findings.push({
              ruleId: 'SEC-AUTH-004',
              ruleTitle: 'Scoped Wildcard in Authentication Redirect URL (Preview Deployment Pattern)',
              severity: 'low',
              category: 'auth',
              path: `${path}[${i}]`,
              observedValue: `"${trimmed}"`,
              rationale: `The redirect URL pattern "${trimmed}" contains wildcards. While Supabase officially supports scoped wildcards for preview deployments (such as Vercel or Netlify branch previews), Supabase officially recommends configuring exact redirect URL paths for production environments to eliminate any risk of subdomain hijacking or redirection ambiguity.`,
              policyAssumption:
                'Scoped wildcards are acceptable for preview/staging environments, but production configurations should use exact URL paths.',
              remediation: `Verify that "${trimmed}" is restricted to non-production preview deployments. For production configurations, configure exact callback URLs without wildcards.`,
            });
          }
        }
      }
    }

    return findings;
  },
};
