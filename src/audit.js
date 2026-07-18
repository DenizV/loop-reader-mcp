/**
 * audit.js — structured audit logging at the authorization boundary.
 *
 * Emits one JSON line per security-relevant event to stdout, which App Service
 * / container logs forward to Log Analytics (or any log sink). This turns
 * "who accessed which Loop item, and were they entitled" into a queryable
 * record — the clean audit point that the discovery-gated design enables.
 *
 * NEVER logs tokens, secrets, or page content. Only principal identifiers,
 * item identifiers, and the authorization decision.
 */

export function audit(event, fields = {}) {
  const record = {
    ts: new Date().toISOString(),
    audit: event, // e.g. "search", "read.allow", "read.deny", "auth.deny"
    ...fields,
  };
  // Single-line JSON so log pipelines can parse each event independently.
  process.stdout.write(JSON.stringify(record) + "\n");
}

// Build a compact, non-sensitive principal descriptor from validated claims.
export function principalInfo(claims = {}) {
  return {
    tid: claims.tid || null, // tenant
    oid: claims.oid || claims.sub || null, // user object id
    upn: claims.preferred_username || claims.upn || null, // human-readable
    azp: claims.azp || claims.appid || null, // calling client app
  };
}
