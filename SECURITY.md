# Security model & notes

This document describes how `loop-reader-mcp` keeps each user inside their own
Microsoft Loop permissions, and the residual risks to manage before production.

## The core guarantee

A connected user can only search and read Loop content **they already have
access to**. This is enforced by Microsoft, not by this code:

- `loop_search` runs as the signed-in user via the **On-Behalf-Of** flow, so
  Microsoft Graph **security-trims** the results to that user's permissions.
- `loop_get_page` will only return an item that appeared in **that same user's**
  trimmed search results (a per-user, TTL-bounded cache keyed on the
  `(driveId, itemId)` pair). It refuses anything else *before* any Graph call.
- Content bytes are then fetched with an app-only identity because SharePoint
  Embedded requires it — but only for items the user already, provably,
  discovered.

## Authentication

The server is its own OAuth 2.0 resource server (no gateway required):

- Publishes RFC 9728 / RFC 8414 discovery documents pointing clients at
  Microsoft Entra.
- Validates each bearer token with `jose` against the Entra JWKS: signature,
  audience (`api://<client-id>`), issuer (v1 and v2), and expiry.
- Returns `401` with a `WWW-Authenticate` challenge when no valid token is
  present.

Entra only issues a token to users **assigned to the app** (enable
"Assignment required" and assign a security group), so unassigned users cannot
obtain a token at all.

## Read-only by construction

The Graph client permits only `GET` and `POST /search/query`. No write tools
are registered. There is no code path that can create, modify, or delete Loop
content.

## Hardening built in

- Discovery-gated retrieval bound to `(driveId, itemId)`; fails closed on
  missing identity or driveId.
- Errors are sanitized — no tokens, headers, or raw bodies are returned.
- Page HTML has `<script>`/`<style>`/event handlers stripped before it reaches
  the model.
- 30-second request timeout and a response size cap.
- Tokens are held in memory only; nothing is written to disk.

## Residual risks to manage

- **App credential scope.** The application permission `Files.Read.All` is
  tenant-wide read. Protect the credential: use a certificate, store it in a
  secrets manager, rotate it, and consider IP-allowlisting the server to your
  MCP client's egress ranges.
- **Revocation lag.** If a user loses access to a page, a read may still
  succeed for up to `VERIFY_TTL_MINUTES` (default 15). Lower it if needed.
- **Prompt injection.** Loop page text flows into the model. Script tags are
  stripped, but instructions embedded in prose are inherent to reading
  documents. Treat page content as untrusted.
- **In-memory cache.** On multi-instance hosting a user may need to re-search
  before reading (fails closed — safe). Use a shared cache for scale.
- **Unofficial mechanism.** The `?format=html` conversion and SPE guest
  registration are documented, but "Loop via the file layer" is not an official
  Loop API; re-test after Microsoft service changes.

## Before production

1. Independent code review / penetration test of the token-validation path.
2. `npm audit` on the lockfile; track and update dependencies.
3. Add an explicit scope check (`scp` contains `access_as_user`) for
   defense-in-depth.
4. Confirm audit logging captures caller identity + item IDs.

## Reporting

Found a vulnerability? Please open a private security advisory on the
repository rather than a public issue.
