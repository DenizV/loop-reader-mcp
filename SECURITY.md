# Security model & notes

How `loop-reader-mcp` keeps each user inside their own Microsoft Loop
permissions, and the residual risks to manage before production.

## The core guarantee

A connected user can only search and read Loop content **they already have
access to** — enforced by Microsoft, not by this code:

- Discovery tools run as the signed-in user via the **On-Behalf-Of** flow, so
  Microsoft Graph **security-trims** results to that user's permissions.
- `loop_get_page` accepts only a signed **capability handle** (`ref`) minted
  from that user's own discovery. It verifies the HMAC signature, that the
  handle was minted for this principal (tenant:user:client), and that it hasn't
  expired — before any content fetch.
- Content bytes are then retrieved with an app-only identity (SharePoint
  Embedded requires it) but only for an item the user already, provably,
  discovered.

## Authentication

The server is its own OAuth 2.0 resource server (no gateway required):

- Publishes RFC 9728 / RFC 8414 discovery documents pointing clients at Entra.
- Validates each bearer token with `jose`: signature (Entra JWKS), audience,
  issuer (v1 + v2), expiry, and a required `scp=access_as_user`.
- Rejects tokens without an `scp` claim (i.e. ID tokens), independent of config.
- Entra only issues a token to users **assigned to the app** (enable
  "Assignment required" + a security group), so unassigned users get nothing.

## Capability handles

- Stateless, HMAC-signed tokens carrying `{driveId, itemId, eTag, principal,
  expiry, name, url, lastModified}`. Signed (not encrypted) — the identifiers
  are non-secret SharePoint IDs; the signature prevents forgery and the
  principal binding prevents cross-user / cross-client replay.
- No server-side handle store, so handles survive restarts and work across
  multiple instances. Verified correct under concurrent multi-user load.

## Read-only & injection resistance

- Graph client permits only `GET` + `POST /search/query`; no write tools exist.
- User queries are sanitized (grouping/quote characters stripped) and results
  are re-filtered server-side to `.loop`/`.fluid`, so a crafted query can
  neither escape the file-type scope nor exceed the user's own trimmed access.
- Path/id inputs are validated and URL-encoded; errors are sanitized (no
  tokens, headers, or bodies returned).

## Logging

- Structured audit events (search/list/read/deny) log only principal
  identifiers + item ids — never tokens, secrets, or page content.
- Optional Application Insights runs in a lean config and **redacts** drive/item
  identifiers from dependency/request telemetry.

## Residual risks to manage

- **App credential scope.** `Files.Read.All` (Application) is tenant-wide read.
  Protect it: certificate over secret, secrets manager, rotation, and consider
  IP-allowlisting the server to your MCP client's egress ranges.
- **Handle signing key.** Prefer an explicit `HANDLE_SIGNING_KEY`; if it falls
  back to the client secret, rotating that secret invalidates outstanding
  handles.
- **Revocation lag.** A handle stays valid up to `VERIFY_TTL_MINUTES` (default
  15) after access is revoked. Lower it, or enable `STRICT_REVOCATION`.
- **Prompt injection.** Loop page text flows into the model; script/style/handler
  tags are stripped, but instructions embedded in prose are inherent to reading
  documents. Treat page content as untrusted.
- **Unofficial mechanism.** `?format=html` + SPE guest registration are
  documented, but "Loop via the file layer" is not an official Loop API.

## Before production

1. Independent code review / penetration test of the token-validation and
   handle paths.
2. `npm audit` on the lockfile; track and update dependencies.
3. Confirm audit logging is captured by your log sink with adequate retention.

## Reporting

Found a vulnerability? Please open a private security advisory on the
repository rather than a public issue.
