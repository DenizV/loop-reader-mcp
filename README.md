# loop-reader-mcp

A read-only, remote **Model Context Protocol (MCP)** server that lets an AI
assistant **search and read Microsoft Loop content** through the Microsoft
Graph API — with **per-user permission trimming**, so each person only ever
sees the Loop pages they already have access to.

> Microsoft Loop has no official content API. This project reads Loop through
> the Graph *file* layer using the documented `?format=html` conversion for
> `.loop` / `.fluid` files, and layers on an authorization model that keeps
> every user strictly inside their own permissions.

**Read-only by construction.** The Graph client permits only `GET` plus
`POST /search/query`. No create/update/delete tools exist.

## Why this is interesting

Loop workspace pages live in **SharePoint Embedded (SPE)** containers, which
do **not** accept delegated (per-user) tokens for content downloads — only an
app-only identity can fetch the bytes. Naively using that app identity for
everything would flatten permissions: any connected user could read any Loop
page. This server avoids that with a two-identity, capability-based design:

```
Assistant ──/.well-known discovery──▶ server → "log in with Microsoft Entra"
Assistant ──OAuth (Entra sign-in)───▶ user authenticates (must be app-assigned)
Assistant ──Bearer <user token>─────▶ server validates it (jose + Entra JWKS)
        │
        ├─ discovery tools ── On-Behalf-Of ─▶ Graph as the USER
        │                                     (Microsoft security-trims results)
        │                                     └─ each hit → signed capability handle
        │
        └─ loop_get_page(ref)
             ├─ verify handle: HMAC signature + principal + expiry
             └─ fetch via APP identity (?format=html) → sanitized HTML
```

**The authorization decision is Microsoft's, not this code's.** A user can only
*discover* pages they may access (search runs as them), and can only *read* a
page via a signed handle minted for their own principal. The app identity is
used only to retrieve bytes the user already proved they can see.

## Tools (all read-only)

| Tool | Identity | Description |
|------|----------|-------------|
| `loop_search` | user (OBO) | Full-text search across Loop, trimmed to the caller |
| `loop_list_recent` | user (OBO) | The caller's most recently modified Loop pages |
| `loop_find_meeting_notes` | user (OBO) | Best-effort meeting-notes finder (name/path heuristic) |
| `loop_list_workspaces` | user (OBO) | Loop workspaces the caller can access, recency-sorted |
| `loop_list_components` | user (OBO) | `.loop` components in the caller's OneDrive |
| `loop_get_page` | app (handle-gated) | A page as sanitized HTML, read by `ref` |

## Security model

- The app is its own OAuth resource server: it validates each Entra JWT
  (signature via JWKS, audience, issuer, expiry, `scp=access_as_user`, rejects
  ID tokens) and publishes discovery docs pointing clients at Entra. No reverse-
  proxy auth needed.
- **Signed, stateless capability handles**: `loop_search` returns an opaque
  `ref` (HMAC-signed, carrying item id + principal + expiry). `loop_get_page`
  reads only by `ref` — the model never handles raw identifiers, handles can't
  be forged or replayed across users/clients, and there's no server-side state
  to lose across restarts/instances.
- **Per-user trimming** via On-Behalf-Of; app identity reachable only through a
  verified handle.
- **Injection-resistant**: user queries are sanitized and results are re-
  filtered server-side to `.loop`/`.fluid`, so a crafted query can neither
  escape the file-type scope nor exceed the user's own access.
- **Structured audit logging** of every search/read (principal + item ids,
  never tokens or content). Optional App Insights telemetry redacts item ids.
- See `SECURITY.md` for the full model and residual risks.

## Setup (overview)

Requires a Microsoft 365 tenant with Loop and rights to register an Entra app.

1. **Register an Entra application** with Microsoft Graph **Application**
   permissions (`Files.Read.All`, `Sites.Read.All`, `FileStorageContainer.Selected`)
   and **Delegated** (`Files.Read.All`, `Sites.Read.All`) for OBO; expose an
   `access_as_user` scope; add your MCP client's OAuth redirect URI; require
   user assignment via a security group.
2. **Register the app as a guest on Loop's SPE container type** (one-time,
   SharePoint Online Management Shell, Windows PowerShell):
   ```powershell
   Set-SPOApplicationPermission `
     -OwningApplicationId "a187e399-0c36-4b98-8f04-1edc167a0996" `
     -GuestApplicationId "<your-client-id>" `
     -PermissionAppOnly "readcontent"
   ```
   (`a187e399-…` is Microsoft Loop's container type ID, constant across tenants.)
3. **Host it** on any platform running a persistent Node.js 20+ HTTP process,
   reachable over HTTPS. Set the env vars from `.env.example`. Enable "always
   on" so it doesn't cold-start. If you don't use App Insights, install with
   `npm install --omit=optional` to keep the deploy small.
4. **Add it to your MCP client** as a custom/remote connector (server URL +
   OAuth client id/secret). Each user connects individually so their own
   sign-in drives the trimming.

## Configuration

See `.env.example`. Required: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
`AZURE_CLIENT_SECRET` (or certificate), `PUBLIC_URL`. Recommended:
`HANDLE_SIGNING_KEY`. Optional: `VERIFY_TTL_MINUTES` (15), `REQUIRE_SCOPE`
(true), `STRICT_REVOCATION` (false), `MAX_CONTENT_BYTES`, `PORT`,
`APPLICATIONINSIGHTS_CONNECTION_STRING`.

## Status & caveats

Built against Microsoft Graph and MCP as of 2026. The `?format=html`
conversion and SPE guest registration are documented, but "Loop via the file
layer" is not an official Loop API — behavior may change. Community code, not a
certified product: review it and run `npm audit` before production. See
`CHANGELOG.md` for version history and `SECURITY.md` for the security model.

## License

MIT — see [LICENSE](LICENSE).
