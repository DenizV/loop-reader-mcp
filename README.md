# loop-reader-mcp

A read-only, remote **Model Context Protocol (MCP)** server that lets an AI
assistant **search and read Microsoft Loop content** through the Microsoft
Graph API — with **per-user permission trimming**, so each person only ever
sees the Loop pages they already have access to.

> Microsoft Loop has no official content API. This project reads Loop through
> the Graph *file* layer using the officially documented `?format=html`
> conversion for `.loop` / `.fluid` files, and layers on an authorization
> model that keeps every user inside their own permissions.

**Read-only by design.** There is no write path — the Graph client permits
only `GET` plus `POST /search/query`. No create/update/delete tools exist.

## Why this is interesting

Loop workspace pages live in **SharePoint Embedded (SPE)** containers, which
do **not** accept delegated (per-user) tokens for content downloads — only an
app-only identity can fetch the bytes. Naively using that app identity for
everything would flatten permissions: any connected user could read any Loop
page. This server avoids that with a two-identity design:

```
Assistant ──/.well-known discovery──▶ server → "log in with Microsoft Entra"
Assistant ──OAuth (Entra sign-in)───▶ user authenticates (must be app-assigned)
Assistant ──Bearer <user token>─────▶ server validates it (jose + Entra JWKS)
        │
        ├─ loop_search ── On-Behalf-Of ─▶ Graph Search as the USER
        │                                 (Microsoft security-trims results)
        │                                 └─ (driveId,itemId) pairs cached per user
        │
        └─ loop_get_page(driveId,itemId)
             ├─ pair in THIS user's cache?  no → refuse (no Graph call)
             └─ yes → download via APP identity (?format=html) → sanitized HTML
```

**The authorization decision is made by Microsoft's own trimming, not by this
code.** A user can only *discover* pages they may access (search runs as them),
and can only *read* a page they personally discovered. The app identity is used
only to retrieve bytes the user already proved they can see.

## Tools

| Tool | Identity | Description |
|------|----------|-------------|
| `loop_search` | user (OBO) | Full-text search across Loop, trimmed to the caller |
| `loop_list_components` | user (OBO) | The caller's OneDrive `.loop` components |
| `loop_get_page` | app (gated) | A page as sanitized HTML via `?format=html` |

## How auth works (no gateway required)

The server is its own OAuth resource server. It:

1. Publishes discovery documents (`/.well-known/oauth-protected-resource` and
   `/.well-known/oauth-authorization-server`) that point clients at Microsoft
   Entra for sign-in.
2. Validates the caller's bearer token itself — signature (Entra JWKS),
   audience (`api://<client-id>`), issuer, and expiry — using `jose`.
3. Rejects any request without a valid token (`401` + `WWW-Authenticate`).

Access stays fully controlled without any reverse-proxy auth layer:

- Entra only issues a token if the user is **assigned to the app** (gate this
  with a security group + "Assignment required").
- The server rejects anything lacking a valid token.
- Per-user OBO trimming limits what each caller can retrieve.

## Setup (overview)

You need a Microsoft 365 tenant with Loop, and rights to register an Entra app.

**1. Register an Entra application** with:
- Microsoft Graph **Application** permissions: `Files.Read.All`,
  `Sites.Read.All`, `FileStorageContainer.Selected` (admin consent).
- Microsoft Graph **Delegated** permissions: `Files.Read.All`, `Sites.Read.All`
  (for the OBO trimmed search).
- An exposed API scope `access_as_user`.
- A redirect URI for your MCP client's OAuth callback.
- A client secret (dev) or certificate (production).
- **Assignment required = Yes**, with a security group of allowed users.

**2. Register the app as a guest on Loop's SharePoint Embedded container type**
(one-time, SharePoint Online Management Shell, Windows PowerShell 5.1):

```powershell
Set-SPOApplicationPermission `
  -OwningApplicationId "a187e399-0c36-4b98-8f04-1edc167a0996" `
  -GuestApplicationId "<your-client-id>" `
  -PermissionAppOnly "readcontent"
```

`a187e399-…` is Microsoft Loop's container type ID (constant across tenants).

**3. Host it** on any platform that can run a persistent Node.js HTTP process
(Node 20+), reachable over HTTPS from your MCP client. Set the environment
variables from `.env.example`. No gateway auth needed — the app validates
tokens itself.

**4. Add it to your MCP client** as a custom/remote connector: the server URL,
plus the app's OAuth client ID and secret. Each user connects individually so
their own sign-in drives the permission trimming.

## Configuration

See `.env.example`. Required: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
`AZURE_CLIENT_SECRET` (or certificate), `PUBLIC_URL`. Optional:
`VERIFY_TTL_MINUTES` (15), `MAX_CONTENT_BYTES` (1 MB), `PORT`.

## Security notes

- Discovery-gated retrieval is bound to `(driveId, itemId)` pairs and fails
  closed on missing identity/driveId.
- Sanitized errors (no tokens/headers); page HTML has scripts/handlers
  stripped; 30s request timeout; response size cap; tokens are memory-only.
- The app credential holds tenant-wide read (`Files.Read.All`) — protect it
  (secrets manager, rotation, prefer a certificate) and consider IP-allowlisting
  the server to your MCP client's egress ranges.
- Permission-revocation lag is bounded by `VERIFY_TTL_MINUTES`.
- Treat Loop page text as untrusted input to the model (prompt-injection
  surface). This is inherent to reading documents.
- This is community code, not a certified product. Review it and run a
  dependency scan (`npm audit`) before production use.

## Status & caveats

Built against Microsoft Graph and MCP as of mid-2026. The `?format=html`
conversion and SPE guest-registration mechanism are documented but the overall
"Loop via the file layer" approach is not an official Loop API — behavior may
change. Contributions and issues welcome.

## License

MIT — see [LICENSE](LICENSE).
