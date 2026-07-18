/**
 * httpServer.js — HTTP entry point (the only supported deployment)
 *
 * v0.6 — the app is the OAuth resource server. It does NOT rely on Azure
 * Easy Auth (which intercepts the MCP/OAuth handshake). Instead it:
 *   1. Serves OAuth discovery documents that point Claude at Microsoft Entra.
 *   2. Validates the caller's bearer token itself (signature via Entra JWKS,
 *      audience, issuer, expiry) using `jose`.
 *   3. Pins the validated token to the request; tools exchange it via OBO.
 *
 * Deploy with Easy Auth DISABLED (or AllowAnonymous). Access control is still
 * enforced end to end:
 *   - Entra only issues a token if the user is assigned to the app
 *     (Enterprise app → Assignment required → security group).
 *   - This server rejects any request without a valid token (401).
 *   - Per-user OBO trimming limits what each caller can see.
 */

import { createServer } from "http";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { runWithUser } from "./userContext.js";
import { registerTools } from "./tools.js";
import { audit } from "./audit.js";
import { getAppToken } from "./auth.js";

// ── Application Insights (best-effort; never blocks startup) ───────────────
// Lean config: keep request + dependency + exception tracking (dependency
// timing shows exactly how long each Graph call takes — useful for the read-
// latency question) but drop the heavier collectors so it costs less per
// request on a small plan. Console auto-collection is off because our audit
// lines already go to stdout → Log Analytics.
if (process.env.APPLICATIONINSIGHTS_CONNECTION_STRING) {
  try {
    const appInsights = (await import("applicationinsights")).default;
    appInsights
      .setup()
      .setAutoCollectConsole(false)
      .setAutoCollectPerformance(false, false)
      .setSendLiveMetrics(false)
      .start();
    // Redact Loop drive/item identifiers from dependency + request telemetry so
    // they don't leave the controlled audit sink. Keeps timing/latency data.
    const redact = (s) =>
      typeof s === "string"
        ? s
            .replace(/\/drives\/[^/]+/gi, "/drives/{driveId}")
            .replace(/\/items\/[^/?]+/gi, "/items/{itemId}")
        : s;
    appInsights.defaultClient?.addTelemetryProcessor((envelope) => {
      const d = envelope?.data?.baseData;
      if (d) {
        if (d.name) d.name = redact(d.name);
        if (d.data) d.data = redact(d.data);
        if (d.target) d.target = redact(d.target);
        if (d.url) d.url = redact(d.url);
      }
      return true;
    });
    process.stderr.write("Application Insights SDK initialized (lean config, IDs redacted)\n");
  } catch (err) {
    process.stderr.write(`Application Insights init failed (continuing): ${err.message}\n`);
  }
}

const PORT = Number(process.env.PORT || 3000);
const TENANT = process.env.AZURE_TENANT_ID;
const CLIENT_ID = process.env.AZURE_CLIENT_ID;
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const ENTRA = `https://login.microsoftonline.com/${TENANT}`;

// ── Token validation (Entra-signed JWTs) ──────────────────────────────────
const JWKS = createRemoteJWKSet(new URL(`${ENTRA}/discovery/v2.0/keys`));
// Accept the API's Application ID URI and the bare client ID as audience,
// and both Entra v2.0 and v1.0 issuer formats.
const AUDIENCES = [`api://${CLIENT_ID}`, CLIENT_ID];
const ISSUERS = [
  `https://login.microsoftonline.com/${TENANT}/v2.0`,
  `https://sts.windows.net/${TENANT}/`,
];

// Optional explicit scope enforcement (defense-in-depth). The OBO exchange
// would fail for a wrong-audience token anyway, but checking scp here rejects
// it earlier and makes intent explicit. Set REQUIRE_SCOPE=false to disable.
const REQUIRE_SCOPE = process.env.REQUIRE_SCOPE !== "false";
const REQUIRED_SCOPE = "access_as_user";

async function validateBearer(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    audience: AUDIENCES,
    issuer: ISSUERS,
    clockTolerance: 60, // seconds — tolerate small clock skew, avoid premature 401s
  });
  // Always require a delegated access token: ID tokens carry aud=client_id but
  // no `scp` claim. Rejecting tokens without `scp` blocks ID-token replay
  // regardless of REQUIRE_SCOPE (defense against the bare client_id audience).
  const scopes = String(payload.scp || "").split(" ").filter(Boolean);
  if (scopes.length === 0) {
    throw new Error("not a delegated access token (no scp claim)");
  }
  if (REQUIRE_SCOPE && !scopes.includes(REQUIRED_SCOPE)) {
    throw new Error(`token missing required scope ${REQUIRED_SCOPE}`);
  }
  return payload; // throws if invalid/expired/insufficient scope
}

// ── Helpers ────────────────────────────────────────────────────────────────
function sendJson(res, obj, status = 200) {
  res.writeHead(status, {
    "content-type": "application/json",
    "access-control-allow-origin": "*",
  });
  res.end(JSON.stringify(obj));
}

function challenge(res) {
  res.writeHead(401, {
    "content-type": "application/json",
    "access-control-allow-origin": "*",
    "WWW-Authenticate": `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource"`,
  });
  res.end(JSON.stringify({ error: "unauthorized" }));
}

createServer(async (req, res) => {
  const path = (req.url || "").split("?")[0];

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "authorization,content-type,mcp-session-id",
    });
    res.end();
    return;
  }

  // ── OAuth discovery (anonymous) ──────────────────────────────────────────
  if (path === "/.well-known/oauth-protected-resource") {
    sendJson(res, {
      resource: PUBLIC_URL,
      authorization_servers: [PUBLIC_URL],
      bearer_methods_supported: ["header"],
      // Advertise offline_access so the client requests a refresh token and can
      // silently renew — avoids the "reconnect every few hours" prompt when the
      // short-lived access token expires.
      scopes_supported: [`api://${CLIENT_ID}/access_as_user`, "offline_access"],
    });
    return;
  }
  if (
    path === "/.well-known/oauth-authorization-server" ||
    path === "/.well-known/openid-configuration"
  ) {
    sendJson(res, {
      issuer: PUBLIC_URL,
      authorization_endpoint: `${ENTRA}/oauth2/v2.0/authorize`,
      token_endpoint: `${ENTRA}/oauth2/v2.0/token`,
      jwks_uri: `${ENTRA}/discovery/v2.0/keys`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      scopes_supported: [`api://${CLIENT_ID}/access_as_user`, "openid", "offline_access", "profile"],
    });
    return;
  }

  // Lightweight health check (anonymous)
  if (path === "/healthz") {
    sendJson(res, { ok: true });
    return;
  }

  // ── Everything else requires a valid token ───────────────────────────────
  const easyAuthToken = req.headers["x-ms-token-aad-access-token"]; // if Easy Auth ever on
  const authHeader = req.headers["authorization"] || "";
  const bearer =
    (typeof easyAuthToken === "string" && easyAuthToken) ||
    (authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null);

  if (!bearer) {
    challenge(res);
    return;
  }

  let claims;
  try {
    claims = await validateBearer(bearer);
  } catch (err) {
    process.stderr.write(`Token validation failed: ${err.message}\n`);
    audit("auth.deny", { reason: err.message });
    challenge(res);
    return;
  }

  // Valid token → pin token + claims to request context and dispatch to MCP.
  await runWithUser(bearer, claims, async () => {
    const server = new McpServer({ name: "loop-reader-mcp", version: "1.1.0" });
    registerTools(server);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res);
  });
}).listen(PORT, () => {
  process.stderr.write(`loop-reader-mcp (v1.1, HTTP) listening on :${PORT}\n`);
  // Pre-warm the app-only (retrieval) token so the first page read doesn't pay
  // the client-credentials round-trip. Best-effort; ignore failures at boot.
  getAppToken().catch(() => {});
});
