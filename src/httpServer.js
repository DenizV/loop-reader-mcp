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

// ── Application Insights (best-effort; never blocks startup) ───────────────
if (process.env.APPLICATIONINSIGHTS_CONNECTION_STRING) {
  try {
    const appInsights = (await import("applicationinsights")).default;
    appInsights.setup().start();
    process.stderr.write("Application Insights SDK initialized\n");
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

async function validateBearer(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    audience: AUDIENCES,
    issuer: ISSUERS,
  });
  return payload; // throws if invalid/expired
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
      scopes_supported: [`api://${CLIENT_ID}/access_as_user`],
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

  try {
    await validateBearer(bearer);
  } catch (err) {
    process.stderr.write(`Token validation failed: ${err.message}\n`);
    challenge(res);
    return;
  }

  // Valid token → pin to request context and dispatch to MCP.
  await runWithUser(bearer, async () => {
    const server = new McpServer({ name: "loop-reader-mcp", version: "1.0.0" });
    registerTools(server);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res);
  });
}).listen(PORT, () => {
  process.stderr.write(`loop-reader-mcp (v1.0, HTTP) listening on :${PORT}\n`);
});
