/**
 * auth.js — hybrid-mode authentication (the only supported mode)
 *
 * Two identities, one confidential client app:
 *   USER  — the caller's inbound assertion (validated by Easy Auth upstream)
 *           is exchanged via On-Behalf-Of for a delegated Graph token.
 *           Delegated Graph calls are security-trimmed to that user.
 *   APP   — client-credentials token, used ONLY to retrieve content the
 *           caller has already discovered via their own trimmed search
 *           (SharePoint Embedded rejects delegated content access).
 *
 * No device code, no disk token cache — all tokens are memory-only.
 */

import { ConfidentialClientApplication } from "@azure/msal-node";
import { createHash } from "crypto";
import dotenv from "dotenv";
dotenv.config();

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name} in environment`);
  return v;
}

let ccaInstance = null;
function getCca() {
  if (!ccaInstance) {
    ccaInstance = new ConfidentialClientApplication({
      auth: {
        clientId: requireEnv("AZURE_CLIENT_ID"),
        authority: `https://login.microsoftonline.com/${requireEnv("AZURE_TENANT_ID")}`,
        clientSecret: requireEnv("AZURE_CLIENT_SECRET"),
        // Production: prefer clientCertificate over clientSecret — load from
        // Key Vault via the Function's managed identity.
      },
    });
  }
  return ccaInstance;
}

// ── On-Behalf-Of: caller's assertion → delegated Graph token ─────────────
const oboCache = new Map(); // sha256(assertion) → { token, expiresAt }

export async function getOboToken(assertion) {
  if (!assertion) {
    throw new Error("Missing user assertion — caller identity is required for every request");
  }
  const key = createHash("sha256").update(assertion).digest("hex");
  const hit = oboCache.get(key);
  if (hit && Date.now() < hit.expiresAt - 300_000) return hit.token;

  const r = await getCca().acquireTokenOnBehalfOf({
    oboAssertion: assertion,
    scopes: [
      "https://graph.microsoft.com/Files.Read.All",
      "https://graph.microsoft.com/Sites.Read.All",
    ],
  });
  oboCache.set(key, { token: r.accessToken, expiresAt: r.expiresOn?.getTime() ?? 0 });
  if (oboCache.size > 1000) oboCache.clear(); // crude bound; fine for a sketch
  return r.accessToken;
}

// ── App-only (client credentials) — retrieval identity ───────────────────
let appCache = { token: null, expiresAt: 0 };

export async function getAppToken() {
  if (appCache.token && Date.now() < appCache.expiresAt - 300_000) {
    return appCache.token;
  }
  const r = await getCca().acquireTokenByClientCredential({
    scopes: ["https://graph.microsoft.com/.default"],
  });
  appCache = { token: r.accessToken, expiresAt: r.expiresOn?.getTime() ?? 0 };
  return r.accessToken;
}

// ── Public API ────────────────────────────────────────────────────────────
// as: "user" → OBO (security-trimmed; requires caller assertion)
//     "app"  → client credentials (retrieval only)
export async function getAccessToken({ as = "user", assertion } = {}) {
  return as === "app" ? getAppToken() : getOboToken(assertion);
}
