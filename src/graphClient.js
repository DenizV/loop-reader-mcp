/**
 * graphClient.js — read-only Graph client (native fetch, no axios)
 *
 * Hardening:
 *   - GET only, plus POST restricted to an allowlist (/search/query).
 *     There is structurally no way for a tool to write/PATCH/PUT/DELETE.
 *   - Identity per call: "user" (OBO, security-trimmed — the default) or
 *     "app" (client credentials, retrieval only).
 *   - Path validation, 30 s timeout, response size cap, sanitized errors
 *     (no headers, no tokens, no request bodies echoed back to the model).
 */

import { getAccessToken } from "./auth.js";
import { currentUser } from "./userContext.js";

const BASE = "https://graph.microsoft.com/v1.0";
const TIMEOUT_MS = 30_000;
const MAX_BYTES = Number(process.env.MAX_CONTENT_BYTES || 1_048_576);

const POST_ALLOWLIST = new Set(["/search/query"]);

function assertSafePath(path) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new Error("Graph path must be a relative path starting with '/'");
  }
  if (path.includes("..") || /^https?:/i.test(path)) {
    throw new Error("Unsafe Graph path rejected");
  }
}

async function request(method, path, { params, body, accept, as = "user" } = {}) {
  assertSafePath(path);
  if (method === "POST" && !POST_ALLOWLIST.has(path)) {
    throw new Error(`POST not permitted to ${path} (read-only server)`);
  }

  const url = new URL(BASE + path);
  for (const [k, v] of Object.entries(params || {})) {
    url.searchParams.set(k, String(v));
  }

  const assertion = currentUser()?.assertion;
  const token = await getAccessToken({ as, assertion });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: accept || "application/json",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      redirect: "follow",
      signal: controller.signal,
    });

    if (!res.ok) {
      // Sanitized error: status + Graph error code only. Never echo
      // headers, tokens, or full response bodies.
      let code = "";
      try {
        code = (await res.json())?.error?.code ?? "";
      } catch {
        /* non-JSON error body */
      }
      throw new Error(`Graph ${method} ${path} failed: HTTP ${res.status}${code ? ` (${code})` : ""}`);
    }

    const buf = Buffer.from(await res.arrayBuffer());
    const ct = res.headers.get("content-type") || "";
    // JSON responses (search results, item metadata) are always parsed in full
    // — never truncated — so a large API response can't silently become
    // "undefined" and yield zero results. The size cap applies only to page
    // CONTENT (html/raw), which is what could realistically be huge.
    if (ct.includes("application/json")) {
      return JSON.parse(buf.toString("utf8"));
    }
    if (buf.length > MAX_BYTES) {
      return { truncated: true, text: buf.subarray(0, MAX_BYTES).toString("utf8") };
    }
    return { truncated: false, text: buf.toString("utf8") };
  } finally {
    clearTimeout(timer);
  }
}

export const graph = {
  // as: "user" (OBO — security-trimmed, default) | "app" (client credentials)
  get: (path, params, accept, as) => request("GET", path, { params, accept, as }),
  search: (body) => request("POST", "/search/query", { body, as: "user" }),
};

// Drive IDs contain '!' which must survive as %21 in URLs.
// Also serves as an injection guard for IDs interpolated into paths.
export function encodeId(id, label = "id") {
  if (typeof id !== "string" || !/^[A-Za-z0-9!_.=-]{1,512}$/.test(id)) {
    throw new Error(`Invalid ${label}`);
  }
  return encodeURIComponent(id);
}
