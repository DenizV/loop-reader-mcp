/**
 * loopTools.js — read-only tool implementations (v0.7.1)
 *
 * Authorization model (per call):
 *   1. loop_search / loop_list run with the CALLER'S delegated token (OBO) —
 *      Microsoft security-trims results to what that user can access. Each hit
 *      becomes a short-lived, SIGNED capability handle bound to this principal.
 *   2. loop_get_page verifies the handle (signature + expiry + principal) and
 *      then retrieves with the app identity (the only identity SPE accepts for
 *      content) via the documented ?format=html conversion. The model reads by
 *      handle only — it never handles raw drive/item IDs.
 *   3. Every boundary crossing is audit-logged (search, list, read.allow,
 *      read.deny).
 *
 * Config:
 *   STRICT_REVOCATION=true   on read, re-verify with the caller's delegated
 *                            token before serving (high-sensitivity; fails
 *                            closed — validate behavior in your tenant first).
 *
 * Deliberately NOT implemented: create/update/delete. No supported Loop write
 * API exists; writing plain text over .loop files corrupts them.
 */

import { graph, encodeId } from "./graphClient.js";
import { mintHandles, resolveHandle, currentClaims } from "./userContext.js";
import { audit, principalInfo } from "./audit.js";

const STRICT_REVOCATION = process.env.STRICT_REVOCATION === "true"; // default off

// True only for actual Loop files. This is the authoritative scope gate: a
// handle (and therefore an app-identity read) is minted ONLY for items whose
// filename ends in .loop/.fluid. It makes KQL query manipulation moot — even
// if a crafted query broadened the search, non-Loop hits are dropped here.
const isLoopFile = (name) => /\.(loop|fluid)$/i.test(name || "");

// Neutralize KQL grouping/operator break-outs in user-supplied query text so a
// crafted query cannot escape the filetype-scoping clause. Server-constructed
// query fragments are never passed through this.
function sanitizeQuery(q) {
  if (typeof q !== "string") return "";
  return q.replace(/[()"']/g, " ").replace(/\s+/g, " ").trim().slice(0, 400);
}

// ── 1. SEARCH (user identity, security-trimmed) ───────────────────────────
export async function searchLoopContent({ query, top = 10 }) {
  const q = sanitizeQuery(query);
  const req = {
    entityTypes: ["driveItem"],
    query: { queryString: `(${q || "*"}) AND (filetype:loop OR filetype:fluid)` },
    fields: ["id", "name", "webUrl", "lastModifiedDateTime", "parentReference", "eTag"],
    from: 0,
    size: Math.min(top, 25),
  };

  const data = await graph.search({ requests: [req] });
  const hits = data?.value?.[0]?.hitsContainers?.[0]?.hits || [];

  const items = hits
    .filter((h) => h.resource?.id && h.resource?.parentReference?.driveId && isLoopFile(h.resource?.name))
    .map((h) => ({
      name: stripExt(h.resource.name),
      driveId: h.resource.parentReference?.driveId,
      itemId: h.resource.id,
      eTag: h.resource.eTag ?? null,
      url: h.resource.webUrl,
      lastModified: h.resource.lastModifiedDateTime,
      summary: h.summary || "",
    }));

  const p = principalInfo(currentClaims());
  audit("search", { ...p, count: items.length, itemIds: items.map((i) => i.itemId) });

  const withRefs = mintHandles(items);
  return {
    results: withRefs.map((r) => ({
      name: r.name,
      ref: r.ref,
      url: r.url,
      lastModified: r.lastModified,
      summary: r.summary,
    })),
    count: withRefs.length,
    note: "To read a result, call loop_get_page with its `ref`.",
  };
}

// Shared: up to two pages of the user's security-trimmed Loop search.
// Returns the raw resource objects (already permission-trimmed by Microsoft).
async function broadLoopSearch(query = "") {
  const base = "(filetype:loop OR filetype:fluid)";
  const qs = query && query.trim() ? `(${query}) AND ${base}` : base;
  let hits = [];
  for (let page = 0; page < 2; page++) {
    const req = {
      entityTypes: ["driveItem"],
      query: { queryString: qs },
      fields: ["id", "name", "webUrl", "lastModifiedDateTime", "parentReference", "eTag"],
      from: page * 25,
      size: 25,
    };
    const data = await graph.search({ requests: [req] });
    const h = data?.value?.[0]?.hitsContainers?.[0]?.hits || [];
    hits = hits.concat(h);
    if (h.length < 25) break;
  }
  // Authoritative scope gate: only real Loop files become readable, regardless
  // of any query manipulation.
  return hits
    .map((h) => h.resource || {})
    .filter((r) => r.id && r.parentReference?.driveId && isLoopFile(r.name));
}

function toItem(r) {
  return {
    name: stripExt(r.name),
    driveId: r.parentReference?.driveId,
    itemId: r.id,
    eTag: r.eTag ?? null,
    url: r.webUrl,
    lastModified: r.lastModifiedDateTime,
    parentPath: r.parentReference?.path || null,
  };
}

// ── 1a. RECENT PAGES (most recently modified Loop pages you can access) ────
// Semantics note: this is "recently modified", derived from your trimmed
// search, not "recently viewed" (Loop's Recent) — the view-based Graph
// endpoints don't reliably return the IDs needed to read the page.
export async function listRecentLoop({ top = 20 } = {}) {
  const resources = await broadLoopSearch("");
  const items = resources
    .map(toItem)
    .filter((i) => i.lastModified)
    .sort((a, b) => new Date(b.lastModified) - new Date(a.lastModified))
    .slice(0, Math.min(top, 25));

  const p = principalInfo(currentClaims());
  audit("list_recent", { ...p, count: items.length });

  const withRefs = mintHandles(items);
  return {
    pages: withRefs.map((x) => ({ name: x.name, ref: x.ref, url: x.url, lastModified: x.lastModified })),
    count: withRefs.length,
    note: "Most recently modified Loop pages you can access. Use a page's `ref` with loop_get_page to read it.",
  };
}

// ── 1c. MEETING NOTES (best-effort heuristic) ─────────────────────────────
// Loop meeting notes are ordinary Loop pages with no distinct Graph type.
// This favors pages that look meeting-related by name or folder path. It is a
// heuristic — expect some misses and occasional false positives.
export async function findMeetingNotes({ query = "" } = {}) {
  const meetingTerms = "(meeting OR meetings OR \"meeting notes\" OR riunione OR riunioni OR agenda OR minutes)";
  const userQ = sanitizeQuery(query);
  const q = userQ ? `${userQ} AND ${meetingTerms}` : meetingTerms;
  const resources = await broadLoopSearch(q);

  const pathHint = /meeting|riunion|agenda|minutes|notes/i;
  const items = resources
    .map(toItem)
    .map((i) => ({ ...i, score: pathHint.test(i.parentPath || "") ? 2 : 1 }))
    .sort((a, b) => b.score - a.score || new Date(b.lastModified || 0) - new Date(a.lastModified || 0))
    .slice(0, 25);

  const p = principalInfo(currentClaims());
  audit("find_meeting_notes", { ...p, count: items.length });

  const withRefs = mintHandles(items);
  return {
    pages: withRefs.map((x) => ({ name: x.name, ref: x.ref, url: x.url, lastModified: x.lastModified })),
    count: withRefs.length,
    note: "Best-effort heuristic (name/path based) — Loop meeting notes are not a distinct type, so this may miss some or include unrelated pages. Use a page's `ref` with loop_get_page to read it.",
  };
}

// ── 1b. LIST WORKSPACES (grouped from the user's trimmed discovery) ───────
// There is no delegated Graph API to list a user's Loop workspaces, and the
// app-only container-enumeration API is NOT permission-trimmed (it would list
// workspaces the user cannot access — a permission-flattening leak). So this
// derives a best-effort workspace list from the user's OWN security-trimmed
// search results, grouped by container/drive. It can only surface workspaces
// the user can already see, and only those with at least one discoverable page.
export async function listLoopWorkspaces({ query = "" } = {}) {
  const resources = await broadLoopSearch(sanitizeQuery(query));

  // Group by container/drive.
  const groups = new Map();
  for (const r of resources) {
    const driveId = r.parentReference?.driveId;
    if (!driveId) continue;
    if (!groups.has(driveId)) groups.set(driveId, []);
    groups.get(driveId).push(r);
  }

  const p = principalInfo(currentClaims());
  audit("list_workspaces", { ...p, workspaceCount: groups.size, pageCount: resources.length });

  // Look up friendly workspace names in parallel (as the user; fail-soft).
  const driveIds = [...groups.keys()];
  const driveInfo = await Promise.all(
    driveIds.map(async (driveId) => {
      try {
        const d = encodeId(driveId, "driveId");
        const drive = await graph.get(`/drives/${d}`, { $select: "id,name,webUrl" }, undefined, "user");
        return { driveId, name: drive.name || null, url: drive.webUrl || null };
      } catch {
        return { driveId, name: null, url: null };
      }
    })
  );
  const infoByDrive = new Map(driveInfo.map((x) => [x.driveId, x]));

  const workspaces = [];
  for (const [driveId, items] of groups) {
    const { name, url } = infoByDrive.get(driveId) || { name: null, url: null };

    // Mint read handles for the pages found in this workspace.
    const withRefs = mintHandles(
      items.map((r) => ({
        name: stripExt(r.name),
        driveId,
        itemId: r.id,
        eTag: r.eTag ?? null,
        url: r.webUrl,
        lastModified: r.lastModifiedDateTime,
      }))
    );

    // Last activity = most recent page modification in this workspace.
    const lastActivity = items
      .map((r) => r.lastModifiedDateTime)
      .filter(Boolean)
      .sort()
      .slice(-1)[0] || null;

    workspaces.push({
      workspace: name || `(unnamed container ${String(driveId).slice(0, 8)}…)`,
      driveId,
      url,
      lastActivity,
      pageCount: items.length,
      pages: withRefs.map((x) => ({ name: x.name, ref: x.ref })),
    });
  }

  // Most recently active workspaces first (covers "recent workspaces").
  workspaces.sort((a, b) => String(b.lastActivity || "").localeCompare(String(a.lastActivity || "")));

  return {
    workspaces,
    count: workspaces.length,
    note:
      "Workspaces are grouped from Loop pages you can access via search, so a " +
      "workspace with no search-indexed pages may not appear. Use a page's `ref` " +
      "with loop_get_page to read it.",
  };
}

// ── 2. LIST ONEDRIVE LOOP COMPONENTS (user identity) ─────────────────────
export async function listOneDriveLoopComponents() {
  const data = await graph.get(`/me/drive/root/search(q='.loop')`, {
    $select: "id,name,webUrl,lastModifiedDateTime,size,parentReference,eTag",
    $top: 100,
  }, undefined, "user");

  const files = (data.value || []).filter((f) => /\.(loop|fluid)$/i.test(f.name || ""));
  const items = files.map((f) => ({
    name: stripExt(f.name),
    driveId: f.parentReference?.driveId,
    itemId: f.id,
    eTag: f.eTag ?? null,
    url: f.webUrl,
    lastModified: f.lastModifiedDateTime,
    sizeBytes: f.size,
  }));

  const p = principalInfo(currentClaims());
  audit("list", { ...p, count: items.length, itemIds: items.map((i) => i.itemId) });

  const withRefs = mintHandles(items);
  return {
    pages: withRefs.map((r) => ({
      name: r.name,
      ref: r.ref,
      url: r.url,
      lastModified: r.lastModified,
      sizeBytes: r.sizeBytes,
    })),
    count: withRefs.length,
    note: "To read a page, call loop_get_page with its `ref`.",
  };
}

// ── 3. GET PAGE CONTENT (handle-gated; app identity for retrieval) ────────
export async function getLoopPageContent({ ref } = {}) {
  const p = principalInfo(currentClaims());

  const entry = ref ? resolveHandle(ref) : null;
  if (!entry) {
    audit("read.deny", { ...p, reason: ref ? "invalid_or_expired_handle" : "missing_handle" });
    throw new Error(
      "Access not verified: call loop_search (or loop_list_components) first, then " +
        "pass the `ref` from a result to loop_get_page. Handles are per-user and " +
        "expire after a short window."
    );
  }
  const { driveId, itemId, eTag, name, url, lastModified } = entry;

  if (STRICT_REVOCATION && !(await reverifyWithUser(driveId, itemId))) {
    audit("read.deny", { ...p, driveId, itemId, reason: "revocation_recheck_failed" });
    throw new Error("Access re-check failed: your access to this item could not be reconfirmed.");
  }

  const d = encodeId(driveId, "driveId");
  const i = encodeId(itemId, "itemId");

  // Single app-identity round-trip: the content itself. Display fields
  // (name/url/lastModified) travel inside the signed handle, so no separate
  // metadata GET is needed. Authorization already happened via the handle.
  let content, format;
  try {
    const res = await graph.get(`/drives/${d}/items/${i}/content`, { format: "html" }, "text/html", "app");
    content = sanitizeHtml(res.text);
    format = res.truncated ? "html (truncated)" : "html";
  } catch {
    const raw = await graph.get(`/drives/${d}/items/${i}/content`, {}, "*/*", "app");
    content = extractReadableText(raw.text);
    format = "raw-text-extraction (lossy fallback — HTML conversion failed)";
  }

  audit("read.allow", { ...p, driveId, itemId, eTag, format });

  return {
    id: itemId,
    name: stripExt(name),
    url,
    lastModified,
    version: eTag,
    format,
    content,
  };
}

// Best-effort re-verification with the caller's delegated identity. SPE may
// reject delegated reads; in that case this returns false (fail-closed). Only
// enable STRICT_REVOCATION after validating this behavior in your tenant.
async function reverifyWithUser(driveId, itemId) {
  try {
    const d = encodeId(driveId, "driveId");
    const i = encodeId(itemId, "itemId");
    await graph.get(`/drives/${d}/items/${i}`, { $select: "id" }, undefined, "user");
    return true;
  } catch {
    return false;
  }
}

// ── helpers ───────────────────────────────────────────────────────────────
function stripExt(name) {
  return typeof name === "string" ? name.replace(/\.(loop|fluid)$/i, "") : name;
}

function sanitizeHtml(html) {
  if (typeof html !== "string") return "";
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/\son\w+\s*=\s*(["']).*?\1/gi, "")
    .replace(/javascript:/gi, "");
}

function extractReadableText(raw) {
  if (typeof raw !== "string") return String(raw);
  const segments = raw.match(/[\x20-\x7E -￿]{4,}/g) || [];
  return segments.join(" ").trim() || "[Binary content — not readable without HTML conversion]";
}
