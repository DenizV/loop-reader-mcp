/**
 * loopTools.js — read-only tool implementations (hybrid mode)
 *
 * Authorization model (per call):
 *   1. loop_search runs with the CALLER'S delegated token (OBO) — Microsoft
 *      security-trims results to what that user can access, including SPE
 *      workspace pages (Search reaches SPE even though delegated downloads
 *      can't). Every returned (driveId, itemId) pair is recorded in the
 *      caller's verification cache.
 *   2. loop_get_page refuses any pair not in the caller's own cache —
 *      BEFORE any Graph call — then retrieves with the app identity (the
 *      only identity SPE accepts for content) using the officially
 *      documented ?format=html conversion for loop/fluid files.
 *
 * Deliberately NOT implemented: create/update/delete. There is no supported
 * Loop write API; writing plain text over .loop files corrupts them.
 */

import { graph, encodeId } from "./graphClient.js";
import { markVerified, isVerified } from "./userContext.js";

// ── 1. SEARCH (user identity, security-trimmed) ───────────────────────────
export async function searchLoopContent({ query, top = 10 }) {
  const req = {
    entityTypes: ["driveItem"],
    query: { queryString: `(${query}) AND (filetype:loop OR filetype:fluid)` },
    fields: ["id", "name", "webUrl", "lastModifiedDateTime", "parentReference"],
    from: 0,
    size: Math.min(top, 25),
    // no region parameter: OBO search is a delegated call
  };

  const data = await graph.search({ requests: [req] });
  const hits = data?.value?.[0]?.hitsContainers?.[0]?.hits || [];

  markVerified(
    hits.map((h) => ({
      driveId: h.resource?.parentReference?.driveId,
      itemId: h.resource?.id,
    }))
  );

  return {
    results: hits.map((h) => ({
      name: stripExt(h.resource?.name),
      itemId: h.resource?.id,
      driveId: h.resource?.parentReference?.driveId,
      url: h.resource?.webUrl,
      lastModified: h.resource?.lastModifiedDateTime,
      summary: h.summary || "",
    })),
    count: hits.length,
  };
}

// ── 2. LIST ONEDRIVE LOOP COMPONENTS (user identity) ─────────────────────
// Teams/Outlook Loop components live as .loop files in the caller's OneDrive.
export async function listOneDriveLoopComponents() {
  const data = await graph.get(`/me/drive/root/search(q='.loop')`, {
    $select: "id,name,webUrl,lastModifiedDateTime,size,parentReference",
    $top: 100,
  }, undefined, "user");

  markVerified(
    (data.value || []).map((f) => ({
      driveId: f.parentReference?.driveId,
      itemId: f.id,
    }))
  );

  const pages = (data.value || [])
    .filter((f) => /\.(loop|fluid)$/i.test(f.name || ""))
    .map((f) => ({
      itemId: f.id,
      name: stripExt(f.name),
      driveId: f.parentReference?.driveId,
      url: f.webUrl,
      lastModified: f.lastModifiedDateTime,
      sizeBytes: f.size,
    }));

  return { pages, count: pages.length };
}

// ── 3. GET PAGE CONTENT (discovery-gated; app identity for retrieval) ────
export async function getLoopPageContent({ driveId, itemId }) {
  const d = encodeId(driveId, "driveId");
  const i = encodeId(itemId, "itemId");

  if (!isVerified(driveId, itemId)) {
    throw new Error(
      "Access not verified: this driveId/itemId pair has not appeared in your own " +
        "search results recently. Call loop_search first — results are permission-" +
        "trimmed to you, and only items you can discover may be read."
    );
  }

  // Retrieval identity: app token (required for SPE containers) —
  // authorization already happened via isVerified() above.
  const meta = await graph.get(`/drives/${d}/items/${i}`, {
    $select: "id,name,webUrl,lastModifiedDateTime,lastModifiedBy,size",
  }, undefined, "app");

  let content, format;
  try {
    // Server-side Fluid → HTML conversion (officially documented for
    // loop/fluid source files in Graph v1.0).
    const res = await graph.get(`/drives/${d}/items/${i}/content`, { format: "html" }, "text/html", "app");
    content = sanitizeHtml(res.text);
    format = res.truncated ? "html (truncated)" : "html";
  } catch {
    // Fallback: raw download + best-effort text extraction
    const raw = await graph.get(`/drives/${d}/items/${i}/content`, {}, "*/*", "app");
    content = extractReadableText(raw.text);
    format = "raw-text-extraction (lossy fallback — HTML conversion failed)";
  }

  return {
    id: meta.id,
    name: stripExt(meta.name),
    url: meta.webUrl,
    lastModified: meta.lastModifiedDateTime,
    lastModifiedBy: meta.lastModifiedBy?.user?.displayName,
    format,
    content,
  };
}

// ── helpers ───────────────────────────────────────────────────────────────
function stripExt(name) {
  return typeof name === "string" ? name.replace(/\.(loop|fluid)$/i, "") : name;
}

// Defense-in-depth: page HTML is untrusted org content that flows into the
// model's context. Strip active content and event handlers.
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
