/**
 * tools.js — MCP tool registration, shared by the stdio (index.js) and
 * HTTP/hybrid (httpServer.js) entry points.
 */

import { z } from "zod";
import {
  searchLoopContent,
  listLoopWorkspaces,
  listRecentLoop,
  findMeetingNotes,
  listOneDriveLoopComponents,
  getLoopPageContent,
} from "./loopTools.js";

function tool(fn) {
  return async (args) => {
    try {
      const result = await fn(args);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      // err.message is already sanitized by graphClient (no tokens/headers)
      return {
        content: [{ type: "text", text: JSON.stringify({ error: err.message }) }],
        isError: true,
      };
    }
  };
}

export function registerTools(server) {
  server.tool(
    "loop_search",
    "Full-text search across Microsoft Loop pages and components. Results are permission-trimmed to the calling user. Read-only. Always search before reading a page.",
    {
      query: z.string().min(1).max(500).describe("Search query string"),
      top: z.number().int().min(1).max(25).optional().default(10),
    },
    tool(searchLoopContent)
  );

  server.tool(
    "loop_list_recent",
    "List your most recently modified Microsoft Loop pages (permission-trimmed). " +
      "Each page includes a `ref` for loop_get_page. Read-only. Note: this reflects " +
      "recently *modified* pages you can access, which approximates Loop's Recent list.",
    {
      top: z.number().int().min(1).max(25).optional().default(20)
        .describe("Max pages to return"),
    },
    tool(listRecentLoop)
  );

  server.tool(
    "loop_find_meeting_notes",
    "Find Microsoft Loop pages that look like meeting notes (best-effort, by name " +
      "and folder path — Loop meeting notes are not a distinct type). Optionally " +
      "narrow with a query. Each result includes a `ref` for loop_get_page. Read-only.",
    {
      query: z.string().max(500).optional()
        .describe("Optional keywords (e.g. a project or meeting name) to narrow results"),
    },
    tool(findMeetingNotes)
  );

  server.tool(
    "loop_list_workspaces",
    "List the Microsoft Loop workspaces/locations you have access to, grouped " +
      "from your own permission-trimmed search results. Each workspace includes " +
      "its pages with a `ref` you can pass to loop_get_page. Optionally narrow " +
      "with a query. Read-only. Note: a workspace only appears if it has at least " +
      "one page discoverable by your search.",
    {
      query: z.string().max(500).optional()
        .describe("Optional keyword filter to narrow which workspaces/pages appear"),
    },
    tool(listLoopWorkspaces)
  );

  server.tool(
    "loop_list_components",
    "List Microsoft Loop component files (.loop) stored in the calling user's OneDrive (Teams/Outlook Loop components). Read-only.",
    {},
    tool(listOneDriveLoopComponents)
  );

  server.tool(
    "loop_get_page",
    "Read a Microsoft Loop page/component as HTML. First call loop_search or " +
      "loop_list_components, then pass the `ref` string from the result you want. " +
      "Each ref is per-user and time-limited; only items YOU discovered can be read. " +
      "Read-only.",
    {
      ref: z.string().min(1).max(2048)
        .describe("The `ref` value from a loop_search / loop_list_components result"),
    },
    tool(getLoopPageContent)
  );
}
