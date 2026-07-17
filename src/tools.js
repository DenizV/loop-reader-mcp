/**
 * tools.js — MCP tool registration, shared by the stdio (index.js) and
 * HTTP/hybrid (httpServer.js) entry points.
 */

import { z } from "zod";
import {
  searchLoopContent,
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
    "loop_list_components",
    "List Microsoft Loop component files (.loop) stored in the calling user's OneDrive (Teams/Outlook Loop components). Read-only.",
    {},
    tool(listOneDriveLoopComponents)
  );

  server.tool(
    "loop_get_page",
    "Read a Microsoft Loop page/component as HTML (server-side conversion). Get driveId/itemId from loop_search or loop_list_components first — in hybrid mode, only items that appeared in YOUR recent search results can be read. Read-only.",
    {
      driveId: z.string().min(1).max(512).describe("Drive ID containing the item"),
      itemId: z.string().min(1).max(512).describe("Item ID of the .loop file"),
    },
    tool(getLoopPageContent)
  );
}
