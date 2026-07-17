/**
 * index.js — delegates to the HTTP entry point.
 *
 * The local stdio/delegated mode was removed when the phased rollout was
 * collapsed to the hosted hybrid deployment (per-user OBO trimming requires
 * an HTTP transport that carries the caller's identity).
 */
import "./httpServer.js";
