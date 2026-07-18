# Changelog

## v1.1.0

Adds discovery tools and a capability-based security model on top of the
original read path.

### New tools
- **loop_list_recent** — the caller's most recently modified Loop pages.
- **loop_find_meeting_notes** — best-effort meeting-notes finder (Loop meeting
  notes are not a distinct Graph type; heuristic by name/path).
- **loop_list_workspaces** — the Loop workspaces the caller can access, grouped
  from their own trimmed results and sorted by recent activity.
- (Existing: loop_search, loop_list_components, loop_get_page.) Six tools total.

### Security
- **Signed, stateless capability handles.** Reads use an opaque `ref`
  (HMAC-signed, carrying item id + principal + expiry). The model never handles
  raw identifiers; handles can't be forged or replayed across users/clients and
  survive restarts / multiple instances.
- **Principal binding** to tenant:user:client.
- **Explicit scope check** (`access_as_user`) and **ID-token rejection**.
- **Query sanitization** + **server-side .loop/.fluid re-filter** (injection
  resistance).
- **Structured audit logging**; optional App Insights telemetry redacts item ids.
- Handle-signing-key hardening; 60s clock-skew tolerance on token validation.

### Performance / reliability
- Single Graph call per read (display fields folded into the signed handle).
- App-token pre-warm at startup; parallel workspace-name lookups.
- `offline_access` advertised so clients get a refresh token and renew silently.
- JSON responses never truncated (size cap applies only to page content).

## v1.0.0
- Initial public release: hosted, in-app OAuth token validation (no gateway);
  On-Behalf-Of per-user search; app-identity retrieval; three tools
  (loop_search, loop_list_components, loop_get_page).
