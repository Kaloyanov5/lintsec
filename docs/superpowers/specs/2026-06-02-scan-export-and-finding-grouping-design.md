# Scan Export & Finding Grouping — Design

**Date:** 2026-06-02
**Status:** Approved
**Phase:** #6 (Scan export), expanded to include read-time finding grouping

## Problem

Passive scanner modules (e.g. `MissingSecurityHeadersModule`) emit one `Finding`
row **per visited URL per rule**. A 30-page crawl with a missing CSP header yields
30 near-identical `Finding` rows: same `vulnerabilityType`, `severity`, `title`,
`description`, `remediation`, and — because the AI cache key is `vulnType + title` —
the **same `aiExplanation`** copied onto every row. Only `evidence.url` differs.

This crowds the scan results page and would bloat any export. Fixing presentation
fixes both, so this phase delivers two things via one mechanism:

1. **Read-time finding grouping** — collapse duplicate findings into groups.
2. **Scan export** — JSON + PDF downloads, both built on the grouped data.

## Decisions

- **Grouping happens at read time** in a shared backend service. Scanner and DB are
  unchanged — still one row per location, full evidence preserved. Reversible, no
  scanner touch.
- **Grouping key:** `(vulnerabilityType, severity, title)`. `note` and `payloadRef`
  do **not** participate in the key — they vary per instance and are carried as
  instance data. Confirmed correct for passive modules; XSS/SQLi titles are generic
  enough that they group by affected page, which is the desired behaviour.
- **Both formats** (PDF + JSON) ship this phase. JSON is near-free (Jackson serializes
  the DTOs); PDF via OpenPDF (already in `pom.xml`, `com.lintsec.report` reserved).
- **Path-suffix endpoints** (`.pdf` / `.json`), not `?format=`.
- **Keep** the existing flat `GET /findings` endpoint; add the grouped one alongside.
- **No guided learning** for the PDF renderer — Claude writes all code this phase.

## Architecture

### Grouping core (shared by results page + both exports)

`FindingGrouper` (in `com.lintsec.report`) — `List<Finding>` → `List<FindingGroup>`:

- **`FindingGroup`** — `vulnerabilityType`, `severity`, `title`, `description`,
  `remediation`, `aiExplanation` (all from the first member; identical within a
  group), `count`, `List<FindingInstance>`.
- **`FindingInstance`** — `id`, `url`, `parameter`, `note` (parsed from
  `evidenceJson`), `payloadRef`, `createdAt`. The fields that actually vary per
  duplicate.
- Groups sorted by severity (CRITICAL first), then title. Instances ordered by
  `createdAt`.

### DTOs (`com.lintsec.dto`)

- `FindingGroupResponse` — mirrors `FindingGroup`.
- `FindingInstanceResponse` — mirrors `FindingInstance`.
- `ScanExport` — the unified export document: scan metadata
  (`targetUrl`, `status`, config, `pagesCrawled`, timestamps), `severityCounts`
  (`Map<Severity,Integer>` / `EnumMap`), and `List<FindingGroupResponse> groups`.
  JSON export serializes this directly; the PDF renderer walks the same object so
  the two formats can never drift.

### Endpoints (`ScanController`)

All guarded by `findByIdAndUserId` → 404 if missing/not owned.

- `GET /api/scans/{id}/findings/grouped` → `List<FindingGroupResponse>`.
  Results page repoints to this.
- `GET /api/scans/{id}/export.json` → `ScanExport` JSON,
  `Content-Disposition: attachment`.
- `GET /api/scans/{id}/export.pdf` → `application/pdf`,
  `Content-Disposition: attachment`.
- Filename: `lintsec-scan-{id}-{yyyyMMdd}.{json|pdf}`.
- Export works for **any** scan status; the report notes the status (a RUNNING scan
  exports a partial snapshot).

### PDF renderer (`com.lintsec.report.ScanReportPdfRenderer`)

Builds the PDF from `ScanExport` via OpenPDF:

- **Header** — LintSec title, target URL, generated-on date, scan status +
  timestamps, pages crawled.
- **Severity summary table** — counts per severity.
- **One block per group** — severity + title + type, `count` and affected-URL list,
  description, remediation, AI explanation.
- Plain layout (polish deferred); correct structure over styling.

### Frontend

- **`scanService`** — add `getGroupedFindings(id)`; exports via plain anchor links to
  `/api/scans/{id}/export.pdf|json` (GET + same-origin cookie, no CSRF needed).
- **`ScanResultsPage`** — `FindingCard` becomes a **group card**: header shows
  severity + title + `× count` badge; expanded shows description / remediation / AI
  once, plus the list of affected locations. Add an **Export** control (PDF / JSON)
  next to Refresh.
- **Types** — add `FindingGroup` + `FindingInstance` to `types/finding.ts`.

## Error handling

- Not-owner / missing scan → 404 (`NotFoundException`).
- PDF generation failure → 500 problem-detail, **fail loud** (user-triggered sync
  action, not the fail-soft AI path).
- Zero findings → still a valid report / JSON ("No findings").

## Verification

- Smoke script: auth → scan 35 (163 findings, heavy dupes) → hit both export
  endpoints, assert 200 + correct content-type + non-trivial body; eyeball the PDF.
- Frontend: `npm run build`.

## Out of scope

- Scan-time / storage dedup (revisit only if row counts become a real DB problem).
- AI re-explain, dashboard, design polish.
