# Changelog

## 2.1.0 — 2026-08-04

### Added

- Live severity, host-volume, and alert-activity visualizations that follow the current queue filters.
- A resizable incident investigation window with Overview, Timeline, Why grouped, and Source alerts tabs.
- Process-to-target and alert-grouping diagrams built with native Qt rendering.
- Plain-language analyst narratives, cautious risk context, recommended checks, and explicit grouping explanations in every SMART JSON incident.
- Accessible names, descriptions, direct value labels, and tooltips for visual summaries.

### Changed

- Incident rows now display readable event names and expose a complete narrative tooltip.
- The main incident preview prioritizes what happened and why the records belong together; source records move into progressive disclosure.
- Search and severity filters now update the table, chart totals, host ranking, timeline, and visible-item summary together.
- The sample-data action and `--demo` option now always load the documented 40-alert sample.

### Verified

- 262 automated tests, 96% branch-aware engine coverage, Ruff formatting/lint, and mypy checks.
- Native chart and diagram rendering in Qt offscreen mode, dialog navigation, source-record inspection, and clipboard behavior.
- Reviewed sample: 40 alerts to 17 incidents with complete reference preservation.
- Splunk Attack Data T1003.001: 8,050 alerts to 450 incidents with complete reference preservation.

## 2.0.0 — 2026-08-04

### Added

- Automatic ingestion and normalization for JSON, JSON Lines/NDJSON, CSV/TSV, XML, Windows Event XML, CEF, LEEF, RFC/BSD syslog, key-value logs, plain text, GZIP, and ZIP.
- Nested field mapping, common security-field aliases, deterministic automatic IDs, and source provenance.
- Adaptive profiles with inferred evidence fields, weights, blocking fields, threshold, time window, evidence minimum, and deterministic profile ID.
- Evidence-weighted similarity, bounded candidate indexing, command-line volatility normalization, and explainable match metadata.
- Profile sidecar with detected formats, mappings, warnings, rationale, and reduction metrics.
- Standalone `soc-alert-normalize` command and multi-input CLI support.
- Extensive V2 ingestion, profile, clustering, pipeline, and safety regression tests.

### Changed

- SMART mode is now the default; exact policy mode remains available.
- Process and target-process identities are conservative cluster boundaries that cannot be bridged by sparse records.
- Expired candidate index entries are removed to preserve performance under stricter clustering.
- Desktop controls, metrics, queue toolbar, timestamp columns, and evidence view respond to screen width.
- Alert-count, confidence, and severity columns sort using typed values rather than display text.
- Input controls accept multiple files and common raw telemetry formats.
- Documentation now describes the adaptive engine, real-data findings, and current limitations.

### Verified

- 252 automated tests, 95% branch-aware engine coverage, Ruff formatting/lint, and mypy checks.
- Reviewed sample: 40 alerts to 17 incidents with complete reference preservation.
- Splunk Attack Data T1003.001: 8,050 alerts to 450 incidents, 94.41% queue reduction, complete reference preservation, and no cluster mixing populated source/target process identities.

## 1.0.0 — 2026-08-04

- Strict exact-match policy engine with normalized tuple grouping.
- Validated JSON input and atomic incident output.
- Dark PySide6 desktop dashboard, filtering, sorting, evidence review, and CSV export.
- Reviewed 40-alert to 17-incident oracle.
- Commit-pinned Splunk Attack Data T1003.001 fixture and specialized Windows/CrowdStrike importer.
