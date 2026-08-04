# Changelog

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
