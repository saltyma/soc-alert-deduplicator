# Release Verification

## Version 2.1.2 gate

| Area | Verification | Status |
|---|---|---|
| Universal ingestion | JSON, JSONL/NDJSON, CSV/TSV, generic and Windows XML, CEF, LEEF, syslog, key-value, plain text, GZIP, ZIP | Passed |
| Schema inference | Nested suffix indexing, aliases, deterministic IDs, severity and timestamp normalization, provenance | Passed |
| Adaptive profile | Coverage/cardinality statistics, deterministic profile ID, inferred fields, weights, threshold and window | Passed |
| Deduplication safety | Host/hash conflicts, process/target anchors, minimum evidence, continuity, maximum span, cluster-drift regression | Passed |
| Output integrity | Unique alert references, protected paths, atomic JSON/CSV, formula neutralization | Passed |
| Desktop interface | Responsive queue-first layout, collapsible sections, filter-aware visuals, numeric sorting, exact-row double-click investigation, plain-language preview, source-record inspection, export, screenshot | Passed |
| Visual explanation | Severity/host/timeline charts, process relationship, grouping-decision diagram, accessible text equivalents | Passed |
| Static checks | Ruff format, Ruff lint, mypy | Passed |
| Automated tests | 264 tests, 96% branch-aware engine coverage | Passed |
| Reviewed sample | 40 alerts to 17 SMART incidents, 0 lost/duplicate references | Passed |
| Public raw telemetry | 8,050 alerts to 450 SMART incidents, 0 lost/duplicate references, no mixed process identities | Passed |

## Compatibility

The original exact-policy engine, configuration contract, CLI path, 40-alert oracle, raw Windows/CrowdStrike importer, and CSV exporter remain covered by the automated suite. SMART mode is now the default; exact behavior is available with `--mode exact` or an explicit compatible exact policy.

## Release artifacts

- source package and console entry points in `pyproject.toml`;
- adaptive desktop screenshot at `docs/demo/gui-dashboard-v2.png`;
- investigation workspace screenshot at `docs/demo/incident-investigation-v2.png`;
- public raw-data manifest, upstream metadata, checksums, and license under `data/external/splunk_attack_data/T1003.001/`;
- architecture, configuration, interface, threat-model, and validation documentation under `docs/`; and
- complete automated tests under `tests/`.
