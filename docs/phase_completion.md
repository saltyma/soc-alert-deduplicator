# Portfolio Phase Completion Record

| Phase | Deliverable | Evidence | Status |
|---|---|---|---|
| 0 — Setup | Repository, Python structure, MIT license | Root files and package layout | Complete |
| 1 — Conception | Problem, users, scope, contracts | `docs/concept.md` | Complete |
| 2 — Research + Data | 40 realistic synthetic alerts and oracle | `data/demo/`, research docs | Complete |
| 3 — Design | Architecture and use cases | `docs/architecture.md`, `docs/use_cases.md` | Complete |
| 4 — Core Implementation | Deterministic validated pipeline and CLI | `src/soc_alert_deduplicator/` | Complete |
| 5 — Testing | Unit, failure, integration, CLI, benchmark tests | `tests/`, 100% engine branch coverage | Complete |
| 6 — Config System | Strict adjustable grouping policy | `config.json`, `docs/configuration.md` | Complete |
| 7 — Demo + Proof | Before/after files, screenshot, reproducible run | `data/demo_before.json`, `data/demo_after.json`, `docs/demo/` | Complete |
| 8 — Documentation | Recruiter-facing README and guides | `README.md`, `docs/` | Complete |
| 9 — Threat Model | Abuse cases, controls, residual risks | `docs/threat_model.md` | Complete |
| 10 — Final Polish | Packaging metadata, clean dependencies, release docs | `pyproject.toml`, requirements, changelog | Complete |

## Additional interface milestone

A native dark PySide6 dashboard was added beyond the original version 1 core plan. It reuses the tested engine, provides incident filtering and evidence review, and adds optional CSV export without changing the canonical JSON output.

## Real-data validation milestone

The complete, commit-pinned Splunk Attack Data T1003.001 scenario is now
reproducible from public raw logs. The importer handles Windows Event XML streams
and CrowdStrike JSON Lines, preserves source/target process evidence, and has a
conditional end-to-end integration test. The verified run transformed 8,050 raw
records into 498 groups with all 8,050 source references preserved. See
`docs/real_data_test.md` for provenance, checksums, commands, and interpretation
limits.
