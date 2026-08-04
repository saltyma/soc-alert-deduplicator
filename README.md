# SOC Alert Deduplicator

A Python-based tool designed to reduce alert fatigue by clustering repetitive SOC alerts into incident-oriented summaries.

## Problem
Security analysts often receive repeated alerts for the same host, user, process, or file hash. This creates fatigue and slows down triage.
This tool aims to reduce alert noise by grouping duplicate or highly similar alerts into incident-oriented summaries.

## Target users
- SOC analysts who need faster alert triage
- SOC admins or detection engineers who need configurable grouping rules

## Status
Phase 5 testing is complete locally. The command-line MVP is protected by unit, failure-path, integration, CLI, and benchmark-oracle tests, with branch coverage enforced at 95% or higher.

## Implemented in version 1

- Parse and validate JSON alert arrays
- Normalize configurable grouping fields
- Group exact duplicates deterministically
- Aggregate alert counts, timestamps, severity, and alert IDs
- Handle omitted, null, blank, case-varied, and space-padded values
- Reject invalid input with concise user-facing errors
- Write complete JSON output atomically

## Quick start

From PowerShell in the project root:

```powershell
$env:PYTHONPATH = "src"
python -m soc_alert_deduplicator --input data/demo/raw_alerts.json --config config.json --output output.json
```

Expected result:

```text
Processed 40 alerts into 17 incidents.
Output written to output.json.
```

## Testing

Run the complete test suite from PowerShell in the project root:

```powershell
pytest
coverage run -m pytest
coverage report
```

The coverage configuration enables branch measurement and fails the report below 95%. The end-to-end benchmark test also requires the generated JSON to match `data/demo/expected_incidents.json` byte for byte.

## Design

- [Version 1 architecture](docs/architecture.md) defines the pipeline, component boundaries, contracts, deterministic behavior, and error strategy.
- [Version 1 use cases](docs/use_cases.md) defines analyst/admin flows and acceptance criteria for implementation and testing.

The implementation flow is: `load -> clean -> group -> score -> summarize -> output`.

## Demo data

The project includes a public-safe demo dataset under `data/demo/`.

- `raw_alerts.json` contains 40 synthetic Wazuh-style alerts enriched with Sysmon-inspired process context.
- `expected_incidents.json` is the manually specified benchmark: 40 alerts should become 17 incidents under the v1 grouping contract.
- The data covers duplicates, case and whitespace normalization, missing optional fields, near-duplicates, unrelated alerts, and the same file hash appearing on different hosts.
- All identities, hosts, timestamps, hashes, command lines, and rule names are fictional.

See [the data research](docs/data_research.md) for source rationale and [the dataset design](docs/dataset_design.md) for the scenario and oracle definitions.
