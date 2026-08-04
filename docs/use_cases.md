# Use Cases

## UC-01: Analyze an unfamiliar export

An analyst selects a JSON, JSONL, CSV, XML, CEF, LEEF, syslog, key-value, or text export without preparing a mapping file. The application detects its format, normalizes recognizable fields, reports warnings, infers a SMART profile, and creates an incident queue.

Acceptance:

- a source report identifies format, record count, mapped fields, and warnings;
- required normalized fields validate;
- every accepted alert appears in one incident; and
- the inferred profile is written beside the output.

## UC-02: Combine endpoint and network sources

A detection engineer selects multiple files from different products. The application preserves per-record provenance, resolves duplicate vendor IDs deterministically, profiles the combined batch, and permits cross-source grouping only when identity and evidence boundaries agree.

Acceptance:

- repeated `--input` and desktop multi-select/drop both work;
- source formats remain visible per incident and in the profile; and
- conflicting host, hash, process, or target identity prevents a merge.

## UC-03: Review the highest-volume incidents

An analyst opens the desktop queue and sorts **Alerts** descending. Values sort numerically, so 100 appears above 20 and 2. The analyst filters by severity, confirms that the visual totals follow the filtered queue, opens the investigation, and inspects the retained source records.

Acceptance:

- numeric, confidence, severity, and text sort roles are typed correctly;
- filtering does not mutate output; and
- the preview explains what happened and why records were grouped; and
- the investigation provides risk context, timeline, diagrams, decision evidence, and complete source records.

## UC-04: Run on a compact display

An analyst uses the application near its 900×620 minimum size. Controls scroll independently, the primary action remains available, queue controls stack, metrics reflow, and low-priority timestamp columns hide. The sidebar can be collapsed.

## UC-05: Apply reviewed tuning

An administrator provides a small tuning file to set a stricter threshold or environment-specific window. The file does not contain source schema mappings.

Acceptance:

- unknown fields and unsafe values are rejected;
- overrides are visible in the profile sidecar; and
- input/tuning files are protected from output overwrite.

## UC-06: Preserve a fixed exact policy

An environment requires a fixed normalized tuple rather than adaptive scoring. The operator selects exact mode with `config.json`; the original deterministic engine produces stable byte-for-byte output for the reviewed oracle.

## UC-07: Reject unsupported binary input

An operator drops a binary EVTX, packet capture, or arbitrary executable into the application. It fails with a concise unsupported/binary error rather than inventing records. Windows event data must be exported as XML.

## UC-08: Validate public raw telemetry

A reviewer fetches the pinned Splunk Attack Data fixture, verifies checksums, processes the five raw files, and inspects the resulting profile and incidents. The run preserves 8,050 references, produces 450 incidents, and contains no cluster mixing populated source/target process identities.
