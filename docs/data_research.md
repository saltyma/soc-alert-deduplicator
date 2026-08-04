# Telemetry Format Research

## Research question

How can a local batch tool accept common security telemetry without requiring a mapping file for every source, while remaining explainable and conservative when data is ambiguous?

## Standards and implementation choices

### JSON and JSON Lines

Security exports commonly use top-level arrays, single objects, wrapper arrays such as `events` or `alerts`, Elastic-style `hits.hits`, or one JSON object per line. The importer treats duplicate object keys as an error because different parsers may otherwise select different values. Nested objects are flattened and indexed by useful suffixes, allowing mappings such as `_source.host.name` → `host`.

### Delimited data

Python's [`csv.Sniffer`](https://docs.python.org/3/library/csv.html#csv.Sniffer) provides delimiter inference from a sample. Detection is restricted to comma, semicolon, tab, and pipe, and a header with at least two fields is required. CSV and TSV labels remain visible in source provenance.

### Syslog

[RFC 5424](https://www.rfc-editor.org/rfc/rfc5424) defines a structured syslog header with priority, version, timestamp, host, application, process ID, message ID, and message body. The importer also recognizes the widespread BSD timestamp/header form. Facility/severity priority is normalized to the application's five-level severity vocabulary.

Because RFC priority begins with an angle-bracket number such as `<134>`, syslog recognition precedes generic XML parsing.

### CEF

The [Common Event Format implementation standard](https://docs.microfocus.com/doc/2097/26.1/siemcefimplementationstandard) describes a pipe-delimited header and key-value extension. The importer retains vendor/product source identity, signature, event name, severity, common destination/user fields, message, and source timestamp when present.

### LEEF

IBM documents [Log Event Extended Format](https://www.ibm.com/docs/en/qsip/7.5?topic=leef-overview) as a pipe-delimited header followed by attributes separated by a version-dependent delimiter. LEEF 1 and 2 records are parsed without a vendor profile; common attributes such as `devTime`, `src`, `sev`, and `msg` flow through the alias mapper.

### XML and Windows events

Exported Windows events use a stable schema namespace and benefit from detailed provider/event mappings. The existing parser preserves Sysmon source and target images, Windows process creation fields, user context, commands, hashes, and record IDs. Generic XML is accepted when it contains scalar event fields or repeated record elements.

Direct binary EVTX is deliberately rejected. Requiring an XML export avoids silently misreading a proprietary binary structure without a dedicated parser dependency.

### Archives and encodings

Vendor bundles often arrive compressed. GZIP and ZIP support is bounded by a 256 MiB expanded limit and 128 ZIP members. Encrypted ZIP members are rejected. UTF-8, validated UTF-16, and CP1252 cover common export encodings; control-heavy/binary data is rejected.

## Normalized contract

Required fields:

- `alert_id`
- `timestamp`
- `source`
- `host`
- `event_type`
- `severity`

Optional evidence includes user, source/target/parent process, command line, SHA-256, rule name, and description. The importer also adds `detected_format` and `source_record` provenance.

Aliases include common flat and nested names for each field. Missing host becomes `unknown-endpoint`; missing event becomes `generic_event`; missing severity becomes informational. Missing or unrecognized timestamps use file metadata and create an explicit profile warning.

## Deduplication implications

- Unique record IDs are provenance, not grouping evidence.
- Host, process, target process, file hash, and event identity constrain clusters when populated.
- Command lines benefit from volatile-number/GUID/hex normalization.
- Description is low-weight evidence because free text changes easily and may contain high-cardinality values.
- Time cadence must be inferred from the current batch, then bounded.
- Missing fields cannot count as positive similarity.

## Validation datasets

The 40-record sample provides a reviewed oracle for repeatability and edge cases. The commit-pinned Splunk Attack Data T1003.001 bundle supplies 8,050 raw Windows/CrowdStrike records for format, scale, provenance, and cluster-drift testing. Neither dataset establishes a universal operational accuracy rate.
