# Product Concept

## Problem

Security teams often receive repeated detections for the same short-lived activity while source formats, field names, timestamp conventions, and context quality vary across tools. Manual mapping and fixed grouping keys make a small deduplication utility brittle: every new source requires setup, and broad keys can conceal different activity.

## Product decision

SOC Alert Deduplicator uses an adaptive local pipeline:

1. detect and decode common text telemetry formats;
2. map flat or nested vendor fields into a stable alert contract;
3. measure field coverage and repetition in the current batch;
4. infer evidence fields, weights, threshold, blocking keys, and a continuity window;
5. group alerts only when weighted evidence and identity boundaries agree; and
6. expose the reasoning, source IDs, and inferred profile for analyst review.

The application reduces queue repetition; it does not suppress evidence, classify true positives, or automate response.

## Primary users

- SOC analysts reviewing exported alert batches.
- Detection engineers validating noisy rules or public attack datasets.
- Security administrators comparing correlation behavior before SIEM implementation.
- Engineering reviewers assessing parsing, validation, deterministic processing, safety, and desktop usability.

## Core requirements

- No source-specific configuration for ordinary supported text formats.
- Multiple heterogeneous files can be combined in one run.
- Every accepted alert is validated and appears in exactly one incident.
- Identity conflicts and time boundaries constrain similarity matching.
- Outputs explain the selected profile and match evidence.
- Failures are concise and do not echo complete telemetry records.
- Runtime is offline and does not execute field values.
- The desktop interface remains useful on compact and wide displays.

## Non-goals

- Live SIEM transport or streaming ingestion.
- Direct proprietary binary parsing for every vendor format.
- Malware detonation, threat classification, campaign attribution, or automated containment.
- Authentication, role-based access, shared storage, or case management.
- A universal guarantee that every cluster represents one real-world incident.

## Success measures

- Complete input/output alert-reference preservation.
- Reviewed sample remains 40 alerts to 17 incidents.
- Public 8,050-record raw-telemetry fixture processes without manual schema mapping.
- Populated source-process and target-process identities never mix inside a cluster.
- Numeric queue columns sort by typed values.
- Static checks and the full automated suite pass.
