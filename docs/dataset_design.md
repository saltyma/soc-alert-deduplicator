# Validation Dataset Design

## Two complementary fixtures

The repository uses a small reviewed sample for deterministic correctness and a larger third-party capture for raw-format and scale validation.

| Fixture | Purpose | Ground truth |
|---|---|---|
| `data/demo/raw_alerts.json` | Exact/smart regression, missing values, normalization, queue UI | Reviewed 17-incident exact oracle |
| `data/external/splunk_attack_data/T1003.001/` | Raw Windows/CrowdStrike ingestion, performance, process-identity drift | No duplicate labels; structural invariants only |

## Reviewed sample

The 40 normalized alerts include:

- repeated credential-access, malware, PowerShell, authentication, and persistence scenarios;
- singleton events that must remain separate;
- casing and surrounding-whitespace changes;
- omitted, null, and blank optional evidence;
- process, host, user, hash, and event changes that should split exact groups;
- command and parent-process variation retained as evidence; and
- informational through critical severity.

The exact-policy oracle contains 17 incidents and preserves all 40 IDs exactly once. SMART mode independently produces 17 incidents with its inferred profile. All names, hosts, commands, and hashes in this fixture are fictional and public-safe.

## Public raw telemetry

The T1003.001 fixture is pinned by upstream commit and file checksum. It contains 8,050 raw records across Sysmon XML, Windows Security XML, and CrowdStrike JSON Lines. It is controlled attack-emulation telemetry, not organic production traffic.

Since the upstream data has no duplicate labels, validation checks invariants rather than an unsupported accuracy claim:

- every raw record normalizes successfully;
- every normalized ID is unique;
- every ID appears in exactly one incident;
- populated host/hash/process/target identities do not conflict within a cluster;
- output is deterministic for the same inputs; and
- runtime remains practical for an interactive batch workflow.

The final V2 run produces 450 incidents and a 94.41% queue reduction. Reduction is descriptive only; it does not measure detection efficacy.

## Adversarial cases added to unit tests

- a missing-process alert followed by two different process families;
- different source hashes with otherwise identical context;
- different target processes with otherwise identical context;
- volatile command GUIDs and numeric arguments;
- activity spanning more than the maximum cluster duration;
- nested Elastic-style fields;
- single-record JSON Lines;
- RFC syslog beginning with an XML-like angle bracket;
- control-heavy binary bytes;
- duplicate IDs across files; and
- mixed-format ZIP/GZIP inputs.

These cases are permanent regressions because each exposed a realistic failure mode in format detection, schema mapping, or cluster safety.
