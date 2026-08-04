# Real raw-data test: Splunk Attack Data T1003.001

## Outcome

The complete canonical bundle imported successfully: **8,050 raw telemetry
records became 8,050 valid normalized alerts and 498 incident groups**. All
8,050 alert IDs appear exactly once in the grouped output, so the transformation
lost no references. The apparent queue reduction is 93.81%.

That percentage is a pipeline observation, not a claim of 93.81% detection
quality. This public scenario has no ground-truth duplicate labels, and the
current engine has no time-window constraint.

## Why this dataset

[Splunk Attack Data](https://github.com/splunk/attack_data) is an official,
Apache-2.0-licensed repository of attack telemetry built for detection
development and testing. The selected
[T1003.001 Atomic Red Team scenario](https://github.com/splunk/attack_data/tree/671041b0405d5d766378a34a82bae59c5c672d9f/datasets/attack_techniques/T1003.001/atomic_red_team)
records LSASS credential-dumping tests executed in Splunk Attack Range.

This is real raw endpoint telemetry from controlled attack emulation. It is more
representative than fabricated alert JSON, but it is not organic production SOC
traffic. The five source files are exactly those declared by the upstream
`atomic_red_team.yml` metadata.

| Source | Raw records | Shape |
|---|---:|---|
| Sysmon | 7,997 | Windows Event XML; some records span multiple lines |
| CrowdStrike Falcon | 43 | JSON Lines |
| Windows Security | 10 | Windows Event XML, Event ID 4688 |
| **Total** | **8,050** | 14.4 MB of raw logs |

Exact byte sizes, SHA-256 hashes, the pinned upstream commit, and per-file record
counts are in
[`data/external/splunk_attack_data/T1003.001/manifest.json`](../data/external/splunk_attack_data/T1003.001/manifest.json).
The upstream metadata and Apache-2.0 license are preserved beside it.

## Reproduce from the raw files

Fetch and checksum the commit-pinned dataset:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\fetch_splunk_t1003_001.ps1
```

Import all three telemetry shapes into the application's validated alert schema:

```powershell
soc-alert-import-raw `
  --input data/external/splunk_attack_data/T1003.001/raw/windows-sysmon_creddump.log `
  --input data/external/splunk_attack_data/T1003.001/raw/procdump_windows-security.log `
  --input data/external/splunk_attack_data/T1003.001/raw/crowdstrike_falcon.log `
  --input data/external/splunk_attack_data/T1003.001/raw/createdump_windows-sysmon.log `
  --input data/external/splunk_attack_data/T1003.001/raw/windows-sysmon.log `
  --output data/external/splunk_attack_data/T1003.001/normalized_alerts.json
```

Run the normal deduplication pipeline:

```powershell
soc-alert-deduplicator `
  --input data/external/splunk_attack_data/T1003.001/normalized_alerts.json `
  --config config.real-data.json `
  --output data/external/splunk_attack_data/T1003.001/incidents.json
```

To inspect it visually, launch `soc-alert-deduplicator-gui`, select those same
normalized input, configuration, and incident-output paths, then choose **Analyze
alerts**.

## Observed result

| Measure | Value |
|---|---:|
| Raw records | 8,050 |
| Valid normalized alerts | 8,050 |
| Exact-key incident groups | 498 |
| Apparent queue reduction | 93.81% |
| Unique input IDs | 8,050 |
| Grouped ID references | 8,050 |
| Lost or duplicate references | 0 |
| Largest group | 3,545 alerts |
| Hosts/agent identities | 6 |

Source distribution: 7,997 Sysmon records, 43 CrowdStrike records, and 10
Windows Security records. The most common event is Sysmon Event ID 10 process
access (6,941 records), followed by process creation (426) and file creation
(382).

The real-data pass caused one useful schema improvement: `target_process_name`
is now preserved separately from the source process and can participate in
grouping. Without it, one process-access group incorrectly combined activity
against different target processes and reached 4,179 alerts. With target context,
the output has 498 groups rather than 206. The remaining 3,545-alert largest
group is repeated `svchost.exe` access to `sysmon64.exe`, which shows why a future
time-window feature is still necessary.

## Interpretation limits

- Imported `severity` is a documented priority heuristic because raw Sysmon and
  Windows Security events are telemetry, not vendor alerts with normalized
  severity labels. Process access to `lsass.exe` is marked critical; other
  mappings remain visible in `raw_import.py`.
- The bundle combines captures dated 2020, 2022, and 2023. It represents one
  ATT&CK technique scenario, not one continuous production queue.
- CrowdStrike records in this sample omit a hostname, so the stable Falcon agent
  ID (`aid`) is used as the endpoint identity.
- Exact grouping still risks over-grouping repeated legitimate activity and
  under-grouping related activity with changing fields. Analysts must inspect
  the source references before acting.
- Logged command lines and URLs are untrusted text. The importer parses them; it
  never executes them.
