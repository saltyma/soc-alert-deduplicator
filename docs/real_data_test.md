# Real-data validation: Splunk Attack Data T1003.001

## Result

The complete commit-pinned bundle contains 8,050 raw endpoint records. The V2 pipeline normalizes all 8,050 records and groups them into 450 incidents, a 94.41% queue reduction. Every normalized alert ID appears exactly once in the incident output.

| Measure | Result |
|---|---:|
| Raw records | 8,050 |
| Valid normalized alerts | 8,050 |
| SMART incidents | 450 |
| Queue reduction | 94.41% |
| Lost alert references | 0 |
| Duplicate output references | 0 |
| Clusters mixing populated source-process identities | 0 |
| Clusters mixing populated target-process identities | 0 |
| Processing time on the development machine | approximately 11 seconds from normalized JSON |

This is a pipeline validation result, not a duplicate-detection accuracy score. The dataset has no duplicate ground-truth labels, and controlled attack-emulation traffic is not representative of every production SOC.

## Dataset provenance

[Splunk Attack Data](https://github.com/splunk/attack_data) is an Apache-2.0-licensed collection published for detection development. The selected [T1003.001 Atomic Red Team scenario](https://github.com/splunk/attack_data/tree/671041b0405d5d766378a34a82bae59c5c672d9f/datasets/attack_techniques/T1003.001/atomic_red_team) records LSASS credential-dumping activity executed in Splunk Attack Range.

The repository pins upstream commit `671041b0405d5d766378a34a82bae59c5c672d9f`. Exact URLs, byte sizes, SHA-256 checksums, and per-file record counts are stored in [`manifest.json`](../data/external/splunk_attack_data/T1003.001/manifest.json). Upstream scenario metadata and license text are retained beside the manifest.

| Telemetry family | Records | Shape |
|---|---:|---|
| Sysmon | 7,997 | Windows Event XML; some events span multiple lines |
| CrowdStrike Falcon | 43 | JSON Lines |
| Windows Security | 10 | Windows Event XML, including Event ID 4688 |
| **Total** | **8,050** | approximately 14.4 MB |

## Reproduce

Download and checksum the pinned files:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\fetch_splunk_t1003_001.ps1
```

Run SMART mode directly against all five raw files:

```powershell
soc-alert-deduplicator `
  --input data/external/splunk_attack_data/T1003.001/raw/windows-sysmon_creddump.log `
  --input data/external/splunk_attack_data/T1003.001/raw/procdump_windows-security.log `
  --input data/external/splunk_attack_data/T1003.001/raw/crowdstrike_falcon.log `
  --input data/external/splunk_attack_data/T1003.001/raw/createdump_windows-sysmon.log `
  --input data/external/splunk_attack_data/T1003.001/raw/windows-sysmon.log `
  --output data/external/splunk_attack_data/T1003.001/incidents.v2.json
```

The same sources can be normalized as a separate inspection step:

```powershell
soc-alert-normalize `
  --input data/external/splunk_attack_data/T1003.001/raw/windows-sysmon_creddump.log `
  --input data/external/splunk_attack_data/T1003.001/raw/procdump_windows-security.log `
  --input data/external/splunk_attack_data/T1003.001/raw/crowdstrike_falcon.log `
  --input data/external/splunk_attack_data/T1003.001/raw/createdump_windows-sysmon.log `
  --input data/external/splunk_attack_data/T1003.001/raw/windows-sysmon.log `
  --output data/external/splunk_attack_data/T1003.001/normalized_alerts.json
```

Then run the normalized batch:

```powershell
soc-alert-deduplicator `
  --input data/external/splunk_attack_data/T1003.001/normalized_alerts.json `
  --output data/external/splunk_attack_data/T1003.001/incidents.v2.json
```

## Safety regression discovered at scale

An early similarity implementation allowed sparse records to bridge clusters with different process names. The initial 8,050-record run exposed a 5,658-alert cluster containing 27 source-process values and 66 target-process values. That result was rejected.

The corrected engine now:

- uses populated process and target-process identities in candidate block keys;
- stores cluster identity anchors independently from the first raw record;
- rejects populated process or target disagreement;
- removes expired cluster references from ordered index buckets; and
- retains continuity and maximum-span boundaries.

The final output contains no incident with multiple populated source-process or target-process identities. This is a structural safety property, not evidence that every remaining cluster is semantically correct.

## Interpretation

The largest final cluster contains 3,565 repeated Sysmon process-access records with the same host, event, source process, and target process inside the permitted continuity span. High-volume exact repetition is expected in this capture and demonstrates why alert-count sorting must be numeric in the desktop queue.

Severity values for raw Sysmon and Windows Security events are documented prioritization heuristics; those event formats do not provide a universal vendor alert severity. Process access to `lsass.exe` is prioritized as critical, while other mappings remain visible in `raw_import.py`.

The five files include captures from different years and endpoint identities. They represent one ATT&CK technique scenario, not one continuous production queue. Analysts must follow source IDs back to raw evidence before making a response decision.
