# T1003.001 real-data fixture

This directory holds the canonical datasets declared by Splunk Attack Data's
`T1003.001/atomic_red_team` metadata. The records were captured from Atomic Red
Team credential-dumping tests running in Splunk Attack Range. They are real raw
lab telemetry, not fabricated alert JSON and not organic production traffic.

- Upstream: <https://github.com/splunk/attack_data>
- Scenario: <https://github.com/splunk/attack_data/tree/671041b0405d5d766378a34a82bae59c5c672d9f/datasets/attack_techniques/T1003.001/atomic_red_team>
- Technique: MITRE ATT&CK T1003.001, LSASS Memory
- License: Apache-2.0; see `UPSTREAM_LICENSE`
- Integrity and provenance: `manifest.json`

The five `.log` files are intentionally ignored by Git because the complete raw
bundle is about 14.4 MB. Fetch the exact commit-pinned files and verify their
SHA-256 checksums with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\fetch_splunk_t1003_001.ps1
```

`normalized_alerts.json` and `incidents.json` are generated locally and are also
ignored. See `docs/real_data_test.md` for the complete reproduction and the
observed results.

Safety note: the files are passive text telemetry, but some fields contain real
attack commands and URLs recorded during emulation. Treat their contents as
untrusted data and do not copy commands into a shell.
