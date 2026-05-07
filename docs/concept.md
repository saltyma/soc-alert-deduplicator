# SOC Alert Deduplicator - Concept Document

## 1. Problem Statement
Alert Fatigue. NO! we are not talking about medical monitoring systems, we are talking about the SOC Alert Fatigue, which happens when InfoSec Analysts are overwhelmed by a high volume of security alerts. This doesn't just result in burnout of valuable SOC assets, but also drags down their response times and leads to overlooked threats, so we can imagine the scale of damage this overlooked problem can exacerbate.
The SOC Alert Deduplicator not only identifies this issue, but offers a solution that can significantly reduce the noise and improve clarity by grouping repeated or highly similar alerts into incident-oriented summaries.

## 2. Target Users
### SOC Analyst:
The SOC Analyst is the main user that benifits from the tool, by relying on it to reduce repeated alerts into grouped incident summaries. Thus reducing the time of triage and focusing on unique and high level threats instead of reviewing the same activity multiple times.

### SOC Admin / Detection Engineer
A SOC Admin / Detection Engineer focuses on fine tuning the tool by configuring how alerts are grouped. they can adjust fields such as host, user, process name, file hash, event type, or severity depending on the SIEM sourse and operational needs.

### Platform Engineer
A secondary Actor that takes care of loading the data into the tool, might need to gather the logs from different sources, organize it, and convert it to a compatible format to feed it to the deduplicator.

## 3. Project Goal
The primary goal of this project is building a Python tool that feeds on JSON security alerts, normalizes important fields, groups duplicate or near-duplicate alerts, and outputs concise incident summaries.
The first version focuses on batch processing local JSON files, nor real-timeSIEM integration.

## 4. Scope
Version 1 will include:

- Loading alerts from a local JSON file
- Reading configurable grouping fields from 'config.json'
- Normalizing alert fields such as host, user, process name, and file hash
- Grouping exact duplicates based on selected fields
- Producing one incident summary per group
- Saving grouped resullts to a JSON output file
- Providing demo input and expected output files
- Including basic tests for parsing, grouping, and missing fields

## 5. Non-Goals
Version 1 will not include:

- Real-time SIEM monitoring
- Machine learning-based clustering
- A web dashboard
- Automatic incident response
- Direct connection to production SIEM systems
- Full support for every alert format
- Guaranteed detection of all duplicate attack activity

## 6. Input Data
The tool expects a JSON file containing a list of alert objects.

Each alert should contain fields such as:

| Field | Description | Required in V1 |
| --- | --- | --- |
| 'alert_id' | Unique alert identifier | yes |
| 'timestamp' | Alert timestamp | Yes |
| 'source' | Alert source, such as Wazuh, Sysmon, or mock SIEM | Yes |
| 'host' | Affected machine or endpoint | Yes |
| 'user' | User account related to the alert | No |
| 'event_type' | Type of event or detection | Yes |
| 'process_name' | Process involved in the alert | No |
| 'file_hash' | File hash if available | No |
| 'severity' | Alert severity level | Yes |
| 'rule_name' | Detection rule name | No |
| 'description' | Human-readable alert description | No |

## 7. Output Data
The tool outputs a list of incident summaries.

Each incident summary should contain:

| Field | Description |
|---|---|
| `incident_id` | Generated incident identifier |
| `alert_count` | Number of alerts grouped into the incident |
| `grouping_fields` | Fields used to create the group |
| `host` | Affected host |
| `user` | Related user, if available |
| `event_type` | Main event type |
| `process_name` | Process involved, if available |
| `file_hash` | File hash, if available |
| `severity` | Highest severity in the group |
| `first_seen` | First alert timestamp |
| `last_seen` | Last alert timestamp |
| `alert_ids` | IDs of grouped alerts |
| `summary` | Short readable explanation |

## 8. Duplicate Detection Logic - V1
In version 1, alerts are considered duplicates when they share the same values for the configured grouping fields.

Default grouping fields:

- `host`
- `user`
- `event_type`
- `process_name`
- `file_hash`

Before grouping, values are normalized by:

- converting text to lowercase
- trimming spaces
- replacing missing optional fields with `unknown`

Example:

Two alerts are grouped together if they have:

- same host
- same user
- same event type
- same process name
- same file hash

This simple rule-based approach is explainable and easy to test.

### SIEM/Data Source Decision for V1
Version 1 will use mock JSON alerts inspired by Wazuh and Sysmon-style fields.

This allows the project to focus first on deduplication logic, clean data design, testing, and documentation without depending on a full SIEM installation.

A later version may include direct Wazuh integration or exported Wazuh alerts.

## 9. Success Criteria
Version 1 is successful if:

- The tool can load a JSON file of alert
- Duplicate alerts are grouped consistently
- Different alerts are not incorrectly grouped
- Missing optional fields do not crash the program
- The grouped output is readable and useful for triage
- The behavior can be adjusted through 'config.json'
- Basic tests prove the main grouping logic works

## 10. Assumptions
- Input alerts are provided as JSON
- Alerts have at least an ID, timestamp, source, host, event type, and severity
- Some optional fields may be missing
- The first version uses batch processing, not real-time monitoring
- The grouping logic is rule-based and explainable
- Demo data is sanitized and safe to publish

## 11. Risks
- False grouping: unrelated alerts may be grouped together if fields are too broad
- Missed grouping: true duplicates may remain separate if fields differ slightly
- Missing fields may reduce grouping accuracy
- Poor configuration may produce misleading incident summaries
- Real SIAM alerts may use inconsistent field names
- Sensitive data must not be included in public demo files

## 12. Future Improvements
- Include the process of gathering the raw data from multiple security resources such as firewalls, SIEMs, endpoits and converting the data into the right format that is compatible with the deduplicator tool, to feed the output directely to the tool, without manual interference of platform engineers. We are talking about a pipeline from the infosec tools to the deduplicator tool.
- Add near-duplicate scoring instead of only exact matching
- Add time-window based grouping
- Support Wazuh exported alerts
- Support Sysmon event samples
- Add CSV output
- Add CLI arguments
- Add basic terminal table output
- Add simple dashboard or Streamlit interface
- Add severity-based prioritization
- Add confidence score for each incident group
