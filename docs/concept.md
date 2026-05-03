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

## 8. Duplicate Detection Logic - V1

## 9. Success Criteria

## 10. Assumptions

## 11. Risks

## 12. Future Improvements
Include the process of gathering the raw data from multiple security resources such as firewalls, SIEMs, endpoits and converting the data into the right format that is compatible with the deduplicator tool, to feed the output directely to the tool, without manual interference of platform engineers. We are talking about a pipeline from the infosec tools to the deduplicator tool.
