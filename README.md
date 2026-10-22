# RDP Brute-Force Detection and Authentication Investigation

## 1. Objective
Investigate repeated failed Windows authentication attempts followed by successful logon events using Microsoft Sentinel and Kusto Query Language (KQL).

## 2. Lab Environment
- SIEM: Microsoft Sentinel
- Log source: Windows Security Events
- Target: VM-Windows
- Data table: SecurityEvent
- Investigation date: October 21, 2026
- Source IP observed: `106.192.188.133`

## 3. Lab Methodology
1. Generated controlled failed RDP authentication attempts.
2. Generated a successful RDP logon.
3. Investigated Windows Security Events in Microsoft Sentinel.
4. Filtered and correlated authentication events using KQL.
5. Reviewed event IDs, logon types, usernames, timestamps and source IP.

## 4. Investigation Findings

### Failed Authentication

- **Event ID:** 4625
- **Observed failed attempts:** 6
- **Source IP:** `106.192.188.133`
- **Logon Type:** 3
- **Distinct target usernames:** 5
- **Target usernames observed:**
  - `alam768`
  - `alamsn`
  - `ajsbdwebhjb`
  - `aksndnjf`
  - `sjnjdfjk`
- **Repeated target:** `sjnjdfjk` (2 failed attempts)

All six failed authentication events were observed from the same source IP against `VM-Windows` during the investigation window.


### Successful Authentication
- Event ID: 4624
- Account observed: `alam686`
- Source IP: `106.192.188.133`
- Successful events observed:
  - Logon Type 3: 2 events
  - Logon Type 10: 1 event

The Type 10 event is stronger evidence of a RemoteInteractive logon. Type 3 indicates a network logon and is not exclusive to RDP.

## 5. Investigation Timeline

| Time (UTC) | Event ID | Account | Logon Type |
|---|---:|---|---:|
| 06:36:51.189 | 4625 | alam768 | 3 |
| 06:37:09.753 | 4625 | alamsn | 3 |
| 06:37:25.790 | 4625 | ajsbdwebhjb | 3 |
| 06:37:44.472 | 4625 | aksndnjf | 3 |
| 06:37:58.999 | 4625 | sjnjdfjk | 3 |
| 06:38:13.672 | 4625 | sjnjdfjk | 3 |
| 06:38:34.715 | 4624 | alam686 | 3 |
| 06:38:37.031 | 4624 | alam686 | 3 |
| 06:38:41.675 | 4624 | alam686 | 10 |

## 6. KQL Investigation
Reusable queries are available in the `queries/` directory:
- `failed-rdp-logons.kql`
- `rdp-authentication-timeline.kql`

The investigation used event filtering, aggregation, timestamp ordering, and correlation by source IP and host.

## 7. SOC Assessment
The observed sequence of multiple failed authentication attempts followed by successful logon events from the same source IP is suspicious and warrants investigation.

However:
- The observed sequence alone does not prove that the failures caused the successful logon.
- Multiple 4624 events do not necessarily represent multiple distinct RDP sessions.
- The source IP alone does not establish attacker identity.
- The activity should be classified based on corroborating evidence and lab context.

**Assessment:** Suspicious authentication pattern observed; compromise is not conclusively established from these events alone.

## 8. Recommended Analyst Actions
1. Validate whether the source IP and login activity are expected.
2. Review the successful Type 10 logon and associated account.
3. Inspect adjacent process creation, network and endpoint telemetry.
4. Check for account misuse, privilege escalation or persistence.
5. If unauthorized access is confirmed, follow the incident response process: contain, investigate, eradicate and recover.
6. Preserve relevant logs and investigation evidence.

## 9. Evidence
Store sanitized investigation screenshots in `evidence/`.

Suggested evidence:
- `01-rdp-test-context.png`
- `02-failed-logons-4625.png`
- `03-successful-rdp-4624.png`
- `04-rdp-correlation-timeline.png`

Remove or redact sensitive public IPs, account information, tenant identifiers and other personal details before public publication where appropriate.

## 10. Interview Learning
This lab demonstrates:
- Windows Event ID 4625 and 4624 interpretation
- Logon Type 3 versus Type 10
- KQL filtering and summarization
- Authentication event timeline analysis
- Evidence-based SOC triage
- Distinguishing suspicious activity from confirmed compromise

## 11. Result
Completed a controlled Windows authentication investigation in Microsoft Sentinel and documented the findings, KQL queries and evidence collection approach.
