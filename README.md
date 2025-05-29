#  Microsft Sentinel-brute-force-detection (Incidentt Response/Rule Detection Creation)
Microsoft Sentinel rule to detect brute force attacks on Azure VMs – aligned with NIST 800-61 IR lifecycle.


## Brute Force Detection Rule in Microsoft Sentinel

This project demonstrates how to detect brute force attacks on Azure virtual machines using Microsoft Sentinel.

It includes a complete setup:
- KQL detection rule
- Step-by-step UI screenshots
- Incident response report based on NIST 800-61
- Optional automated response guidance


Tools & Framework Used :

- Microsoft Sentinel
- Microsoft Defender for Endpoint (MDE)
- NIST SP 800-61 Incident Response Lifecycle


 Project: Brute Force Detection in Microsoft Sentinel
Incident Type: Brute Force Attack on Azure VMs
Framework: NIST SP 800-61 – Incident Response Lifecycle

✅ Step 1: Preparation
Microsoft Sentinel and Microsoft Defender for Endpoint (MDE) were already deployed on all VMs.

Log collection and monitoring were active.

NSG (Network Security Group) rules existed but needed tightening.



__________________________________________________________________________________________________


### ✅ Step 2: Detection & Analysis

Brute force attempts were detected from 5 public IP addresses targeting 6 different Azure VMs.

| IP Address         | Device Name               | Action Type   | Failed Attempts |
|--------------------|---------------------------|---------------|-----------------|
| 178.20.129.235     | vmchei                    | LogonFailed   | 52              |
| 134.209.120.69     | dangerclose               | LogonFailed   | 57              |
| 216.225.206.246    | windows-mde-kb            | LogonFailed   | 80              |
| 193.37.69.105      | jh-vm-test-mde            | LogonFailed   | 57              |
| 193.37.69.105      | mde-ron                   | LogonFailed   | 82              |
| 185.243.96.107     | threat-hunt-lab           | LogonFailed   | 54              |

---

🔎 **KQL Query Used:**

```kql
DeviceLogonEvents
| where RemoteIP in ("178.20.129.235", "134.209.120.69", "216.225.206.246", "193.37.69.105", "185.243.96.107")
| where ActionType != "LogonFailed"




_________________________________________________________________________________________________________




✅ Step 3: Detection Rule Creation in Sentinel
🎯 Rule Logic (KQL):
kql
Copy
Edit
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172."
| summarize FailedAttempts = count() by RemoteIP, DeviceName, bin(Timestamp, 1h)
| where FailedAttempts >= 50
📌 Rule Settings:
Type: Scheduled Query Rule

Run every: 5 hours

Look back: 5 hours

Severity: High

MITRE ATT&CK Mapping:

Tactic: Credential Access

Technique: Brute Force (T1110)



_________________________________________________________________________________________________________

✅ Step 4: Containment, Eradication & Recovery
Affected VMs were isolated using Microsoft Defender for Endpoint.

Full anti-malware scans were run on all machines.

Continued monitoring showed no further malicious activity.

__________________________________________________________________________________________________________

✅ Step 5: Post-Incident Activity
NSG rules were updated to block RDP access from the public internet.

Only allowed access from trusted IPs (e.g., analyst’s home IP).

Proposed policy to enforce Bastion Host usage for all VM remote access going forward.
