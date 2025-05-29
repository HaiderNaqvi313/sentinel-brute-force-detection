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

# 🔐 Azure VM Brute Force Detection – Microsoft Sentinel

This project detects and responds to brute force login attempts against Azure virtual machines using Microsoft Sentinel and Microsoft Defender for Endpoint (MDE). The response process follows the NIST SP 800-61 Incident Response Lifecycle and includes custom KQL-based rule creation.

---

## ✅ Step 1: Preparation

- Microsoft Sentinel and MDE pre-configured on all virtual machines.
- Log collection and monitoring for login attempts were active.
- Network Security Group (NSG) rules existed but required updates.

---

## ✅ Step 2: Detection & Analysis

Brute force attempts were detected from 5 public IP addresses targeting 6 different Azure VMs.

| IP Address         | Device Name         | Action Type   | Failed Attempts |
|--------------------|---------------------|---------------|-----------------|
| 178.20.129.235     | vmchei              | LogonFailed   | 52              |
| 134.209.120.69     | dangerclose         | LogonFailed   | 57              |
| 216.225.206.246    | windows-mde-kb      | LogonFailed   | 80              |
| 193.37.69.105      | jh-vm-test-mde      | LogonFailed   | 57              |
| 193.37.69.105      | mde-ron             | LogonFailed   | 82              |
| 185.243.96.107     | threat-hunt-lab     | LogonFailed   | 54              |

🔎 **KQL Query Used:**

```kql
DeviceLogonEvents
| where RemoteIP in ("178.20.129.235", "134.209.120.69", "216.225.206.246", "193.37.69.105", "185.243.96.107")
| where ActionType != "LogonFailed"
```

✅ **Result:** No successful logins detected.

---

## ✅ Step 3: Detection Rule Creation in Sentinel

🎯 **Rule Logic (KQL):**

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172."
| summarize FailedAttempts = count() by RemoteIP, DeviceName, bin(Timestamp, 1h)
| where FailedAttempts >= 50
```

📌 **Rule Settings:**

| Setting              | Value                        |
|----------------------|------------------------------|
| Type                 | Scheduled Query Rule         |
| Run Every            | 5 hours                      |
| Look Back            | 5 hours                      |
| Severity             | High                         |

🎯 **MITRE ATT&CK Mapping:**

| Category   | Value                        |
|------------|------------------------------|
| Tactic     | Credential Access            |
| Technique  | Brute Force (T1110)          |

---

## ✅ Step 4: Containment, Eradication & Recovery

- Isolated affected VMs using Microsoft Defender for Endpoint.
- Ran full anti-malware scans on all impacted systems.
- Monitored environment post-cleanup for any reinfection attempts.

---

## ✅ Step 5: Post-Incident Activity

- Updated NSG rules to block public RDP access.
- Allowed RDP only from a trusted home IP.
- Proposed policy to require use of Azure Bastion for all VM access.

---


---

Created by **Haider Naqvi**
