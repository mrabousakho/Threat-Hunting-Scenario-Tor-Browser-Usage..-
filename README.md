# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/mrabousakho/Threat-Hunting-Scenario-Tor-Browser-Usage..-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

Threat Hunt Report (Unauthorized TOR Usage)
Detection of Unauthorized TOR Browser Installation and Use on Workstation: “buakar-threat-hunting”


Scenario:
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.


High-Level TOR related IoC Discovery Plan:
Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events
Check DeviceProcessEvents for any signs of installation or usage
Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports
Steps Taken
Searched the DeviceFileEvent for any file that had the string “tor” in it and discovered what look the employee “buakar downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called tor-shopping-list.txt. These events began 2026-03-30T02:35:22.1272782Z. 
Query used to locate the events:


DeviceFileEvents
| where DeviceName == "buakar-threat-h"
| where InitiatingProcessAccountName == "buakar"
| where FileName startswith "tor"
| where Timestamp >= datetime(2026-03-30T02:35:22.1272782Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256, Account = InitiatingProcessAccountName, FileName




Searched the DeviceProcessEvents  table for any ProcessCommandLine that contained the string tor-browser-windows-x86_64-portable-15.0.8.exe. Based on log return
At this time and date Mar 29, 2026 – 9:39:39 PM and employee by the name of
Buakar on the buakar-threat-hunt device downloaded the Tor Browser installer from the official Tor website, initiating the staging of anonymization tooling.


DeviceProcessEvents
| where DeviceName == "buakar-threat-h"
| where  AccountName =="buakar"
| where ProcessCommandLine contains "tor.exe"
| project DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, FolderPath, InitiatingProcessAccountName


Searched for DeviceProcessEvent table for any indication that the user employee buakar actually opened the browser. THere was evidence that they did open it at Mar 30, 2026 – 12:28:48 AM.
There were other instances of firefox.exe and tor.exe
Query used to locate event:
DeviceProcessEvents
| where DeviceName == "buakar-threat-h"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| where  AccountName =="buakar"
| where ProcessCommandLine contains "tor.exe"
| project Timestamp, AccountName, ActionType, FileName, ProcessCommandLine, FolderPath

Searched for the DeviceNetworkEvent for any indication that the tor browser was used to establish connection using any of the known tor port numbers.
On Mar 30, 2026 – ~12:30 AM, a remote session was established via Guacamole RDP, Source IP: 10.0.8.9 User: buakar port 9001. There were a few other connections.
Query used to locate events:
DeviceNetworkEvents
| where DeviceName == "buakar-threat-h"
| where InitiatingProcessAccountName !="system"
| where InitiatingProcessFileName == "tor.exe"
| where RemotePort in("9001", "9030", "9040", "9050", "9851", "9150")
| where isnotempty(RemoteIP)
| project Timestamp, IsInitiatingProcessRemoteSession, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort



 The 1 in the initiatingProcessRemoteSession indicates the process was executed. We also see the remote IPs of the sessions. The remote port 9001 is associated with tor. Firefox with tor was also used for normal browsing over port 443 and 8080. But I filter those out to focus on tor port established connections. 
Chronological Events
Phase 1: Tool Acquisition (Initial Access / Preparation)
Mar 29, 2026 – 9:39:39 PM
The user buakar downloaded the Tor Browser installer:
File: tor-browser-windows-x86_64-portable-15.0.8.exe
Source: https://dist.torproject.org/...
Location: C:\Users\employee\Download\
Initiated by:
explorer.exe (user-driven download)
Phase 2: Remote Session Activity Begins
📅 Mar 30, 2026 – ~12:19 AM
A remote session was established via Guacamole RDP
Source IP: 10.0.8.9
User: buakar
Phase 3: Silent Installation (Defense Evasion)
📅 Mar 30, 2026 – 12:24:49 AM
Tor Browser installer executed with:
tor-browser-windows-x86_64-portable-15.0.8.exe /S
Parent process:
cmd.exe
Phase 4: Installation Artifacts Created
📅 Mar 30, 2026 – 12:25:23 AM
Multiple Tor files created:
tor.txt
Tor-Launcher.txt
Installed under:

C:\Users\buakar\Desktop\Tor Browser\
Phase 5: Tor Browser Execution
📅 Mar 30, 2026 – 12:28:48 AM
firefox.exe (Tor Browser) launched
Phase 6: Tor Service Initialization
📅 Mar 30, 2026 – 12:28:52 AM
tor.exe process started with full configuration:
SOCKS Proxy: 127.0.0.1:9150
Control Port: 127.0.0.1:9151
DisableNetwork = 1
Phase 7: Browser Subprocess Activity
📅 Mar 30, 2026 – 12:28:57 AM
Additional firefox.exe processes spawned (browser content processes)
Phase 8: Internal Proxy Communication (Tor Active)
📅 Mar 30, 2026 – 12:28:31 AM
Network event:
Source: 127.0.0.1
Destination: 127.0.0.1
Process: tor.exe
Phase 9: Post-Activity Artifact Creation
📅 Mar 30, 2026 – 2:18:40 AM
File created:
tor-shopping-list.txt
Created via: notepad.exe
During remote session
Final Threat Interpretation
This is a complete and intentional sequence of actions, not accidental:
 Observed Behavior:
Tool download (Tor Browser)
Remote access via RDP
Silent installation (/S)
Execution of Tor Browser
Initialization of anonymization proxy
Active user interaction
MITRE ATT&CK Mapping
T1105 – Ingress Tool Transfer (Tor download)
T1059 – Command Execution (cmd.exe silent install)
T1090.003 – Multi-hop Proxy (Tor)
T1021.001 – Remote Services (RDP)
T1071 – Application Layer Protocol (Tor traffic potential)
Summary
On March 29, 2026, at 9:39 PM, user “buakar” downloaded the Tor Browser installer from the official Tor website, initiating the staging of anonymization tooling. At approximately 12:19 AM on March 30, a remote session was established via Guacamole RDP (10.0.8.9), after which the installer was executed silently using cmd.exe with the /S flag, enabling stealth deployment. Within minutes, installation artifacts confirmed successful setup, followed by execution of the Tor Browser (firefox.exe) and its underlying service (tor.exe), which established a local SOCKS proxy for anonymized communication, as evidenced by successful loopback network activity (127.0.0.1). At 2:18 AM, the user created a file (tor-shopping-list.txt) during the same remote session, indicating continued manual interaction. This sequence reflects a deliberate pattern of remote access, covert installation, and activation of anonymization capabilities, consistent with insider misuse and potential defense evasion, and represents a high-risk security event requiring further investigation.
Response Taken
TOR usage was confirmed on endpoint buakar-threat-hunt. The device was isolated and the user's direct manager was notified.
