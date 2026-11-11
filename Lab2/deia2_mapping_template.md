# DEIA 2 - MITRE / IOC Mapping

Fill in this file with your agreed-upon results and upload it as your
submission for the MITRE / IOC mapping exercise. Add one row per IOC and one
row per TTP mapping, keeping the two tables and their four columns each. The
first row of each table is an example; replace it with your own result.

## IOCs

Map every IOC from the threat intel report to one level of the Pyramid of Pain,
and state how long it stays useful as an order of magnitude.

Pyramid of Pain levels, use these exact names: `Hash Values`, `IP Addresses`,
`Domain Names`, `Network/Host Artifacts`, `Tools`, `TTPs`.

Validity: `days`, `weeks`, `months`, `years`.

| IOC | Type | Pyramid of Pain level | Validity |
|-----|------|-----------------------|----------|
| `192.0.2.147` | Command and Control IP | IP Addresses | days |
| `198.51.100.89` | Command and Control IP | IP Addresses | days |
| `203.0.113.221` | Command and Control IP | IP Addresses | days |
| `targetcompany-helpdesk[.]net` | Phishing / C2 Domain | Domain Names | weeks |
| `targetorg-servicedesk[.]com` | Phishing / C2 Domain | Domain Names | weeks |
| `secure-targetname[.]cloud` | Phishing / C2 Domain | Domain Names | weeks |
| `targetcompany-auth[.]org` | Phishing / C2 Domain | Domain Names | weeks |
| `sso-targetorganization[.]net` | Phishing / C2 Domain | Domain Names | weeks |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SystemHealthService` | Registry key | Network/Host Artifacts | months |
| `\Microsoft\Windows\Maintenance\SystemHealthCheck` | Scheduled Task | Network/Host Artifacts | months |
| `Global\SystemHealth Monitor2025` | Mutex Name | Network/Host Artifacts | months |
| `SilentStrike` | Custom Backdoor | Tools | months |
| `VaultBreaker` | Credential Harvesting Tool | Tools | months |
| `PhantomLoader` | Fileless Malware Loader | Tools | months |
| `CryptoVault` | Ransomware Variant | Tools | months |
| `Process Hacker` | Administrative/Abused Tool | Tools | years |
| `RClone` | Exfiltration Tool | Tools | years |
| `ADExplorer` | Discovery Tool | Tools | years |
| `a7c3b5d9e2f4a8b1c6d9e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5` | Malware File Hash | Hash Values | hours |

## TTPs

Map every TTP from the report to a tactic and a technique. All 15 tactics must
appear, and you should reach at least 30 technique mappings.

Tactics, use these exact names: `Reconnaissance` (TA0043),
`Resource Development` (TA0042), `Initial Access` (TA0001), `Execution`
(TA0002), `Persistence` (TA0003), `Privilege Escalation` (TA0004), `Stealth`
(TA0005), `Defense Impairment` (TA0112), `Credential Access` (TA0006),
`Discovery` (TA0007), `Lateral Movement` (TA0008), `Collection` (TA0009),
`Command and Control` (TA0011), `Exfiltration` (TA0010), `Impact` (TA0040).

| Tactic | Technique ID | Technique name | Evidence from the report |
|--------|--------------|----------------|--------------------------|
| Reconnaissance | `T1589.001` | Gather Victim Identity Information: Credentials | Purchasing employee credentials from underground forums |
| Reconnaissance | `T1598.002` | Phishing for Information: Spearphishing Voice | Conducting multi-stage phone campaigns (vishing) targeting help desk staff |
| Reconnaissance | `T1592.002` | Gather Victim Host Information: Software | Gathering information about IT processes and security tools |
| Resource Development | `T1583.001` | Acquire Infrastructure: Domains | Registering domains such as `targetcompany-helpdesk[.]net` |
| Resource Development | `T1588.002` | Obtain Capabilities: Tool | Using commercial VoIP services and custom malware like SilentStrike |
| Resource Development | `T1586.001` | Compromise Accounts: Social Media Accounts | Establishing social media profiles on LinkedIn for false identities |
| Initial Access | `T1566.002` | Phishing: Spearphishing Link | Sending emails appearing to originate from HR with links to fake portals |
| Initial Access | `T1190` | Exploit Public-Facing Application | Exploiting exposed services and VPN endpoints |
| Initial Access | `T1199` | Trusted Relationship | Compromising managed service providers (MSPs) to pivot into client networks |
| Execution | `T1059.001` | Command and Scripting Interpreter: PowerShell | Creating WMI event consumers that execute malicious PowerShell scripts |
| Execution | `T1204.002` | User Execution: Malicious File | Employees clicking on fake benefits enrollment links or training portals |
| Persistence | `T1547.001` | Boot or Logon Autostart Execution: Registry Run Keys | Modifications to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| Persistence | `T1053.005` | Scheduled Task/Job: Scheduled Task | Creating tasks mimicking legitimate Windows processes like SystemMaintenanceTask |
| Persistence | `T1543.003` | Create or Modify System Process: Windows Service | Installing services like Microsoft Update Service or Windows Diagnostic Service |
| Privilege Escalation | `T1548.002` | Abuse Elevation Control Mechanism: Byp | User Account Control | Process hollowing and payload loading via PhantomLoader |
| Privilege Escalation | `T1078.002` | Valid Accounts: Domain Accounts | Utilizing stolen or compromised privileged credentials |
| Stealth | `T1036.004` | Masquerade Task or Service | Scheduled tasks and services named to mimic legitimate Windows processes |
| Stealth | `T1070.004` | Indicator Removal: File Deletion | Clearing Windows Event Logs and staging cleanup |
| Stealth | `T1564.004` | Hide Artifacts: NTFS Data Streams / Hidden Files | Staging data in hidden directories like C:\Windows\Temp\~tmp873 |
| Defense Impairment | `T1562.001` | Impair Defenses: Disable or Modify Tools | Using Process Hacker to disable security software |
| Defense Impairment | `T1070.001` | Indicator Removal: Clear Windows Event Logs | Clearing Windows Event Logs and disabling logging services |
| Credential Access | `T1003` | OS Credential Dumping | Using VaultBreaker targeting password managers |
| Credential Access | `T1110.003` | Brute Force: Password Spraying | Attempting to access exposed services using previously breached credentials |
| Credential Access | `T1558.003` | Steal or Forge Kerberos Tickets: Kerberoasting | Querying Service Principal Names (SPNs) for Kerberoasting |
| Discovery | `T1087.002` | Account Discovery: Domain Account | Enumerating Active Directory using `net group "Domain Admins" /domain` |
| Discovery | `T1018` | Remote System Discovery | Scanning for database servers and backup systems |
| Discovery | `T1083` | File and Directory Discovery | Searching file shares for documents containing passwords and diagrams |
| Lateral Movement | `T1021.001` | Remote Services: Remote Desktop Protocol | Utilizing RDP sessions using compromised accounts |
| Lateral Movement | `T1021.006` | Remote Services: Windows Remote Management | Using WinRM with stolen credentials |
| Lateral Movement | `T1570` | Lateral Tool Transfer | Using PsExec and tools to move laterally |
| Collection | `T1114.002` | Email Collection: Remote Email Collection | Collecting email archives from Exchange servers |
| Collection | `T1074.001` | Data Staged: Local Data Staging | Staging data in hidden directories like `C:\Windows\Temp\~tmp873` |
| Command and Control | `T1071.001` | Application Layer Protocol: Web Protocols | HTTPS uploads to attacker-controlled C2 infrastructure |
| Command and Control | `T1568.002` | Dynamic Resolution: Domain Generation Algorithms | Using newly registered domains for communication |
| Exfiltration | `T1041` | Exfiltration Over C2 Channel | HTTPS uploads of compressed archives to external IP addresses |
| Exfiltration | `T1567.002` | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Uploading data to cloud storage services (Dropbox, OneDrive) using API keys |
| Impact | `T1486` | Data Encrypted for Impact | Deploying CryptoVault ransomware with ChaCha20 encryption |
| Impact | `T1490` | Inhibit System Recovery | Deleting Volume Shadow Copies and system backups |