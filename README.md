Windows Log Triage
A single-file, browser-based tool that reads Windows event logs exported from a SIEM (CSV or Excel) and flags signs of attack: brute force, password spraying, Kerberos abuse, lateral movement, persistence, credential theft, log tampering, malware and ransomware behavior.
Detection runs entirely in your browser. Log data is not uploaded anywhere.
> **Status:** tested with synthetic events and one small NXLog sample (10 Exchange health events). It has not been validated against production Security, Sysmon or Defender logs. Treat alerts as leads to investigate, not verdicts.
Features
Reads `.csv`, `.tsv`, `.xlsx` and `.xls` exports. Multiple files can be loaded at once.
Maps columns automatically, including SIEM-style names such as `@timestamp`, `json_data.EventID` and `json_data.Hostname`.
Reads the raw JSON column that NXLog and similar forwarders include, to recover fields such as `IpAddress`, `TargetUserName`, `LogonType` and `CommandLine`.
About 115 built-in rules, applied automatically when a file loads. Each alert shows severity, MITRE ATT&CK technique, an explanation and the matching events.
A behavior model that flags unusual logon hours, new source addresses per user, and spikes in failed logons.
A timeline of failed logons with alert periods highlighted.
Three detection profiles: Balanced (default), Sensitive and Strict.
Optional AI triage report and follow-up questions (see AI analysis).
Quick start
Save `index.html` (the tool) and open it in a modern browser, or host it with GitHub Pages.
Drop one or more exported log files onto the page.
Review the alerts. Open any alert to see the evidence rows.
No build step, server or install is needed.
Hosting with GitHub Pages
Put `index.html` in the repository root.
Go to Settings > Pages, choose the branch and the root folder, and save.
Open the URL GitHub shows.
The page loads SheetJS (for Excel files) from cdnjs and fonts from Google Fonts. Without internet access, CSV still works but Excel files will not load. For an offline setup, download SheetJS and reference it locally.
Expected input
The file needs at least a timestamp and an event ID per row. Everything else improves detection.
Field	Used for	Example column names
Timestamp	All rules	`@timestamp`, `TimeCreated`, `TimeGenerated`
Event ID	All rules	`EventID`, `event.code`, `json_data.EventID`
Account	Logon rules	`TargetUserName`, `AccountName`
Source address	Brute force, spray, RDP	`IpAddress`, `SourceNetworkAddress`
Host	Lateral movement, grouping	`Computer`, `Hostname`
Logon type, workstation	Logon rules	`LogonType`, `WorkstationName`
Channel	Sysmon, Defender and other channel-specific rules	`Channel`
Message / raw JSON	Command lines, scripts, services	`Message`, `CommandLine`
Some rules need extra fields: `Status`/`SubStatus`, `TicketEncryptionType`, `ServiceName`, `PreAuthType`, `ShareName`, `TargetServerName`, `MemberName`, `LogonProcessName`, `AuthenticationPackageName` and `KeyLength`. If the export drops them, those rules cannot fire.
`siem_sourceip` and similar columns identify the log forwarder, not the attacker, so they are not used as the source address.
Times are converted to your browser's local time.
Log sources to include
Rules only fire for logs that are exported. For best coverage, collect:
Security from domain controllers and servers (4624, 4625, 4648, 4662, 4688 with command-line auditing, 4720, 4728/4732/4756, 4740, 4768, 4769, 4776, 1102 and others).
System (7045, 104, 7040).
Microsoft-Windows-Sysmon/Operational.
Microsoft-Windows-PowerShell/Operational (4103, 4104) with script block logging on.
Microsoft-Windows-Windows Defender/Operational.
TaskScheduler, TerminalServices, AppLocker, Windows Firewall and WMI-Activity where available.
MSExchange Management on Exchange servers.
Detection coverage
Area	Examples
Logon abuse	Brute force, password spraying, username enumeration, success after failures, lockouts and mass lockouts, disabled-account attempts, RDP from public addresses, one account on many addresses or hosts, Guest/Administrator/anonymous/service account misuse

Kerberos and directory	Kerberoasting, AS-REP roasting, DCSync, SID history, rogue computer accounts, AD replication changes, certificate template changes
Lateral movement	Explicit credentials on many targets, admin share access, pass-the-hash pattern, many hosts per account
Persistence	New accounts, privileged group changes, services and scheduled tasks (including suspicious commands), WMI subscriptions, registry Run keys, LSA packages
Defense evasion	Log clearing, logging stopped, audit and firewall changes, Defender disabled, AMSI bypass, timestomping, PowerShell v2 downgrade, log source going silent
Credential theft	Mimikatz and similar tools, LSASS access, SAM/NTDS dumps, shadow copy abuse, WDigest, stored credential harvesting
Execution	Encoded or hidden PowerShell, download cradles, Office or web server starting a shell, living-off-the-land binaries, known offensive tools
Impact	Shadow copy deletion, backup and security services stopped, controlled folder access, data destruction
Exfiltration and C2	Tunneling tools, archiving and upload tools, abused DNS services, known C2 pipe names
Exchange	Mailbox export, forwarding rules, role assignments
Health	Repeated errors from one source
The full list is shown in the app under View all rules.
Detection profiles
Profile	Failed logons	Window	Spray accounts	Many hosts	Alerts trigger at
Balanced	10	5 min	5	8	High
Sensitive	5	10 min	3	5	Medium
Strict	20	5 min	8	12	Critical
Severity
1 = low, 2 = medium, 3 = high, 4 = critical. The banner at the top counts alerts at or above the profile's trigger level.
AI analysis
The page can ask Claude to write a triage report (summary, likely attack story, ATT&CK techniques, ordered response steps, possible false positives) and answer follow-up questions. Only a summary of the top alerts is sent, never the raw log rows.
This feature uses the runtime built into claude.ai artifacts. When the page is hosted on GitHub Pages or opened as a local file, the AI buttons and the JSON export will not work, and the page shows a message instead. All detection still works. To enable AI in a standalone deployment, replace the `ai()` function with a call to your own backend that holds an API key. Do not put an API key in browser code.
Adding or changing rules
Rules are plain arrays in the script section of `index.html`.
Single-event rule (`R`):
```js
// [event IDs separated by |, channel regex or '', severity 1-4, title, MITRE, explanation]
R.push(['4720','',2,'User account created','Persistence (T1136)','Confirm this was an approved change.']);
```
Command line or script rule (`C`), tested against process creation (4688), PowerShell (4103, 4104), Sysmon event 1 and Exchange management logs:
```js
// [regex, severity 1-4, title, MITRE]
C.push([/vssadmin.*delete\s+shadows/i,4,'Shadow copy deletion','Impact (T1490)']);
```
Correlation rules (counts within a time window, rare values, sequences) live in `detect()` and `extra()`.
Limitations
Detection is rule-based and depends on what the SIEM exports. Missing channels or fields mean missing detections.
Admin and backup tooling can match some patterns (for example Exchange administration and PowerShell remoting). Alerts say to verify who ran the activity.
The behavior model needs enough history per user (15 or more logons) to be meaningful.
Alerts exist only in the page. There is no email, Slack or webhook delivery. Use the JSON export in claude.ai, or extend the code, to feed other tools.
Large files are parsed in the browser and can be slow or memory-heavy.
Suggested repository layout
```
.
├── index.html   # the tool
├── README.md
└── LICENSE
```
Contributing
Issues and pull requests are welcome, especially:
Rules with sample events and the false-positive cases you found.
Field-name mappings for other SIEM export formats.
A standalone download fallback for alerts and a pluggable AI backend.
Disclaimer
This tool is for defensive security monitoring of systems you are authorized to review. It is not a replacement for a SIEM, EDR or an incident response process.
