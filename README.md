# suspicious_process_services_analyzer
A PowerShell script for detecting suspicious processes and services on Windows. It analyzes Sysmon and Windows event logs, flags anomalies (e.g. typosquatting, obfuscation), checks digital signatures, and compares services against an external blacklist. Results are displayed in a report (Out-Grid format) or exported to Excel.

Windows Logs (Security/System):
4688: Process Creation
7045 / 4697: Service Installation/Creation
4657: Registry Modification
5156: Network Traffic Allowed (Filtering Platform)
5145: File/Folder Access (File Share)
4624: Logon Success
4648: Explicit Credential Logon
Sysmon Logs (Microsoft-Windows-Sysmon/Operational):
ID=1: Process Creation
ID=3: Network Connection
ID=13: Registry Modification (e.g., Services key changes)
Local Anomaly Rules (10 Total):
Vulnerable Service: Process outside trusted paths started by services.exe.
Named Pipe / COMSPEC: Detects \\.\pipe or %COMSPEC% references.
sc.exe create: Captures service creation via sc.exe.
Temp Service: Temporary service changing state from OnDemand to Disabled quickly.
Suspicious exe in Service Config: Executable in service parameters (IDs 4697/7045).
Non-Standard Path: Executable outside standard system paths.
Typosquatting: Detects files like svch0st.exe, explor.exe, etc.
Unusual Shell: Detects uncommon shells.
Suspicious Arguments: Flags arguments like -nop, -w hidden, encodedcommand, invoke-webrequest.
Macro Attack: Detects winword.exe launching cmd.exe or powershell.exe.
Remote Pattern Rules (5 Total, R1-R5):
R1: 5156 → 7045/4697: Service creation detected after ephemeral port traffic.
R2: ID=13 → ID=3: Registry key modification followed by network traffic from services.exe.
R3: 5145 (admin$) → IPC$ / svcctl: Resource sharing followed by service manipulation.
R4: 4624 (Logon Type 3) → 4697: Service creation within the same session in 1 min.
R5: 4648: Use of sc.exe in a remote context (Target Server ≠ localhost).
