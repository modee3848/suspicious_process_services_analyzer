# suspicious_process_services_analyzer
A PowerShell script for detecting suspicious processes and services on Windows. It analyzes Sysmon and Windows event logs, flags anomalies (e.g. typosquatting, obfuscation), checks digital signatures, and compares services against an external blacklist. Results are displayed in a report (Out-Grid format) or exported to Excel.
