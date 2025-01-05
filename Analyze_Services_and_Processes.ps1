[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [String[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [string]$Filename
)

################################################################################
# Functions to get Windows Events and Sysmon logs
################################################################################

Function Get-EventsByID {
    param(
        [int[]]$EventIds,
        [string[]]$LogNames = @("Security","System"),
        [int]$Newest = 1000
    )
    $results = @()
    foreach ($log in $LogNames) {
        try {
            Write-Verbose "Reading Log: $log (Newest=$Newest) for EventID in $($EventIds -join ',')"
            $tempAll = Get-EventLog -LogName $log -Newest $Newest -ErrorAction SilentlyContinue
            if ($tempAll) {
                $filtered = $tempAll | Where-Object { $_.EventID -in $EventIds }
                if ($filtered) {
                    $results += $filtered
                }
            }
        }
        catch {
            Write-Warning "Failed to read log '$log'. Error: $_"
        }
    }
    return $results
}

Function Get-SysmonEvents {
    param(
        [int[]]$EventIdsSysmon,
        [int]$MaxEvents = 1000
    )
    $resultsSys = @()

    foreach ($eid in $EventIdsSysmon) {
        try {
            $evts = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
                                 -MaxEvents $MaxEvents `
                                 -FilterXPath "*[System[EventID=$eid]]" `
                                 -ErrorAction SilentlyContinue
            if ($evts) {
                $resultsSys += $evts
            }
        }
        catch {
            Write-Warning "Failed to read Sysmon event ID=$eid. Error: $_"
        }
    }
    return $resultsSys
}

################################################################################
# CSV - External source
################################################################################

$suspiciousServicesUrl  = "https://raw.githubusercontent.com/mthcht/awesome-lists/cda2a08a9c3a4805745c8d56ff88a6fce043cadf/Lists/suspicious_windows_services_names_list.csv"
$tempDir                = "$env:TEMP\ServiceAnalysis"
$suspiciousServicesPath = Join-Path -Path $tempDir -ChildPath "suspicious_services.csv"

if (-not (Test-Path -Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
}

try {
    Write-Host "Downloading suspicious services list..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $suspiciousServicesUrl -OutFile $suspiciousServicesPath -ErrorAction Stop
    Write-Host "Suspicious services list downloaded." -ForegroundColor Green
}
catch {
    Write-Warning "Failed to download suspicious services list."
    return
}

$suspiciousServices = @()
if (Test-Path $suspiciousServicesPath) {
    $suspiciousServices = Import-Csv -Path $suspiciousServicesPath | Select-Object -ExpandProperty service_name
}



################################################################################
# Function: PARSE-PROCESSFIELDS (for raporting purpose Process/CommandLine/Parent)
################################################################################

Function Parse-ProcessFields {
    param(
        [Parameter(Mandatory=$true)]
        [Object]$EventItem
    )

    # PSCustomObject - fields: ImageName, CommandLine, ParentImage, TimeGenerated, EventID
    $result = [PSCustomObject]@{
        ImageName    = ""
        CommandLine  = ""
        ParentImage  = ""
        TimeGenerated= $EventItem.TimeCreated
        EventID      = $EventItem.Id
    }

    if ($EventItem.ProviderName -eq "Microsoft-Windows-Sysmon") {
        # Sysmon
        $xml = [XML]$EventItem.ToXml()
        $datas = $xml.Event.EventData.Data
        $imgN = $datas | Where-Object { $_.Name -eq 'Image' }
        $cmdN = $datas | Where-Object { $_.Name -eq 'CommandLine' }
        $pimN= $datas | Where-Object { $_.Name -eq 'ParentImage' }

        $result.ImageName   = $imgN.'#text'
        $result.CommandLine = $cmdN.'#text'
        $result.ParentImage = $pimN.'#text'
    }
    else {
        # Windows fallback
        $msgLower = ($EventItem.Message + "").ToLower()
        $result.ImageName   = ($msgLower | Select-String -Pattern "new process name:\s+(.*)"    | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ""
        $result.CommandLine = ($msgLower | Select-String -Pattern "command line:\s+(.*)"        | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ""
        $result.ParentImage = ($msgLower | Select-String -Pattern "parent process name:\s+(.*)" | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ""
        $result.TimeGenerated= $EventItem.TimeGenerated
        $result.EventID     = $EventItem.EventID
    }

    return $result
}

################################################################################
# Main Function: DETECT-SUSPICIOUS_ACTIVITY
################################################################################

Function Detect-SuspiciousActivity {
    Write-Host "Analyzing system for various suspicious activity indicators..." -ForegroundColor Green

    $trustedPaths = @(
        "C:\windows\system32\*",
        "C:\windows\System32\*",
        "C:\windows\syswow64\*",
        "C:\windows\servicing\*",
        "C:\ProgramData\Microsoft\Windows Defender\*",
        "C:\WINDOWS\CCmsetup\*",
        "C:\windows\ccm\*",
        "C:\WINDOWS\Microsoft.Net\Framework\*",
        "C:\WINDOWS\Microsoft.Net\Framework64\*"
		"C:\Program Files (x86)\Microsoft\EdgeUpdate\*"
    )

    $suspiciousExecutables2 = @(
        "cmd.exe",
        "powershell.exe",
        "cscript.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "regsvcs.exe",
        "regasm.exe",
        "wmic.exe"
    )

    Write-Host "Getting multiple Event Logs (Security / System) + Sysmon for suspicious activity..." -ForegroundColor Yellow

    # Windows
    $all4688       = Get-EventsByID -EventIds 4688 -LogNames @("Security","System")
    $all7045_4697  = Get-EventsByID -EventIds @(7045,4697) -LogNames @("Security","System")
    $all4657       = Get-EventsByID -EventIds 4657 -LogNames @("Security","System")
    $all5156       = Get-EventsByID -EventIds 5156 -LogNames @("Security","System")
    $all5145       = Get-EventsByID -EventIds 5145 -LogNames @("Security","System")
    $all4624       = Get-EventsByID -EventIds 4624 -LogNames @("Security","System")
    $all4697_only  = Get-EventsByID -EventIds 4697 -LogNames @("Security","System")
    $all4648       = Get-EventsByID -EventIds 4648 -LogNames @("Security","System")

    # Sysmon
    $sysmon1  = Get-SysmonEvents -EventIdsSysmon 1
    $sysmon3  = Get-SysmonEvents -EventIdsSysmon 3
    $sysmon13 = Get-SysmonEvents -EventIdsSysmon 13

    # INFO
    if (-not $all4688)      { Write-Host "No Windows events with ID=4688" -ForegroundColor Yellow }
    if (-not $all7045_4697) { Write-Host "No Windows events with ID=7045/4697" -ForegroundColor Yellow }
    if (-not $all4657)      { Write-Host "No Windows events with ID=4657" -ForegroundColor Yellow }
    if (-not $all5156)      { Write-Host "No Windows events with ID=5156" -ForegroundColor Yellow }
    if (-not $all5145)      { Write-Host "No Windows events with ID=5145" -ForegroundColor Yellow }
    if (-not $all4624)      { Write-Host "No Windows events with ID=4624" -ForegroundColor Yellow }
    if (-not $all4697_only) { Write-Host "No Windows events with ID=4697" -ForegroundColor Yellow }
    if (-not $all4648)      { Write-Host "No Windows events with ID=4648" -ForegroundColor Yellow }

    if (-not $sysmon1)      { Write-Host "No Sysmon logs ID=1 found" -ForegroundColor Yellow }
    if (-not $sysmon3)      { Write-Host "No Sysmon logs ID=3 found" -ForegroundColor Yellow }
    if (-not $sysmon13)     { Write-Host "No Sysmon logs ID=13 found" -ForegroundColor Yellow }

    ############################################################################
    # 1) Vulnerable Service
    ############################################################################

    [System.Collections.ArrayList]$colRule1 = New-Object System.Collections.ArrayList

    if ($sysmon1 -and $sysmon1.Count -gt 0) {
        foreach ($evtSys1 in $sysmon1) {
            $parsed1 = Parse-ProcessFields -EventItem $evtSys1
            if ($parsed1.ParentImage.ToLower().Contains("services.exe")) {
                # check trusted
                $isTrusted = $false
                foreach ($tp in $trustedPaths) {
                    if ($parsed1.ImageName -like $tp.ToLower()) {
                        $isTrusted = $true
                        break
                    }
                }
                if (-not $isTrusted) {
                    [void]$colRule1.Add($parsed1)
                }
            }
        }
    }

    if (($colRule1.Count -eq 0) -and $all4688) {
        # fallback
        foreach ($ev4688 in $all4688) {
            if ($ev4688.Message -and $ev4688.Message -match "Parent Process Name:\s+services\.exe") {
                $p = Parse-ProcessFields -EventItem $ev4688
                $isTrusted = $false
                foreach ($tp in $trustedPaths) {
                    if ($p.ImageName -like $tp.ToLower()) {
                        $isTrusted = $true
                        break
                    }
                }
                if (-not $isTrusted) {
                    [void]$colRule1.Add($p)
                }
            }
        }
    }

    ############################################################################
    # 2) Named Pipe / COMSPEC (7045/4697) => ewent. Sysmon1 -> fallback 7045/4697
    ############################################################################

    [System.Collections.ArrayList]$colRule2 = New-Object System.Collections.ArrayList

    if ($sysmon1 -and $sysmon1.Count -gt 0) {
        foreach ($evS1 in $sysmon1) {
            $pp = Parse-ProcessFields -EventItem $evS1
            if ($pp.CommandLine -match "\\\\.\\pipe" -or $pp.CommandLine -match "%comspec%") {
                [void]$colRule2.Add($pp)
            }
        }
    }

    if (($colRule2.Count -eq 0) -and $all7045_4697) {
        foreach ($evP in $all7045_4697) {
            if ($evP.Message -match "\\\\.\\pipe" -or $evP.Message -match "%COMSPEC%") {
                $p2 = Parse-ProcessFields -EventItem $evP
                [void]$colRule2.Add($p2)
            }
        }
    }

    ############################################################################
    # 3) sc.exe => Sysmon ID=1 fallback 4688
    ############################################################################

    [System.Collections.ArrayList]$colRule3 = New-Object System.Collections.ArrayList

    if ($sysmon1 -and $sysmon1.Count -gt 0) {
        foreach ($eSc in $sysmon1) {
            $parsed3 = Parse-ProcessFields -EventItem $eSc
            if ($parsed3.ImageName -like "*\sc.exe" -and $parsed3.CommandLine -like "*create*") {
                [void]$colRule3.Add($parsed3)
            }
        }
    }

    if (($colRule3.Count -eq 0) -and $all4688) {
        foreach ($ev4688sc in $all4688) {
            if ($ev4688sc.Message -match "sc.exe" -and $ev4688sc.Message -match "create") {
                $pp3 = Parse-ProcessFields -EventItem $ev4688sc
                [void]$colRule3.Add($pp3)
            }
        }
    }

    ############################################################################
    # 4) Temp Service => Sysmon ID=13 fallback 4657
    ############################################################################

    [System.Collections.ArrayList]$colRule4 = New-Object System.Collections.ArrayList
    if ($sysmon13 -and $sysmon13.Count -gt 0) {
        $serviceMods = @{}
        foreach ($ev13 in $sysmon13) {
            # parse
            $parsed13 = Parse-ProcessFields -EventItem $ev13
            $xml13 = [XML]$ev13.ToXml()
            $datas13 = $xml13.Event.EventData.Data
            $regKey  = ($datas13 | Where-Object { $_.Name -eq 'TargetObject' }).'#text'
            $details = ($datas13 | Where-Object { $_.Name -eq 'Details' }).'#text'

            if ($regKey -and $details -and $regKey.ToLower() -match "currentcontrolset\\services\\(.+)\\start") {
                if ($details -match "0x00000003") {
                    $serviceMods[$regKey] = [PSCustomObject]@{
                        TimeGenerated = $ev13.TimeCreated
                        ImageName     = $parsed13.ImageName
                        CmdLine       = $parsed13.CommandLine
                        Parent        = $parsed13.ParentImage
                    }
                }
                elseif ($details -match "0x00000004") {
                    if ($serviceMods.ContainsKey($regKey)) {
                        $t0 = $serviceMods[$regKey].TimeGenerated
                        $diff = ($ev13.TimeCreated - $t0).TotalSeconds
                        if ($diff -le 60) {
                            $rec4 = [PSCustomObject]@{
                                TimeGenerated = $ev13.TimeCreated
                                EventID       = $parsed13.EventID
                                Type          = "4 - Temp Service"
                                Message       = "TempService for $regKey within 1min OnDemand->Disabled via process=$($serviceMods[$regKey].ImageName)"
                            }
                            [void]$colRule4.Add($rec4)
                        }
                    }
                }
            }
        }
    }

    # Fallback to 4657
    if (($colRule4.Count -eq 0) -and $all4657) {
        $svcMods = @{}
        foreach ($ev4657 in $all4657) {
            if (-not $ev4657.Message) { continue }
            $parsed4657 = Parse-ProcessFields -EventItem $ev4657
            $msg4 = $ev4657.Message
            $targetObj = ($msg4 | Select-String -Pattern "TargetObject:\s+(.*)" | ForEach-Object { $_.Matches[0].Groups[1].Value })
            $newVal    = ($msg4 | Select-String -Pattern "(New Value|Details):\s+(0x[0-9A-Fa-f]+)" | ForEach-Object { $_.Matches[0].Groups[2].Value })
            if ($targetObj -and $newVal) {
                $nV = $newVal.ToLower()
                if ($nV -eq "0x00000003") {
                    $svcMods[$targetObj] = [PSCustomObject]@{
                        TimeGenerated = $ev4657.TimeGenerated
                        ImageName     = $parsed4657.ImageName
                        CmdLine       = $parsed4657.CommandLine
                        Parent        = $parsed4657.ParentImage
                    }
                }
                elseif ($nV -eq "0x00000004") {
                    if ($svcMods.ContainsKey($targetObj)) {
                        $tOn = $svcMods[$targetObj].TimeGenerated
                        $delta = ($ev4657.TimeGenerated - $tOn).TotalSeconds
                        if ($delta -le 60) {
                            $recFall = [PSCustomObject]@{
                                TimeGenerated = $ev4657.TimeGenerated
                                EventID       = $parsed4657.EventID
                                Type          = "4 - Temp Service"
                                Message       = "TempService for $targetObj in 1min OnDemand->Disabled via process=$($svcMods[$targetObj].ImageName)"
                            }
                            [void]$colRule4.Add($recFall)
                        }
                    }
                }
            }
        }
    }

    if ($colRule4.Count -eq 0) {
        $colRule4 += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "4 - Temp Service"
            Message       = "No 'Temp Service' pattern detected."
        }
    }


    # =================================================
    # 5) Suspicious exe in service installation (4697/7045)
    # =================================================
    $eventSuspProcService = $null
    if ($all7045_4697) {
        $eventSuspProcService = $all7045_4697 | Where-Object {
            $line = $_.Message.ToLower()
            $found = $false
            foreach ($exe in $suspiciousExecutables2) {
                if ($line -match $exe) {
                    $found = $true
                    break
                }
            }
            $found
        }
    }


    $foundAny6   = $false; $results6   = @()
    $foundAny7   = $false; $results7   = @()
    $foundAny8   = $false; $results8   = @()
    $foundAny9   = $false; $results9   = @()
    $foundAny10  = $false; $results10  = @()

    $commonProcessPaths = @(
        "C:\Windows\system32\",
		"C:\Windows\System32\WindowsPowerShell",
        "C:\Windows\syswow64",
        "C:\Windows\Servicing",
        "C:\Windows\Ccm",
        "C:\Windows\Ccmsetup",
        "C:\Windows\Microsoft.net\Framework",
        "C:\Windows\Microsoft.net\Framework64",
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\ProgramData\Microsoft\Windows Defender"
		"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
		"C:\Windows\WinSxS\"
		"C:\Windows\Sysmon.exe"
    )
    $monitoredExtensions = @(".exe",".com",".bat",".cmd",".ps1",".vbs",".js",".hta",".scr",".dll")
    $typoRegex = @(
   'svch0st\.exe$',
   'svchost32\.exe$',
    'explor\.exe$',
     'run(dl|ll)132\.exe$',
     'rundl123\.exe$',
    'regsvrr(3|4)2\.exe$',
    'regsv[c|s]\.exe$',
    'lsasss?\.exe$',
    'cmd32\.exe$',
    'p0wershell\.exe$',
    'powershel1\.exe$',
    'scvhost\.exe$' 
    ) -join '|'
    $unusualShells = @("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","powershell_ise.exe")
    $suspiciousArgPatterns = @(
        "encodedcommand","-nop","-w hidden","-noexit","executionpolicy bypass",
        "invoke-webrequest","invoke-expression","downloadstring","downloadfile",
        "add-type","net user","net localgroup","startupinfo","start-process",
        "start-transcript","iex ","curl ","wget "
    )

    # --- Creating list to analyze from Sysmon ID=1 (or fallback to event id 4688):
    $allSysmonToCheck = $null
    if ($sysmon1 -and $sysmon1.Count -gt 0) {
        $allSysmonToCheck = $sysmon1
        Write-Host "Using Sysmon (EventID=1) for advanced process creation info." -ForegroundColor Cyan
    }
    else {
        $allSysmonToCheck = $all4688
        Write-Host "No Sysmon ID=1 logs found, fallback to Windows Event 4688 for process creation." -ForegroundColor Yellow
    }

    if ($allSysmonToCheck) {
        foreach ($evt in $allSysmonToCheck) {
            if ($evt.ProviderName -eq "Microsoft-Windows-Sysmon") {

                $xml = [XML]$evt.ToXml()
                $datas = $xml.Event.EventData.Data

                $imageNameNode   = $datas | Where-Object { $_.Name -eq 'Image' }
                $commandLineNode = $datas | Where-Object { $_.Name -eq 'CommandLine' }
                $parentImageNode = $datas | Where-Object { $_.Name -eq 'ParentImage' }

                $imageName   = $imageNameNode.'#text'
                $commandLine = $commandLineNode.'#text'
                $parentImage = $parentImageNode.'#text'

            }
            else {
                $msgLower = ($evt.Message + "").ToLower() 
                $imageName   = ($msgLower | Select-String -Pattern "new process name:\s+(.*)"    | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ""
                $commandLine = ($msgLower | Select-String -Pattern "command line:\s+(.*)"        | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ""
                $parentImage = ($msgLower | Select-String -Pattern "parent process name:\s+(.*)" | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ""
            }

            if (-not $imageName)   { $imageName   = "" }
            if (-not $commandLine) { $commandLine = "" }
            if (-not $parentImage) { $parentImage = "" }

            # (6) Non-Standard Path
$extension = "unknown"
try {
    if ($imageName -and $imageName -notmatch '[<>:"/\\|?*]') {
       
    }
}
catch {
    Write-Warning "Error extracting extension from: $imageName"
}

$isNonTrustedPath = $true
 $extension = [System.IO.Path]::GetExtension($imageName).ToLower()
 
foreach ($cp in $commonProcessPaths) {
    if ($imageName -like "$cp*") {
        $isNonTrustedPath = $false
        break
    }
}

if ($isNonTrustedPath -and ($extension -in $monitoredExtensions) -and ($imageName -ne "")) {
    $foundAny6 = $true
    $results6 += [PSCustomObject]@{
        TimeGenerated = $evt.TimeCreated
        EventID       = $evt.Id
        Type          = "6 - Non-Standard Path"
        Message       = "Process $imageName (ext: $extension) from untrusted path. Parent: $parentImage"
    }
}


            # (7) Typosquatting
            if ($imageName -match $typoRegex) {
                $foundAny7 = $true
                $results7 += [PSCustomObject]@{
                    TimeGenerated = $evt.TimeCreated
                    EventID       = $evt.Id
                    Type          = "7 - Typosquatting"
                    Message       = "Process $imageName matches known typosquatting pattern. Command Line: $commandLine Parent: $parentImage"
                }
            }

# (8) Unusual Shell
$exeNameOnly = ""
try {
    $exeNameOnly = [System.IO.Path]::GetFileName($imageName)
}
catch {
    Write-Warning "Error processing GetFileName for: $imageName"
}

$allowedShells = @(
    @{ Process = "powershell.exe"; Path = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" },
    @{ Process = "cmd.exe"; Path = "C:\Windows\System32\cmd.exe" }
)

$isAllowed = $false
foreach ($allowed in $allowedShells) {
    if ($exeNameOnly -ieq $allowed.Process -and $imageName -ieq $allowed.Path) {
        $isAllowed = $true
        break
    }
}

if ($exeNameOnly -and ($exeNameOnly -in $unusualShells) -and -not $isAllowed) {
    $foundAny8 = $true
    $results8 += [PSCustomObject]@{
        TimeGenerated = $evt.TimeCreated
        EventID       = $evt.Id
        Type          = "8 - Unusual Shell Process"
        Message       = "Shell $exeNameOnly -> Path: $imageName, Command line: $commandLine Parent: $parentImage"
    }
}
            # (9) Suspicious Arguments
            $foundSusArg = $false
            foreach ($argPattern in $suspiciousArgPatterns) {
                if ($commandLine.ToLower() -match $argPattern) {
                    $foundSusArg = $true
                    break
                }
            }
            if ($foundSusArg) {
                $foundAny9 = $true
                $results9 += [PSCustomObject]@{
                    TimeGenerated = $evt.TimeCreated
                    EventID       = $evt.Id
                    Type          = "9 - Suspicious Arguments"
                    Message       = "Process $imageName with suspicious cmdline: $commandLine. Parent: $parentImage"
                }
            }

            # (10) Macro Attack
            if ($parentImage.ToLower() -match "winword.exe" -and ($exeNameOnly -and $exeNameOnly -in $unusualShells)) {
                $foundAny10 = $true
                $results10 += [PSCustomObject]@{
                    TimeGenerated = $evt.TimeCreated
                    EventID       = $evt.Id
                    Type          = "10 - Macro Attack Suspected"
                    Message       = "Office doc (winword.exe) launched shell: $imageName"
                }
            }
        }
    }

    if (-not $foundAny6) {
        $results6 += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "Info"
            Message       = "No suspicious processes found (Non-Standard Path)."
        }
    }
    if (-not $foundAny7) {
        $results7 += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "Info"
            Message       = "No suspicious processes found (Typosquatting)."
        }
    }
    if (-not $foundAny8) {
        $results8 += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "Info"
            Message       = "No suspicious processes found (Unusual Shell)."
        }
    }
    if (-not $foundAny9) {
        $results9 += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "Info"
            Message       = "No suspicious processes found (Suspicious Arguments)."
        }
    }
    if (-not $foundAny10) {
        $results10 += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "Info"
            Message       = "No suspicious processes found (Macro Attack)."
        }
    }

    $results6_10 = @()
    $results6_10 += $results6
    $results6_10 += $results7
    $results6_10 += $results8
    $results6_10 += $results9
    $results6_10 += $results10

    # =================================================
    # R1->R5 (Remote Service Patterns)
    # =================================================

    $r1_detected = $false
    if ($all5156 -and $all7045_4697) {
        foreach ($e1 in $all5156) {
            if (-not $e1.Message) { continue }
            $line = $e1.Message.ToLower()
            $sourcePortMatch      = ($line | Select-String -Pattern "sourceport:\s+(\d+)"      | ForEach-Object { $_.Matches[0].Groups[1].Value })
            $destinationPortMatch = ($line | Select-String -Pattern "destinationport:\s+(\d+)" | ForEach-Object { $_.Matches[0].Groups[1].Value })
            if ($sourcePortMatch -and $destinationPortMatch) {
                $sourcePort      = [int]$sourcePortMatch
                $destinationPort = [int]$destinationPortMatch

                if ($line -match "services.exe" -and
                    $line -match "sourceaddress:\s+null" -and
                    $line -match "destinationaddress:\s+null" -and
                    $sourcePort -ge 49152 -and $sourcePort -le 65535 -and
                    $destinationPort -ge 49152 -and $destinationPort -le 65535) {

                    $cname   = $e1.MachineName
                    $t1      = $e1.TimeGenerated
                    $followup= $all7045_4697 | Where-Object {
                        $_.MachineName -eq $cname -and
                        (($_.TimeGenerated - $t1).TotalSeconds -le 60)
                    }
                    if ($followup) {
                        $r1_detected = $true
                        break
                    }
                }
            }
        }
    }
    if ($r1_detected) {
        $r1_message = "Suspicious remote service pattern (5156->7045/4697) with ephemeral ports detected."
    }
    else {
        $r1_message = "No suspicious remote service pattern (5156->7045/4697) with ephemeral ports detected."
    }

$r2_detected = $false
if ($sysmon13 -and $sysmon3) {
    foreach ($event13 in $sysmon13) {
        $xml13 = [XML]$event13.ToXml()
        $targetObject = ($xml13.Event.EventData.Data | Where-Object { $_.Name -eq "TargetObject" }).'#text'

        if ($targetObject -like "HKLM\System\CurrentControlSet\Services\*") {
            $t1 = $event13.TimeCreated
            $machineName = $event13.MachineName

            $matchingEvent3 = $sysmon3 | Where-Object {
                $_.MachineName -eq $machineName -and
                ($_.TimeCreated - $t1).TotalSeconds -le 60
            }

            foreach ($event3 in $matchingEvent3) {
                $xml3 = [XML]$event3.ToXml()
                $sourceIP = ($xml3.Event.EventData.Data | Where-Object { $_.Name -eq "SourceIp" }).'#text'
                $destinationIP = ($xml3.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationIp" }).'#text'
                $sourcePort = ($xml3.Event.EventData.Data | Where-Object { $_.Name -eq "SourcePort" }).'#text'
                $destinationPort = ($xml3.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationPort" }).'#text'
                $image = ($xml3.Event.EventData.Data | Where-Object { $_.Name -eq "Image" }).'#text'

                if ($sourceIP -ne $destinationIP -and
                    $sourceIP -ne "null" -and
                    $destinationIP -ne "null" -and
                    $sourcePort -ge 49152 -and $sourcePort -le 65535 -and
                    $destinationPort -ge 49152 -and $destinationPort -le 65535 -and
                    $image -like "*\services.exe") {

                    $r2_detected = $true
                        $r2_message = "EventID=13 with TargetObject=$targetObject followed by EventID=3 with Image=$image, SourceIP=$sourceIP, DestinationIP=$destinationIP, SourcePort=$sourcePort, DestinationPort=$destinationPort within 1 minute on $machineName."
                    }
                }
            }
        }
    }


if (-not $r2_detected) {
        $r2_message = "No suspicious pattern (13->3) detected."
    }

    $r3_detected = $false
    if ($all5145) {
        $adminCSet = $all5145 | Where-Object {
            $_.Message -match "writedata" -and
            ($_.Message -match "\\admin\$" -or $_.Message -match "\\c\$")
        }
        if ($adminCSet) {
            foreach ($a1 in $adminCSet) {
                if (-not $a1.Message) { continue }
                $a1Line = $a1.Message.ToLower()
                $cname  = $a1.MachineName
                $acct   = ($a1Line | Select-String "accountname:\s+(.*)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })
                $saddr  = ($a1Line | Select-String "sourceaddress:\s+(.*)"| ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })
                $sport  = ($a1Line | Select-String "sourceport:\s+(.*)"   | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })

                if (-not $acct)  { $acct  = "" }
                if (-not $saddr) { $saddr = "" }
                if (-not $sport) { $sport = "" }

                $t1 = $a1.TimeGenerated
                $ipcFollow = $all5145 | Where-Object {
                    $_.MachineName -eq $cname -and
                    (($_.TimeGenerated - $t1).TotalSeconds -le 60) -and
                    $_.Message -match "\\ipc\$" -and
                    $_.Message -match "relativetargetname:\s+svcctl" -and
                    $_.Message -match $acct -and
                    $_.Message -match $saddr -and
                    $_.Message -match $sport
                }
                if ($ipcFollow) {
                    $r3_detected = $true
                    break
                }
            }
        }
    }
    if ($r3_detected) {
        $r3_message = "Suspicious admin share to IPC$ pattern detected (5145) with RelativeTargetName: svcctl."
    }
    else {
        $r3_message = "No suspicious admin->IPC$ (with svcctl) pattern detected."
    }

    $r4_detected = $false
    if ($all4624 -and $all4697_only) {
        foreach ($l1 in $all4624) {
            if (-not $l1.Message) { continue }
            if ($l1.Message -match "logon type:\s+3") {
                $logonId = ($l1.Message | Select-String "Logon ID:\s+(0x[0-9a-f]+)" | ForEach-Object { $_.Matches[0].Groups[1].Value })
                if ($logonId) {
                    $t1 = $l1.TimeGenerated
                    $follow4697 = $all4697_only | Where-Object {
                        ($_.TimeGenerated - $t1).TotalSeconds -le 60 -and $_.Message -match $logonId
                    }
                    if ($follow4697) {
                        $r4_detected = $true
                        break
                    }
                }
            }
        }
    }
    if ($r4_detected) {
        $r4_message = "Suspicious pattern: LogonType=3 (4624) followed by 4697 same LogonId in 1 min."
    }
    else {
        $r4_message = "No (4624->4697) LogonId pattern detected."
    }

    $r5_detected = $false
    if ($all4648) {
        foreach ($ev in $all4648) {
            if (-not $ev.Message) { continue }
            $line = $ev.Message.ToLower()
            if ($line -match "c:\\windows\\system32\\sc.exe") {
                $targetServer = ($line | Select-String "target server:\s+(.*)" | ForEach-Object { $_.Matches[0].Groups[1].Value.ToLower() })
                if ($targetServer -and $targetServer -notin @("localhost","-","")) {
                    $r5_detected = $true
                    break
                }
            }
        }
    }
    if ($r5_detected) {
        $r5_message = "Suspicious 4648 (sc.exe remote) pattern detected."
    }
    else {
        $r5_message = "No suspicious 4648 (sc.exe remote) pattern."
    }

    $allSuspiciousEvents = @()

    # (1) Vulnerable Service (z $colRule1)
    if ($colRule1.Count -gt 0) {
        foreach ($p1 in $colRule1) {
            $allSuspiciousEvents += [PSCustomObject]@{
                TimeGenerated = $p1.TimeGenerated
                EventID       = $p1.EventID
                Type          = "1 - Vulnerable Service"
                Message       = "Process=$($p1.ImageName), CommandLine=$($p1.CommandLine), Parent=$($p1.ParentImage)"
            }
        }
    }
    else {
        $allSuspiciousEvents += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "1 - Vulnerable Service"
            Message       = "No suspicious service creation detected (#1)."
        }
    }

    # (2) Named Pipe
    if ($colRule2.Count -gt 0) {
        foreach ($p2 in $colRule2) {
            $allSuspiciousEvents += [PSCustomObject]@{
                TimeGenerated = $p2.TimeGenerated
                EventID       = $p2.EventID
                Type          = "2 - Named Pipe / COMSPEC"
                Message       = "Process=$($p2.ImageName), CommandLine=$($p2.CommandLine), Parent=$($p2.ParentImage)"
            }
        }
    }
    else {
        $allSuspiciousEvents += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "2 - Named Pipe / COMSPEC"
            Message       = "No named pipe client impersonation (#2)."
        }
    }

    # (3) sc.exe
    if ($colRule3.Count -gt 0) {
        foreach ($p3 in $colRule3) {
            $allSuspiciousEvents += [PSCustomObject]@{
                TimeGenerated = $p3.TimeGenerated
                EventID       = $p3.EventID
                Type          = "3 - Suspicious sc.exe usage"
                Message       = "Process=$($p3.ImageName), CommandLine=$($p3.CommandLine), Parent=$($p3.ParentImage)"
            }
        }
    }
    else {
        $allSuspiciousEvents += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "3 - Suspicious sc.exe usage"
            Message       = "No sc.exe create usage (#3)."
        }
    }

    # (4) Temp Service ($colRule4)
    foreach ($r4 in $colRule4) {
        $allSuspiciousEvents += $r4
    }

    # (5) Suspicious exe in service
    if ($eventSuspProcService) {
        foreach ($evSPS in $eventSuspProcService) {
            $allSuspiciousEvents += [PSCustomObject]@{
                TimeGenerated = $evSPS.TimeGenerated
                EventID       = $evSPS.EventID
                Type          = "5 - Suspicious exe in service (4697/7045)"
                Message       = $evSPS.Message
            }
        }
    }
    else {
        $allSuspiciousEvents += [PSCustomObject]@{
            TimeGenerated = (Get-Date)
            EventID       = "N/A"
            Type          = "Suspicious exe in service (4697/7045)"
            Message       = "No suspicious exe in 4697/7045 events."
        }
    }
    # R1->R5
    $allSuspiciousEvents += [PSCustomObject]@{
        TimeGenerated = (Get-Date)
        EventID       = "N/A"
        Type          = "Info R1"
        Message       = $r1_message
    }
    $allSuspiciousEvents += [PSCustomObject]@{
        TimeGenerated = (Get-Date)
        EventID       = "N/A"
        Type          = "Info R2"
        Message       = $r2_message
    }
    $allSuspiciousEvents += [PSCustomObject]@{
        TimeGenerated = (Get-Date)
        EventID       = "N/A"
        Type          = "Info R3"
        Message       = $r3_message
    }
    $allSuspiciousEvents += [PSCustomObject]@{
        TimeGenerated = (Get-Date)
        EventID       = "N/A"
        Type          = "Info R4"
        Message       = $r4_message
    }
    $allSuspiciousEvents += [PSCustomObject]@{
        TimeGenerated = (Get-Date)
        EventID       = "N/A"
        Type          = "Info R5"
        Message       = $r5_message
    }

    # (6..10)
    $allSuspiciousEvents += $results6_10

    return $allSuspiciousEvents
} 

$allSuspiciousEvents = Detect-SuspiciousActivity

if ($allSuspiciousEvents -and $allSuspiciousEvents.Count -gt 0) {
    $allSuspiciousEvents | Out-GridView -Title "Suspicious/Info Events Report"
}
else {
    Write-Host "No event data available." -ForegroundColor Yellow
}

# ====================
# Getting info about Services
# ====================
$total = @()

try {
    $services = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -ErrorAction Stop

    if (-not $services) {
        Write-Warning "No services found on $ComputerName. Check permissions or connectivity."
        return
    }
    else {
        Write-Host "Services found: $($services.Count)" -ForegroundColor Green
    }

    foreach ($service in $services) {
        $executablePath = "Unknown"
        $commandLine    = "Unknown"
        $signature      = "Unknown"
        $signer         = "N/A"
        $rawImagePath   = "Unknown"

        try {
            $registryKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
            if (Test-Path $registryKey) {
                $imagePathFromRegistry = (Get-ItemProperty -Path $registryKey).ImagePath
                if ($imagePathFromRegistry -and $imagePathFromRegistry -ne "") {
                    $rawImagePath  = $imagePathFromRegistry
                    $parsablePath  = $imagePathFromRegistry -split " " | Select-Object -First 1
                    $commandLine   = $imagePathFromRegistry
                    $executablePath= $parsablePath
                }
            }
        }
        catch {
            Write-Warning "Failed to fetch registry details for service $($service.Name)."
        }

        if ($service.ProcessId -ne 0) {
            try {
                $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" -ErrorAction Stop
                $executablePath = $process.ExecutablePath
                $commandLine    = $process.CommandLine
            }
            catch {
                Write-Warning "Failed to fetch process details for service $($service.Name)."
            }
        }

        if ($executablePath -and (Test-Path -Path $executablePath)) {
            try {
                $sig = Get-AuthenticodeSignature $executablePath
                if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject) {
                    $signature = "Valid"
                    $signer    = $sig.SignerCertificate.Subject
                }
                elseif ($sig.Status -eq 'Valid') {
                    $signature = "Valid"
                }
                else {
                    $signature = "Unsigned"
                }
            }
            catch {
                Write-Warning "Failed to verify signature for file $executablePath."
            }
        }
        else {
            $signature = "File Not Found"
        }
		
		            $isSuspicious = $false
            $suspiciousReason = @()
            if ($suspiciousServices -contains $service.Name) {
                $isSuspicious = $true
                $suspiciousReason += "Matches suspicious name list"
            }

        $total += [PSCustomObject]@{
            ComputerName    = $ComputerName
            DisplayName     = $service.DisplayName
            Description     = $service.Description
            Name            = $service.Name
            State           = $service.State
            StartMode       = $service.StartMode
            ExecutablePath  = $rawImagePath
            CommandLine     = $commandLine
            SignatureStatus = $signature
            Signer          = $signer
			SuspiciousReason= ($suspiciousReason -join "; ") -replace "; $", ""
        }
    }
}
catch {
    Write-Warning "Error connecting to $ComputerName, skipping..."
}

if ($total -and $total.Count -gt 0) {
    $total | Out-GridView -Title 'Service Analysis Report'
}
else {
    Write-Host "No service data available." -ForegroundColor Yellow
}

# ====================
# Optionally : Write to Excel
# ====================
if ($Filename) {
    $Date = Get-Date -Format 'yyyy-MM-dd_HH-mm'
    $worksheetNameEvents   = "Events_$($Date)"
    $worksheetNameServices = "Services_$($Date)"
    if ($allSuspiciousEvents -and $allSuspiciousEvents.Count -gt 0) {
        $allSuspiciousEvents | Export-Excel -Path $Filename -WorksheetName $worksheetNameEvents -AutoFilter -AutoSize -Append
    }
    if ($total -and $total.Count -gt 0) {
        $total | Export-Excel -Path $Filename -WorksheetName $worksheetNameServices -AutoFilter -AutoSize -Append
    }
    Write-Host ("Exported analysis to {0}" -f $Filename) -ForegroundColor Green
}
