<#
.SYNOPSIS
    MagicWinPwn - Automated Windows Privilege Escalation Script

.DESCRIPTION
    MagicWinPwn is a powerful and automated Windows privilege escalation
    script designed to help security professionals and CTF enthusiasts
    uncover potential misconfigurations, vulnerabilities, and weaknesses
    that can lead to privilege escalation.

.AUTHOR
    MagicBytes (@Mag1cByt3s)
#>

# Function to Display ASCII Art Banner
function Show-Banner {
    Write-Host "`n" -ForegroundColor DarkMagenta
    Write-Host -ForegroundColor DarkMagenta " __  __                   _         __        __  _           ____"
    Write-Host -ForegroundColor DarkMagenta "|  \/  |   __ _    __ _  (_)   ___  \ \      / / (_)  _ __   |  _ \  __      __  _ __"
    Write-Host -ForegroundColor DarkMagenta "| |\/| |  / _` |  /  _`| | |  / __|  \ \ /\ / /  | | | '_ \  | |_) | \ \ /\ / / | '_ \"
    Write-Host -ForegroundColor DarkMagenta "| |  | | | (_| | | (_| | | | | (__    \ V  V /   | | | | | | |  __/   \ V  V /  | | | |"
    Write-Host -ForegroundColor DarkMagenta "|_|  |_|  \__,_|  \__, | |_|  \___|    \_/\_/    |_| |_| |_| |_|       \_/\_/   |_| |_|"
    Write-Host -ForegroundColor DarkMagenta "                   |___/"                                                                
    Write-Host "         Windows Privilege Escalation Script" -ForegroundColor Cyan
    Write-Host "                    By @Mag1cByt3s" -ForegroundColor Yellow
    Write-Host "    (https://github.com/Mag1cByt3s/MagicWinPwn)" -ForegroundColor DarkGray
    Write-Host "`n"
}

# Logging function
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $message"
}

# Function to Get Current User, Groups, and Privileges
function Get-UserInfo {
    Write-Log "Enumerating current user information..."

    # Get current user
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $username = $currentUser.Name
    $groups = $currentUser.Groups | ForEach-Object { 
        try {
            $_.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            $_.Value
        }
    }

    Write-Host "`n[+] Current User Information:" -ForegroundColor Green
    Write-Host "    Username: $username"

    # Check if user has Administrator rights
    $adminCheck = [System.Security.Principal.WindowsPrincipal]::new($currentUser).IsInRole([System.Security.Principal.WindowsBuiltinRole]::Administrator)
    Write-Host "    Is Administrator: $adminCheck"

    # Display group memberships
    Write-Host "`n[+] Group Memberships:" -ForegroundColor Green
    foreach ($group in $groups) {
        Write-Host "    - $group"
    }

    # Get user privileges (SeDebugPrivilege, SeImpersonatePrivilege, etc.) with proper formatting
    Write-Host "`n[+] Assigned Privileges:" -ForegroundColor Green
    $privileges = whoami /priv | ForEach-Object { $_ -replace "\s{2,}", " | " }  # Replace multiple spaces with a separator
    if ($privileges -match "Privilege Name") {
        Write-Host "`n    Privilege Name                    | Description                                   | State" -ForegroundColor Cyan
        Write-Host "    --------------------------------------------------------------------------------------------" -ForegroundColor Cyan
        $privileges | Select-Object -Skip 1 | ForEach-Object { 
            if ($_ -match "(Se\S+)\s+\|\s+(.+?)\s+\|\s+(Enabled|Disabled)") {
                Write-Host ("    {0,-33} | {1,-45} | {2}" -f $matches[1], $matches[2], $matches[3]) 
            }
        }
    }
    else {
        Write-Host "    No privileges found or user lacks permission to query." -ForegroundColor Yellow
    }

    Write-Host "`n"
}

# Basic System Enumeration
function Get-SystemInfo {
    Write-Log "Gathering enhanced system information..."
    
    # Get detailed system information
    Write-Host "`n[+] Detailed System Information:" -ForegroundColor Green
    try {
        $systemInfo = systeminfo 2>$null
        if ($systemInfo) {
            # Display only key information
            $systemInfo | Select-String "Host Name:|OS Name:|OS Version:|System Manufacturer:|System Model:|System Type:|Hotfix|System Boot Time:|Domain:" | ForEach-Object {
                Write-Host "    $_" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "    Unable to retrieve system information (insufficient privileges)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "    Error retrieving system information: $_" -ForegroundColor Red
    }
    
    # Get environment variables
    Write-Host "`n[+] Environment Variables:" -ForegroundColor Green
    $envVars = @{
        "PATH"                   = $env:PATH
        "USERPROFILE"            = $env:USERPROFILE
        "HOMEDRIVE"              = $env:HOMEDRIVE
        "HOMEPATH"               = $env:HOMEPATH
        "TEMP"                   = $env:TEMP
        "APPDATA"                = $env:APPDATA
        "LOCALAPPDATA"           = $env:LOCALAPPDATA
        "COMPUTERNAME"           = $env:COMPUTERNAME
        "USERNAME"               = $env:USERNAME
        "PROCESSOR_ARCHITECTURE" = $env:PROCESSOR_ARCHITECTURE
    }
    
    foreach ($var in $envVars.GetEnumerator()) {
        Write-Host "    $($var.Key): $($var.Value)" -ForegroundColor Gray
    }
    
    # Analyze PATH for potential issues
    Write-Host "`n[+] PATH Analysis:" -ForegroundColor Green
    $pathDirs = $env:PATH -split ';'
    foreach ($dir in $pathDirs) {
        if ($dir -and (Test-Path $dir -ErrorAction SilentlyContinue)) {
            try {
                $acl = Get-Acl $dir -ErrorAction Stop
                $access = $acl.Access | Where-Object { 
                    $_.IdentityReference -match "Users|Everyone|Authenticated Users" -and 
                    $_.FileSystemRights -match "Write|Modify|FullControl" 
                }
                if ($access) {
                    Write-Host "    [!] Writeable PATH directory: $dir" -ForegroundColor Red
                }
                else {
                    Write-Host "    $dir" -ForegroundColor Gray
                }
            }
            catch {
                Write-Host "    $dir (Access Denied)" -ForegroundColor Yellow
            }
        }
        elseif ($dir) {
            Write-Host "    $dir (Does not exist)" -ForegroundColor Yellow
        }
    }
    
    # Get installed patches
    Write-Host "`n[+] Installed Patches:" -ForegroundColor Green
    try {
        $patches = Get-HotFix | Sort-Object InstalledOn
        $patches | ForEach-Object {
            Write-Host "    $($_.HotFixID) - $($_.Description) - $($_.InstalledOn)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "    Error retrieving patches: $_" -ForegroundColor Red
    }
    
    # Get installed software
    Write-Host "`n[+] Installed Software:" -ForegroundColor Green
    try {
        $software = Get-WmiObject -Class Win32_Product | Select-Object Name, Version
        $software | ForEach-Object {
            Write-Host "    $($_.Name) ($($_.Version))" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "    Error retrieving installed software (WMI access denied)" -ForegroundColor Yellow
        Write-Host "    Trying alternative method..." -ForegroundColor Yellow
        
        # Alternative method using registry
        try {
            $regPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            
            $software = $regPaths | ForEach-Object {
                Get-ItemProperty $_ 2>$null | Where-Object { 
                    $_.DisplayName -and $_.DisplayName -notmatch "Update|Hotfix|Security|Patch" 
                }
            } | Select-Object DisplayName, DisplayVersion | Sort-Object DisplayName -Unique
            
            $software | ForEach-Object {
                Write-Host "    $($_.DisplayName) ($($_.DisplayVersion))" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "    Unable to retrieve installed software: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "`n"
}

# Network Enumeration Functions
function Get-NetworkInfo {
    Write-Log "Gathering network information..."
    
    # Get IP Configuration
    Get-IPConfigInfo
    
    # Get ARP Table
    Get-ARPTable
    
    # Get Routing Table
    Get-RoutingTable
    
    # Get Listening Ports
    Get-ListeningPorts
    
    # Get Named Pipes
    Get-NamedPipesInfo
    
    Write-Host "`n"
}

function Get-IPConfigInfo {
    Write-Host "`n[+] Network Interfaces and IP Configuration:" -ForegroundColor Green
    $ipconfig = ipconfig /all
    $ipconfig | ForEach-Object { Write-Host "    $_" }
}

function Get-ARPTable {
    Write-Host "`n[+] ARP Table:" -ForegroundColor Green
    $arp = arp -a
    $arp | ForEach-Object { Write-Host "    $_" }
}

function Get-RoutingTable {
    Write-Host "`n[+] Routing Table:" -ForegroundColor Green
    $route = route print
    $route | ForEach-Object { Write-Host "    $_" }
}

function Get-ListeningPorts {
    Write-Host "`n[+] Listening Ports:" -ForegroundColor Green
    try {
        $netstat = netstat -ano | Select-String "LISTENING"
        if ($netstat) {
            Write-Host "    Proto  Local Address          Process ID  Process Name" -ForegroundColor Cyan
            Write-Host "    -----------------------------------------------------" -ForegroundColor Cyan
            $netstat | ForEach-Object {
                $line = $_.ToString().Trim()
                if ($line -match "TCP\s+(.+?)\s+.+?\s+LISTENING\s+(\d+)") {
                    $localAddr = $matches[1]
                    $processId = $matches[2]
                    $processName = try { (Get-Process -Id $processId -ErrorAction Stop).ProcessName } catch { "Unknown" }
                    Write-Host ("    {0,-7} {1,-22} {2,-11} {3}" -f "TCP", $localAddr, $processId, $processName) -ForegroundColor Gray
                }
            }
        }
        else {
            Write-Host "    No listening TCP ports found" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "    Error retrieving listening ports: $_" -ForegroundColor Red
    }
}

function Get-NamedPipesInfo {
    Write-Log "Enumerating named pipes..."
    
    Write-Host "`n[+] Named Pipes:" -ForegroundColor Green
    try {
        # Get named pipes using Get-ChildItem
        $pipes = Get-ChildItem "\\.\pipe\" -ErrorAction Stop | Sort-Object Name
        
        if ($pipes) {
            Write-Host "    Total Named Pipes Found: $($pipes.Count)" -ForegroundColor Cyan
            Write-Host "`n    Name" -ForegroundColor Cyan
            Write-Host "    ----" -ForegroundColor Cyan
            
            # Display pipe names (limiting output to prevent excessive scrolling)
            $pipes | Select-Object -First 50 | ForEach-Object {
                Write-Host "    $($_.Name)" -ForegroundColor Gray
            }
            
            if ($pipes.Count -gt 50) {
                Write-Host "    ... and $($pipes.Count - 50) more pipes" -ForegroundColor Yellow
                Write-Host "    (Showing first 50 pipes only)" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "    No named pipes found" -ForegroundColor Yellow
        }
        
        # Check for interesting/common named pipes that might indicate C2 or vulnerable services
        Write-Host "`n[+] Interesting Named Pipes (Potential C2 or Vulnerable Services):" -ForegroundColor Green
        $interestingPipes = $pipes | Where-Object {
            $_.Name -match "msagent|mojo|winsock|lsass|spoolss|srvsvc|atsvc|epmapper|ntsvcs|scerpc|eventlog|wkssvc|trkwks|vmware|windscribe|cobalt|beacon|posh|powershell"
        }
        
        if ($interestingPipes) {
            $interestingPipes | ForEach-Object {
                Write-Host "    [!] $($_.Name)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "    No obviously interesting named pipes found" -ForegroundColor Gray
        }
        
    }
    catch {
        Write-Host "    Error retrieving named pipes: $_" -ForegroundColor Red
        
        # Fallback method using .NET
        Write-Host "`n    Trying alternative enumeration method..." -ForegroundColor Yellow
        try {
            $pipeDirectory = New-Object System.IO.DirectoryInfo "\\.\pipe\"
            $pipes = $pipeDirectory.GetFileSystemInfos() | Sort-Object Name
            
            if ($pipes) {
                Write-Host "    Total Named Pipes Found: $($pipes.Count)" -ForegroundColor Cyan
                $pipes | Select-Object -First 30 | ForEach-Object {
                    Write-Host "    $($_.Name)" -ForegroundColor Gray
                }
            }
        }
        catch {
            Write-Host "    Failed to enumerate named pipes with alternative method: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "`n"
}

# Security Enumeration Functions
function Get-SecurityInfo {
    Write-Log "Checking security controls..."
    
    # Check Windows Defender Status
    Get-DefenderStatus
    
    # Check AppLocker Policies
    Get-AppLockerRules
    
    Write-Host "`n"
}

function Get-DefenderStatus {
    Write-Host "`n[+] Windows Defender Status:" -ForegroundColor Green
    
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        
        Write-Host "    AntiVirus Enabled     : $($defenderStatus.AntivirusEnabled)"
        Write-Host "    Real-Time Protection  : $($defenderStatus.RealTimeProtectionEnabled)"
        Write-Host "    Behavior Monitoring   : $($defenderStatus.BehaviorMonitorEnabled)"
        Write-Host "    IOAV Protection       : $($defenderStatus.IoavProtectionEnabled)"
        Write-Host "    OnAccess Protection   : $($defenderStatus.OnAccessProtectionEnabled)"
        Write-Host "    NIS Enabled           : $($defenderStatus.NISEnabled)"
        
        # Check if signatures are recent
        $signatureAge = $defenderStatus.AntivirusSignatureAge
        if ($signatureAge -gt 7) {
            Write-Host "    Signature Age         : $signatureAge days (POSSIBLY OUTDATED)" -ForegroundColor Yellow
        }
        else {
            Write-Host "    Signature Age         : $signatureAge days" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    Error retrieving Defender status: $_" -ForegroundColor Red
    }
}

function Get-AppLockerRules {
    # Test common executables against AppLocker policy
    Write-Host "`n[+] Testing Common Executables Against AppLocker Policy:" -ForegroundColor Green
    $testPaths = @(
        # Core Windows utilities
        "C:\Windows\System32\cmd.exe",
        "C:\Windows\System32\powershell.exe",
        "C:\Windows\System32\powershell_ise.exe",
        "C:\Windows\System32\wscript.exe",
        "C:\Windows\System32\cscript.exe",
        "C:\Windows\System32\wmic.exe",
        "C:\Windows\System32\mshta.exe",
        "C:\Windows\System32\rundll32.exe",
        "C:\Windows\System32\regsvr32.exe",
        "C:\Windows\System32\regasm.exe",
        "C:\Windows\System32\regsvcs.exe",
        "C:\Windows\System32\msbuild.exe",
        "C:\Windows\System32\scriptrunner.exe",
        "C:\Windows\System32\bash.exe",
        "C:\Windows\System32\certutil.exe",
        "C:\Windows\System32\bitsadmin.exe",
        "C:\Windows\System32\at.exe",
        "C:\Windows\System32\schtasks.exe",
        "C:\Windows\System32\winrs.exe",
    
        # Additional living-off-the-land binaries (LOLBins)
        "C:\Windows\System32\control.exe",
        "C:\Windows\System32\cmstp.exe",
        "C:\Windows\System32\dnscmd.exe",
        "C:\Windows\System32\esentutl.exe",
        "C:\Windows\System32\expand.exe",
        "C:\Windows\System32\extrac32.exe",
        "C:\Windows\System32\findstr.exe",
        "C:\Windows\System32\forfiles.exe",
        "C:\Windows\System32\ftp.exe",
        "C:\Windows\System32\ieexec.exe",
        "C:\Windows\System32\makecab.exe",
        "C:\Windows\System32\mavinject.exe",
        "C:\Windows\System32\mftrace.exe",
        "C:\Windows\System32\msxsl.exe",
        "C:\Windows\System32\odbcconf.exe",
        "C:\Windows\System32\pcalua.exe",
        "C:\Windows\System32\pcwrun.exe",
        "C:\Windows\System32\presentationhost.exe",
        "C:\Windows\System32\print.exe",
        "C:\Windows\System32\replace.exe",
        "C:\Windows\System32\robocopy.exe",
        "C:\Windows\System32\runas.exe",
        "C:\Windows\System32\syncappvpublishingserver.exe",
        "C:\Windows\System32\wbem\wmic.exe",
        "C:\Windows\System32\winsat.exe",
        "C:\Windows\System32\workfolders.exe",
    
        # Microsoft Office applications (if installed)
        "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
        "C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE",
        "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE",
        "C:\Program Files (x86)\Microsoft Office\root\Office16\EXCEL.EXE",
    
        # Microsoft Visual Studio tools (if installed)
        "C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe",
        "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe",
        "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\gacutil.exe",
    
        # Python (if installed)
        "C:\Python27\python.exe",
        "C:\Python3\python.exe",
        "C:\Users\Public\Python\python.exe",
    
        # Git (if installed)
        "C:\Program Files\Git\bin\sh.exe",
        "C:\Program Files\Git\usr\bin\sh.exe",
    
        # Other common utilities
        "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
        "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
    )

    # Filter to only include paths that exist
    $existingPaths = $testPaths | Where-Object { Test-Path $_ }

    foreach ($path in $existingPaths) {
        try {
            $result = Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path $path -User Everyone
            $decision = $result.PolicyDecision
            $color = if ($decision -eq "Denied") { "Red" } else { "Green" }
            Write-Host "    $path : $decision" -ForegroundColor $color
        }
        catch {
            Write-Host "    $path : Error testing policy - $_" -ForegroundColor Yellow
        }
    }
}

function Get-ProcessInfo {
    Write-Log "Enumerating running processes..."
    
    Write-Host "`n[+] Running Processes:" -ForegroundColor Green
    try {
        $processes = Get-WmiObject Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine
        $processes | ForEach-Object {
            Write-Host "    $($_.ProcessId): $($_.Name)" -ForegroundColor Gray
            if ($_.ExecutablePath) {
                Write-Host "        Path: $($_.ExecutablePath)" -ForegroundColor DarkGray
            }
            if ($_.CommandLine) {
                Write-Host "        Cmd: $($_.CommandLine)" -ForegroundColor DarkGray
            }
        }
    }
    catch {
        Write-Host "    Error retrieving process information: $_" -ForegroundColor Red
    }
    
    Write-Host "`n"
}

function Get-UserEnumeration {
    Write-Log "Enumerating user and group information..."
    
    # Get logged in users
    Get-LoggedUsers
    
    # Get all users
    Get-AllUsers
    
    # Get all groups
    Get-AllGroups
    
    # Get password policy
    Get-PasswordPolicy
    
    Write-Host "`n"
}

function Get-LoggedUsers {
    Write-Host "`n[+] Logged-In Users:" -ForegroundColor Green
    try {
        $users = query user 2>$null
        if ($users) {
            $users | ForEach-Object { Write-Host "    $_" }
        }
        else {
            Write-Host "    No other users currently logged in" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "    Error retrieving logged-in users: $_" -ForegroundColor Red
    }
}

function Get-AllUsers {
    Write-Host "`n[+] All Users:" -ForegroundColor Green
    try {
        $users = net user 2>$null
        if ($users) {
            # Extract user names from the output
            $userLines = $users | Select-String "User accounts for" -Context 0, 100
            if ($userLines) {
                $userLines.Context.PostContext | ForEach-Object {
                    if ($_ -match "-------------------------------------------------------------------------------") {
                        return
                    }
                    if ($_ -match "The command completed successfully") {
                        return
                    }
                    if ($_ -match "\S") {
                        $cleanLine = $_.Trim() -replace '\s{2,}', ' '
                        $cleanLine.Split(' ') | ForEach-Object {
                            if ($_ -match "\S") {
                                Write-Host "    - $_" -ForegroundColor Gray
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Host "    Error retrieving user list: $_" -ForegroundColor Red
    }
}

function Get-AllGroups {
    Write-Host "`n[+] All Groups:" -ForegroundColor Green
    try {
        $groups = net localgroup 2>$null
        if ($groups) {
            # Extract group names from the output
            $groupLines = $groups | Select-String "Aliases for" -Context 0, 100
            if ($groupLines) {
                $groupLines.Context.PostContext | ForEach-Object {
                    if ($_ -match "-------------------------------------------------------------------------------") {
                        return
                    }
                    if ($_ -match "The command completed successfully") {
                        return
                    }
                    if ($_ -match "\*") {
                        $_.Trim() -replace '\*', '' | ForEach-Object {
                            if ($_ -match "\S") {
                                Write-Host "    - $_" -ForegroundColor Gray
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Host "    Error retrieving group list: $_" -ForegroundColor Red
    }
}

function Get-PasswordPolicy {
    Write-Host "`n[+] Password Policy:" -ForegroundColor Green
    try {
        $policy = net accounts 2>$null
        if ($policy) {
            $policy | ForEach-Object {
                if ($_ -match "\S" -and $_ -notmatch "The command completed successfully") {
                    Write-Host "    $_" -ForegroundColor Gray
                }
            }
        }
    }
    catch {
        Write-Host "    Error retrieving password policy: $_" -ForegroundColor Red
    }
}

# Main Execution
function Start-MagicWinPwn {
    Show-Banner
    Get-SystemInfo
    Get-UserInfo
    Get-NetworkInfo
    Get-SecurityInfo
    Get-UserEnumeration
    Get-ProcessInfo
    Write-Log "Enumeration complete."
}

# Execute the script
Start-MagicWinPwn