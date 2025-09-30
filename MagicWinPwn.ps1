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
    Write-Log "Gathering system information..."
    $os = Get-WmiObject Win32_OperatingSystem

    Write-Host "`n[+] OS Information:" -ForegroundColor Green
    Write-Host "    Name: $($os.Caption) ($($os.Version))"
    Write-Host "    Architecture: $($os.OSArchitecture)"
    Write-Host "    Build Number: $($os.BuildNumber)"
    Write-Host "    Install Date: $($os.ConvertToDateTime($os.InstallDate))"

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

# Main Execution
function Start-MagicWinPwn {
    Show-Banner
    Get-SystemInfo
    Get-UserInfo
    Get-NetworkInfo
    Get-SecurityInfo
    Write-Log "Enumeration complete."
}

# Execute the script
Start-MagicWinPwn