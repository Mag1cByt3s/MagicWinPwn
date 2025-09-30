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
    Write-Host "`n[+] AppLocker Policy Rules:" -ForegroundColor Green
    
    try {
        # Check if AppLocker is available
        $appLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        
        if ($appLockerPolicy.RuleCollections.Count -eq 0) {
            Write-Host "    No AppLocker rules found" -ForegroundColor Yellow
            return
        }
        
        # Display rule collections
        $ruleCollections = $appLockerPolicy | Select-Object -ExpandProperty RuleCollections
        
        foreach ($collection in $ruleCollections) {
            Write-Host "    Rule Collection: $($collection.GetType().Name)" -ForegroundColor Cyan
            
            # Display key properties
            Write-Host "      Name: $($collection.Name)"
            Write-Host "      Action: $($collection.Action)"
            Write-Host "      Description: $($collection.Description)"
            
            # Display conditions
            if ($collection.PathConditions) {
                Write-Host "      Path Conditions:" -ForegroundColor Gray
                foreach ($condition in $collection.PathConditions) {
                    Write-Host "        - $condition"
                }
            }
            
            if ($collection.PublisherConditions) {
                Write-Host "      Publisher Conditions:" -ForegroundColor Gray
                foreach ($condition in $collection.PublisherConditions) {
                    Write-Host "        - $condition"
                }
            }
            
            Write-Host ""
        }
        
        # Test common executables against AppLocker policy
        Write-Host "`n[+] Testing Common Executables Against AppLocker Policy:" -ForegroundColor Green
        $testPaths = @(
            "C:\Windows\System32\cmd.exe",
            "C:\Windows\System32\powershell.exe",
            "C:\Windows\System32\wscript.exe",
            "C:\Windows\System32\cscript.exe"
        )
        
        foreach ($path in $testPaths) {
            if (Test-Path $path) {
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
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Host "    AppLocker module not available or not installed" -ForegroundColor Yellow
    }
    catch {
        Write-Host "    Error retrieving AppLocker policy: $_" -ForegroundColor Red
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