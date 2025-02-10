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
    $asciiArt = @"
  __  __             _    __        ___       ____                 
 |  \/  | __ _  __ _(_) __\ \      / (_)_ __ |  _ \__      ___ __  
 | |\/| |/ _` |/ _` | |/ __\ \ /\ / /| | '_ \| |_) \ \ /\ / / '_ \ 
 | |  | | (_| | (_| | | (__ \ V  V / | | | | |  __/ \ V  V /| | | |
 |_|  |_|\__,_|\__, |_|\___| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
               |___/                                               

"@
    Write-Host "`n" -ForegroundColor DarkMagenta
    Write-Host $asciiArt -ForegroundColor Magenta
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
        } catch {
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
    } else {
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

# Main Execution
function Start-MagicWinPwn {
    Show-Banner
    Get-SystemInfo
    Get-UserInfo
    Write-Log "Enumeration complete."
}

# Execute the script
Start-MagicWinPwn