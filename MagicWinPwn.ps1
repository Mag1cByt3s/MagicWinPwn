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

# Basic System Enumeration
function Get-SystemInfo {
    Write-Log "Gathering system information..."
    $os = Get-WmiObject Win32_OperatingSystem
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    Write-Host "`n[+] OS Information:" -ForegroundColor Green
    Write-Host "    Name: $($os.Caption) ($($os.Version))"
    Write-Host "    Architecture: $($os.OSArchitecture)"
    Write-Host "    Build Number: $($os.BuildNumber)"
    Write-Host "    Install Date: $($os.InstallDate)"
    
    Write-Host "`n[+] User Information:" -ForegroundColor Green
    Write-Host "    Username: $($user.Name)"
    Write-Host "    Is Admin: $( [System.Security.Principal.WindowsBuiltinRole]::Administrator -in ($user.Groups | ForEach-Object { $_.Value }) )"

    Write-Host "`n"
}

# Main Execution
function Start-MagicWinPwn {
    Show-Banner
    Get-SystemInfo
    Write-Log "Enumeration complete."
}

# Execute the script
Start-MagicWinPwn
