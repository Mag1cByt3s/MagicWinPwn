# MagicWinPwn

MagicWinPwn is a powerful and automated Windows privilege escalation script designed to help security professionals and CTF enthusiasts uncover potential misconfigurations, vulnerabilities, and weaknesses that can lead to privilege escalation.

<br>

---

<br>

## Usage

### Running the Script
To execute **MagicWinPwn**, open **PowerShell** and run:
```powershell
powershell -ep bypass -f .\MagicWinPwn.ps1
```

<br>

### Options (Coming Soon)
| Option        | Description |
|--------------|-------------|
| `-All`       | Run all privilege escalation checks |
| `-Services`  | Check for vulnerable services |
| `-Registry`  | Identify registry misconfigurations |
| `-Credentials` | Search for stored credentials |
| `-Report`    | Generate a structured report |

<br>

---

<br>

## Features

- Automated privilege escalation enumeration  
- Checks for common misconfigurations and vulnerabilities  
- Identifies weak permissions, stored credentials, and exploitable services  
- Generates structured output for better readability  
- Lightweight and standalone (No dependencies required)  

<br>

---

<br>

## Privilege Escalation Checks

MagicWinPwn automates various **Windows privilege escalation techniques**, including:

- **Basic System Information** (OS, user privileges, architecture)
- **User Privileges & Groups** (Identifies admin access & privilege levels)
- **Service Misconfigurations** (Unquoted service paths, weak permissions)
- **Scheduled Tasks & Startup Applications** (Auto-elevated execution paths)
- **Stored Credentials & Passwords** (SAM, LSA Secrets, Credential Manager)
- **Weak File & Registry Permissions** (DLL hijacking, writable registry keys)
- **Windows Exploit Checks** (Common CVEs and known escalation paths)

<br>

---

<br>

## Example Output
```powershell
[+] OS Information: Name: Windows 10 Pro (10.0.19044) Architecture: x64 Build Number: 19044 Install Date: 2022-03-15

[+] User Information: Username: REDFLAKE-PC\Admin Is Admin: True

[+] Services with Unquoted Paths: - C:\Program Files\Vulnerable App\service.exe (SYSTEM) [!] Exploit: Path Manipulation (Place malicious .exe in the directory)

[+] Writable Directories: - C:\Program Files\VulnerableApp
[!] Exploit: Drop malicious DLL for privilege escalation
```

<br>

---

<br>

## Screenshots