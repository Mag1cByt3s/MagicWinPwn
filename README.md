# MagicWinPwn

MagicWinPwn is a powerful and automated Windows privilege escalation script designed to help security professionals and CTF enthusiasts uncover potential misconfigurations, vulnerabilities, and weaknesses that can lead to privilege escalation.

<br>

---

<br>

## Usage

### Running the Script
To execute **MagicWinPwn** run:
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
- Enumerates network configuration, ARP table, and routing information  
- Checks Windows Defender and AppLocker security controls  
- Generates structured output for better readability  
- Lightweight and standalone (No dependencies required)  

<br>

---

<br>

## Privilege Escalation Checks

MagicWinPwn automates various **Windows privilege escalation techniques**, including:

- **Basic System Information** (OS, user privileges, architecture)
- **User Privileges & Groups** (Identifies admin access & privilege levels)
- **Network Configuration** (Interfaces, IP addresses, DNS, ARP, routing)
- **Security Controls** (Windows Defender status, AppLocker policies)
- **Service Misconfigurations** (Unquoted service paths, weak permissions)
- **Scheduled Tasks & Startup Applications** (Auto-elevated execution paths)
- **Stored Credentials & Passwords** (SAM, LSA Secrets, Credential Manager)
- **Weak File & Registry Permissions** (DLL hijacking, writable registry keys)
- **Windows Exploit Checks** (Common CVEs and known escalation paths)

<br>

---

<br>

## Example Output

```
[+] OS Information: Name: Windows 10 Pro (10.0.19044) Architecture: x64 Build Number: 19044 Install Date: 2022-03-15

[+] User Information: Username: WINLPE-SRV01\Admin Is Admin: True

[+] Network Interfaces and IP Configuration:
    Windows IP Configuration
       Host Name . . . . . . . . . . . . : WINLPE-SRV01
       Primary Dns Suffix  . . . . . . . :
       Node Type . . . . . . . . . . . . : Hybrid
       IP Routing Enabled. . . . . . . . : No
       WINS Proxy Enabled. . . . . . . . : No
       DNS Suffix Search List. . . . . . : .htb

[+] Windows Defender Status:
    AntiVirus Enabled     : True
    Real-Time Protection  : False
    Behavior Monitoring   : False
    IOAV Protection       : False

[+] AppLocker Policy Rules:
    Rule Collection: AppxRuleCollection
      Name: (Default Rule) All signed packaged apps
      Action: Allow
      Description: Allows members of the Everyone group to run packaged apps that are signed.
```

<br>

---

<br>

## Screenshots

![MagicWinPwn Banner](https://raw.githubusercontent.com/Mag1cByt3s/MagicWinPwn/main/screenshots/banner.png)
*Script execution with banner*

![User Information](https://raw.githubusercontent.com/Mag1cByt3s/MagicWinPwn/main/screenshots/userinfo.png)
*User privilege enumeration*

![Network Information](https://raw.githubusercontent.com/Mag1cByt3s/MagicWinPwn/main/screenshots/network.png)
*Network configuration enumeration*

![Security Controls](https://raw.githubusercontent.com/Mag1cByt3s/MagicWinPwn/main/screenshots/security.png)
*Windows Defender and AppLocker status*

<br>

---

<br>

## Contributing

Contributions are welcome! Feel free to submit a pull request or open an issue for any suggestions or improvements.

<br>

---

<br>

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

<br>

---

<br>

## Disclaimer

This tool is designed for educational purposes and authorized security testing only. The author is not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before using this tool on any system.
