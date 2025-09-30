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
- Enumerates detailed system information (patches, environment variables, installed software)
- Analyzes PATH directories for write permissions
- Lists running processes with executable paths and command lines
- Enumerates logged-in users, all local users, and groups
- Retrieves password policy and account information
- Identifies installed software through multiple methods

<br>

---

<br>

## Privilege Escalation Checks

MagicWinPwn automates various **Windows privilege escalation techniques**, including:

- **Basic System Information** (OS, user privileges, architecture)
- **User Privileges & Groups** (Identifies admin access & privilege levels)
- **Network Configuration** (Interfaces, IP addresses, DNS, ARP, routing table, listening ports)
- **Security Controls** (Windows Defender status, AppLocker policies)
- **Service Misconfigurations** (Unquoted service paths, weak permissions)
- **Scheduled Tasks & Startup Applications** (Auto-elevated execution paths)
- **Stored Credentials & Passwords** (SAM, LSA Secrets, Credential Manager)
- **Weak File & Registry Permissions** (DLL hijacking, writable registry keys)
- **Windows Exploit Checks** (Common CVEs and known escalation paths)
- **Enhanced System Information** (Installed patches, environment variables, software inventory)
- **Process Enumeration** (Running processes with full paths and command lines)
- **User & Group Enumeration** (All users, groups, password policies, logged-in users)
- **PATH Analysis** (Identifies writable directories in system PATH)

<br>

## Advanced Security Checks

MagicWinPwn includes advanced security control enumeration:

- **AppLocker Policy Analysis**: Tests over 40 common executables against AppLocker policies
  - **LOLBins Testing**: Checks restrictions on living-off-the-land binaries commonly used in attacks
  - **Writable Directory Identification**: Highlights common bypass locations for AppLocker restrictions
- **Comprehensive Defender Status**: Detailed Windows Defender protection feature enumeration

<br>

---

<br>

## Example Output

```
PS C:\Users\htb-student\Desktop> .\MagicWinPwn.ps1


 __  __                   _         __        __  _           ____
|  \/  |   __ _    __ _  (_)   ___  \ \      / / (_)  _ __   |  _ \  __      __  _ __
| |\/| |  / _ |  /  _| | |  / __|  \ \ /\ / /  | | | '_ \  | |_) | \ \ /\ / / | '_ \
| |  | | | (_| | | (_| | | | | (__    \ V  V /   | | | | | | |  __/   \ V  V /  | | | |
|_|  |_|  \__,_|  \__, | |_|  \___|    \_/\_/    |_| |_| |_| |_|       \_/\_/   |_| |_|
                   |___/
         Windows Privilege Escalation Script
                    By @Mag1cByt3s
    (https://github.com/Mag1cByt3s/MagicWinPwn)


[2025-09-30 13:54:58] Gathering enhanced system information...

[+] Detailed System Information:
    Host Name:                 WINLPE-SRV01
    OS Name:                   Microsoft Windows Server 2016 Standard
    OS Version:                10.0.14393 N/A Build 14393
    System Boot Time:          9/30/2025, 1:47:48 PM
    System Manufacturer:       VMware, Inc.
    System Model:              VMware7,1
    System Type:               x64-based PC
    BIOS Version:              VMware, Inc. VMW71.00V.24504846.B64.2501180334, 1/18/2025
    Domain:                    WORKGROUP
    Hotfix(s):                 4 Hotfix(s) Installed.

[+] Environment Variables:
    TEMP: C:\Users\HTB-ST~1\AppData\Local\Temp\2
    PATH: C:\Program Files (x86)\Common Files\Oracle\Java\javapath;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\;C:\Program Files (x86)\Microsoft SQL Server\130\Tools\Binn\;C:\Program Files\Microsoft SQL Server\130\Tools\Binn\;C:\Program Files\Microsoft SQL Server\130\DTS\Binn\;C:\Program Files (x86)\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files\Azure Data Studio\bin;C:\Program Files\PuTTY\;C:\Users\htb-student\AppData\Local\Microsoft\WindowsApps;
    USERNAME: htb-student
    PROCESSOR_ARCHITECTURE: AMD64
    APPDATA: C:\Users\htb-student\AppData\Roaming
    USERPROFILE: C:\Users\htb-student
    COMPUTERNAME: WINLPE-SRV01
    HOMEDRIVE: C:
    HOMEPATH: \Users\htb-student
    LOCALAPPDATA: C:\Users\htb-student\AppData\Local

[+] PATH Analysis:
    C:\Program Files (x86)\Common Files\Oracle\Java\javapath
    C:\Windows\system32
    C:\Windows
    C:\Windows\System32\Wbem
    C:\Windows\System32\WindowsPowerShell\v1.0\
    C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\
    C:\Program Files (x86)\Microsoft SQL Server\130\Tools\Binn\
    C:\Program Files\Microsoft SQL Server\130\Tools\Binn\
    C:\Program Files\Microsoft SQL Server\130\DTS\Binn\
    C:\Program Files (x86)\Microsoft SQL Server\150\DTS\Binn\ (Does not exist)
    C:\Program Files\Azure Data Studio\bin
    C:\Program Files\PuTTY\
    C:\Users\htb-student\AppData\Local\Microsoft\WindowsApps

[+] Installed Patches:
    KB3199986 - Update - 11/21/2016 00:00:00
    KB5001078 - Security Update - 03/25/2021 00:00:00
    KB4054590 - Update - 03/30/2021 00:00:00
    KB3200970 - Security Update - 04/13/2021 00:00:00

[+] Installed Software:
    SQL Server 2016 Database Engine Shared (13.2.5026.0)
    Microsoft OLE DB Driver for SQL Server (18.3.0.0)
    Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219 (10.0.40219)
    Microsoft Help Viewer 2.3 (2.3.28107)
    Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219 (10.0.40219)
    Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.21005 (12.0.21005)
    Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.21005 (12.0.21005)
    Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29914 (14.28.29914)
    Microsoft ODBC Driver 13 for SQL Server (13.2.5026.0)
    SQL Server 2016 Database Engine Shared (13.2.5026.0)
    SQL Server 2016 Database Engine Services (13.2.5026.0)
    SQL Server Management Studio for Reporting Services (15.0.18369.0)
    Microsoft SQL Server 2008 Setup Support Files  (10.3.5500.0)
    SSMS Post Install Tasks (15.0.18369.0)
    Microsoft VSS Writer for SQL Server 2016 (13.2.5026.0)
    Java 8 Update 231 (64-bit) (8.0.2310.11)
    Browser for SQL Server 2016 (13.2.5026.0)
    Integration Services (15.0.2000.130)
    Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127 (14.24.28127)
    SQL Server 2016 Database Engine Services (13.2.5026.0)
    SQL Server 2016 DMF (13.0.1601.5)
    Microsoft SQL Server 2012 Native Client  (11.4.7462.6)
    VMware Tools (11.1.1.16303738)
    SQL Server 2016 Shared Management Objects (13.0.16107.4)
    SQL Server 2016 Connection Info (13.0.16108.4)
    Microsoft ODBC Driver 17 for SQL Server (17.5.1.1)
    SQL Server 2016 Common Files (13.2.5026.0)
    SQL Server 2016 Connection Info (13.0.16108.4)
    SuperPuTTY (1.4.0.8)
    Sql Server Customer Experience Improvement Program (13.2.5026.0)
    Visual Studio 2017 Isolated Shell for SSMS (15.0.28307.421)
    Microsoft SQL Server Data-Tier Application Framework (x86) (13.0.3225.4)
    SQL Server 2016 Shared Management Objects (13.0.16107.4)
    Microsoft Analysis Services OLE DB Provider (15.0.2000.568)
    SQL Server 2016 Shared Management Objects Extensions (13.2.5026.0)
    SQL Server 2016 Batch Parser (13.0.1601.5)
    SQL Server 2016 Shared Management Objects Extensions (13.2.5026.0)
    Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29914 (14.28.29914)
    SQL Server 2016 Database Engine Services (13.2.5026.0)
    Microsoft SQL Server 2016 Setup (English) (13.2.5026.0)
    Microsoft SQL Server 2016 RsFx Driver (13.2.5026.0)
    SQL Server Management Studio (15.0.18369.0)
    PuTTY release 0.75 (64-bit) (0.75.0.0)
    Microsoft SQL Server 2016 T-SQL ScriptDom  (13.2.5026.0)
    Microsoft Visual Studio Tools for Applications 2017 x64 Hosting Support (15.0.27520)
    SQL Server 2016 Database Engine Services (13.2.5026.0)
    Microsoft SQL Server 2016 T-SQL Language Service  (13.0.14500.10)
    Microsoft Analysis Services OLE DB Provider (15.0.2000.568)
    SQL Server 2016 SQL Diagnostics (13.0.1601.5)
    Microsoft Visual Studio Tools for Applications 2017 x86 Hosting Support (15.0.27520)
    SQL Server 2016 XEvent (13.0.1601.5)
    SQL Server Management Studio (15.0.18369.0)
    SQL Server 2016 DMF (13.0.1601.5)
    SQL Server Management Studio for Analysis Services (15.0.18369.0)
    Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127 (14.24.28127)
    SQL Server 2016 Common Files (13.2.5026.0)
    Java Auto Updater (2.8.231.11)
    SQL Server 2016 XEvent (13.0.1601.5)


[2025-09-30 13:55:26] Enumerating current user information...

[+] Current User Information:
    Username: WINLPE-SRV01\htb-student
    Is Administrator: False

[+] Group Memberships:
    - WINLPE-SRV01\None
    - Everyone
    - BUILTIN\Remote Desktop Users
    - BUILTIN\Users
    - NT AUTHORITY\REMOTE INTERACTIVE LOGON
    - NT AUTHORITY\INTERACTIVE
    - NT AUTHORITY\Authenticated Users
    - NT AUTHORITY\This Organization
    - NT AUTHORITY\Local account
    - LOCAL
    - NT AUTHORITY\NTLM Authentication

[+] Assigned Privileges:

    Privilege Name                    | Description                                   | State
    --------------------------------------------------------------------------------------------
    SeChangeNotifyPrivilege           | Bypass traverse checking                      | Enabled


[2025-09-30 13:55:26] Gathering network information...

[+] Network Interfaces and IP Configuration:

    Windows IP Configuration

       Host Name . . . . . . . . . . . . : WINLPE-SRV01
       Primary Dns Suffix  . . . . . . . :
       Node Type . . . . . . . . . . . . : Hybrid
       IP Routing Enabled. . . . . . . . : No
       WINS Proxy Enabled. . . . . . . . : No
       DNS Suffix Search List. . . . . . : htb

    Ethernet adapter Ethernet1:

       Connection-specific DNS Suffix  . :
       Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
       Physical Address. . . . . . . . . : 00-50-56-94-9D-E1
       DHCP Enabled. . . . . . . . . . . : No
       Autoconfiguration Enabled . . . . : Yes
       Link-local IPv6 Address . . . . . : fe80::b5a3:a7a6:f420:93d7%2(Preferred)
       IPv4 Address. . . . . . . . . . . : 172.16.20.45(Preferred)
       Subnet Mask . . . . . . . . . . . : 255.255.254.0
       Default Gateway . . . . . . . . . : 172.16.20.1
       DHCPv6 IAID . . . . . . . . . . . : 151015510
       DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-30-6D-FA-57-00-50-56-94-9D-E1
       DNS Servers . . . . . . . . . . . : 8.8.8.8
       NetBIOS over Tcpip. . . . . . . . : Enabled

    Ethernet adapter Ethernet0 2:

       Connection-specific DNS Suffix  . : .htb
       Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter #2
       Physical Address. . . . . . . . . : 00-50-56-94-96-5A
       DHCP Enabled. . . . . . . . . . . : Yes
       Autoconfiguration Enabled . . . . : Yes
       IPv6 Address. . . . . . . . . . . : dead:beef::142(Preferred)
       Lease Obtained. . . . . . . . . . : Tuesday, September 30, 2025 1:48:00 PM
       Lease Expires . . . . . . . . . . : Tuesday, September 30, 2025 2:48:00 PM
       IPv6 Address. . . . . . . . . . . : dead:beef::4c23:ae13:b163:f160(Preferred)
       Link-local IPv6 Address . . . . . : fe80::4c23:ae13:b163:f160%4(Preferred)
       IPv4 Address. . . . . . . . . . . : 10.129.43.43(Preferred)
       Subnet Mask . . . . . . . . . . . : 255.255.0.0
       Lease Obtained. . . . . . . . . . : Tuesday, September 30, 2025 1:48:00 PM
       Lease Expires . . . . . . . . . . : Tuesday, September 30, 2025 2:48:00 PM
       Default Gateway . . . . . . . . . : fe80::250:56ff:fe94:53e%4
                                           10.129.0.1
       DHCP Server . . . . . . . . . . . : 10.129.0.1
       DHCPv6 IAID . . . . . . . . . . . : 436228182
       DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-30-6D-FA-57-00-50-56-94-9D-E1
       DNS Servers . . . . . . . . . . . : 1.1.1.1
                                           8.8.8.8
       NetBIOS over Tcpip. . . . . . . . : Enabled
       Connection-specific DNS Suffix Search List :
                                           htb

    Ethernet adapter Ethernet:

       Media State . . . . . . . . . . . : Media disconnected
       Connection-specific DNS Suffix  . :
       Description . . . . . . . . . . . : Windscribe VPN
       Physical Address. . . . . . . . . : 00-FF-B3-3C-CD-5A
       DHCP Enabled. . . . . . . . . . . : Yes
       Autoconfiguration Enabled . . . . : Yes

    Tunnel adapter isatap..htb:

       Media State . . . . . . . . . . . : Media disconnected
       Connection-specific DNS Suffix  . : .htb
       Description . . . . . . . . . . . : Microsoft ISATAP Adapter
       Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
       DHCP Enabled. . . . . . . . . . . : No
       Autoconfiguration Enabled . . . . : Yes

    Tunnel adapter isatap.{02D6F04C-A625-49D1-A85D-4FB454FBB3DB}:

       Media State . . . . . . . . . . . : Media disconnected
       Connection-specific DNS Suffix  . :
       Description . . . . . . . . . . . : Microsoft ISATAP Adapter #3
       Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
       DHCP Enabled. . . . . . . . . . . : No
       Autoconfiguration Enabled . . . . : Yes

[+] ARP Table:

    Interface: 172.16.20.45 --- 0x2
      Internet Address      Physical Address      Type
      172.16.21.255         ff-ff-ff-ff-ff-ff     static
      224.0.0.22            01-00-5e-00-00-16     static
      224.0.0.252           01-00-5e-00-00-fc     static
      239.255.255.250       01-00-5e-7f-ff-fa     static

    Interface: 10.129.43.43 --- 0x4
      Internet Address      Physical Address      Type
      10.129.0.1            00-50-56-94-05-3e     dynamic
      10.129.63.102         00-50-56-94-e4-ef     dynamic
      10.129.248.226        00-50-56-94-63-af     dynamic
      10.129.255.255        ff-ff-ff-ff-ff-ff     static
      224.0.0.22            01-00-5e-00-00-16     static
      224.0.0.252           01-00-5e-00-00-fc     static
      239.255.255.250       01-00-5e-7f-ff-fa     static
      255.255.255.255       ff-ff-ff-ff-ff-ff     static

[+] Routing Table:
    ===========================================================================
    Interface List
      2...00 50 56 94 9d e1 ......vmxnet3 Ethernet Adapter
      4...00 50 56 94 96 5a ......vmxnet3 Ethernet Adapter #2
      7...00 ff b3 3c cd 5a ......Windscribe VPN
      1...........................Software Loopback Interface 1
      9...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter
      6...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #3
    ===========================================================================

    IPv4 Route Table
    ===========================================================================
    Active Routes:
    Network Destination        Netmask          Gateway       Interface  Metric
              0.0.0.0          0.0.0.0      172.16.20.1     172.16.20.45    271
              0.0.0.0          0.0.0.0       10.129.0.1     10.129.43.43     15
           10.129.0.0      255.255.0.0         On-link      10.129.43.43    271
         10.129.43.43  255.255.255.255         On-link      10.129.43.43    271
       10.129.255.255  255.255.255.255         On-link      10.129.43.43    271
            127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
            127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
      127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
          172.16.20.0    255.255.254.0         On-link      172.16.20.45    271
         172.16.20.45  255.255.255.255         On-link      172.16.20.45    271
        172.16.21.255  255.255.255.255         On-link      172.16.20.45    271
            224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
            224.0.0.0        240.0.0.0         On-link      10.129.43.43    271
            224.0.0.0        240.0.0.0         On-link      172.16.20.45    271
      255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
      255.255.255.255  255.255.255.255         On-link      10.129.43.43    271
      255.255.255.255  255.255.255.255         On-link      172.16.20.45    271
    ===========================================================================
    Persistent Routes:
      Network Address          Netmask  Gateway Address  Metric
              0.0.0.0          0.0.0.0      172.16.20.1  Default
    ===========================================================================

    IPv6 Route Table
    ===========================================================================
    Active Routes:
     If Metric Network Destination      Gateway
      4    271 ::/0                     fe80::250:56ff:fe94:53e
      1    331 ::1/128                  On-link
      4    271 dead:beef::/64           On-link
      4    271 dead:beef::142/128       On-link
      4    271 dead:beef::4c23:ae13:b163:f160/128
                                        On-link
      4    271 fe80::/64                On-link
      2    271 fe80::/64                On-link
      4    271 fe80::4c23:ae13:b163:f160/128
                                        On-link
      2    271 fe80::b5a3:a7a6:f420:93d7/128
                                        On-link
      1    331 ff00::/8                 On-link
      4    271 ff00::/8                 On-link
      2    271 ff00::/8                 On-link
    ===========================================================================
    Persistent Routes:
      None


[2025-09-30 13:55:27] Checking security controls...

[+] Windows Defender Status:
    AntiVirus Enabled     : True
    Real-Time Protection  : False
    Behavior Monitoring   : False
    IOAV Protection       : False
    OnAccess Protection   : False
    NIS Enabled           : False
    Signature Age         : 1515 days (POSSIBLY OUTDATED)

[+] Testing Common Executables Against AppLocker Policy:
    C:\Windows\System32\cmd.exe : Denied
    C:\Windows\System32\wscript.exe : Allowed
    C:\Windows\System32\cscript.exe : Allowed
    C:\Windows\System32\mshta.exe : Allowed
    C:\Windows\System32\rundll32.exe : Allowed
    C:\Windows\System32\regsvr32.exe : Allowed
    C:\Windows\System32\scriptrunner.exe : Allowed
    C:\Windows\System32\certutil.exe : Allowed
    C:\Windows\System32\bitsadmin.exe : Allowed
    C:\Windows\System32\at.exe : Allowed
    C:\Windows\System32\schtasks.exe : Allowed
    C:\Windows\System32\winrs.exe : Allowed
    C:\Windows\System32\control.exe : Allowed
    C:\Windows\System32\cmstp.exe : Allowed
    C:\Windows\System32\esentutl.exe : Allowed
    C:\Windows\System32\expand.exe : Allowed
    C:\Windows\System32\extrac32.exe : Allowed
    C:\Windows\System32\findstr.exe : Allowed
    C:\Windows\System32\forfiles.exe : Allowed
    C:\Windows\System32\ftp.exe : Allowed
    C:\Windows\System32\makecab.exe : Allowed
    C:\Windows\System32\mavinject.exe : Allowed
    C:\Windows\System32\odbcconf.exe : Allowed
    C:\Windows\System32\pcalua.exe : Allowed
    C:\Windows\System32\pcwrun.exe : Allowed
    C:\Windows\System32\presentationhost.exe : Allowed
    C:\Windows\System32\print.exe : Allowed
    C:\Windows\System32\replace.exe : Allowed
    C:\Windows\System32\robocopy.exe : Allowed
    C:\Windows\System32\runas.exe : Allowed
    C:\Windows\System32\syncappvpublishingserver.exe : Allowed
    C:\Windows\System32\wbem\wmic.exe : Allowed
    C:\Windows\System32\winsat.exe : Allowed
    C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe : Allowed
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe : Allowed
    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe : Allowed
    C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe : Allowed
    C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe : Denied


[2025-09-30 13:55:29] Enumerating running processes...

[+] Running Processes:
    0: System Idle Process
    4: System
    340: smss.exe
    444: csrss.exe
    548: csrss.exe
    572: wininit.exe
    612: winlogon.exe
    684: services.exe
    700: lsass.exe
    788: svchost.exe
    856: svchost.exe
    964: svchost.exe
    972: svchost.exe
    104: svchost.exe
    376: svchost.exe
    448: dwm.exe
    1052: svchost.exe
    1084: vm3dservice.exe
    1140: svchost.exe
    1192: svchost.exe
    1432: svchost.exe
    1472: svchost.exe
    1812: svchost.exe
    1904: spoolsv.exe
    2040: svchost.exe
    1224: svchost.exe
    1580: svchost.exe
    1464: inetinfo.exe
    2056: sqlwriter.exe
    2076: svchost.exe
    2096: WindscribeService.exe
    2120: svchost.exe
    2148: vmtoolsd.exe
    2156: MsMpEng.exe
    2168: svchost.exe
    2252: Tomcat8.exe
    2288: FileZilla Server.exe
    2364: VGAuthService.exe
    2408: conhost.exe
    3384: sqlservr.exe
    3392: sqlceip.exe
    3456: dllhost.exe
    3632: msdtc.exe
    3660: WmiPrvSE.exe
    4544: svchost.exe
    4952: WmiPrvSE.exe
    5060: RuntimeBroker.exe
    3808: sihost.exe
    3812: svchost.exe
    4716: taskhostw.exe
    3920: GoogleUpdate.exe
    5820: ServerManager.exe
    6080: svchost.exe
    4808: vm3dservice.exe
    5876: vmtoolsd.exe
    5912: FileZilla Server Interface.exe
    6136: csrss.exe
    5812: winlogon.exe
    6164: jusched.exe
    6200: dwm.exe
    6568: rdpclip.exe
        Path: C:\Windows\System32\rdpclip.exe
        Cmd: rdpclip
    6604: sihost.exe
        Path: C:\Windows\system32\sihost.exe
        Cmd: sihost.exe
    6612: svchost.exe
        Path: C:\Windows\system32\svchost.exe
        Cmd: C:\Windows\system32\svchost.exe -k UnistackSvcGroup
    6676: taskhostw.exe
        Path: C:\Windows\system32\taskhostw.exe
        Cmd: taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
    6716: RuntimeBroker.exe
        Path: C:\Windows\System32\RuntimeBroker.exe
        Cmd: C:\Windows\System32\RuntimeBroker.exe -Embedding
    7316: vm3dservice.exe
        Path: C:\Windows\System32\vm3dservice.exe
        Cmd: "C:\Windows\System32\vm3dservice.exe" -u
    7544: jusched.exe
        Path: C:\Program Files (x86)\Common Files\Java\Java Update\jusched.exe
        Cmd: "C:\Program Files (x86)\Common Files\Java\Java Update\jusched.exe"
    6240: cmd.exe
        Path: C:\Windows\system32\cmd.exe
        Cmd: "C:\Windows\system32\cmd.exe"
    6708: conhost.exe
        Path: C:\Windows\system32\conhost.exe
        Cmd: \??\C:\Windows\system32\conhost.exe 0x4
    5416: powershell.exe
        Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        Cmd: powershell.exe  -ep bypass
    6480: msiexec.exe
    5076: WmiApSrv.exe
    1860: taskhostw.exe
    3336: taskhostw.exe
        Path: C:\Windows\system32\taskhostw.exe
        Cmd: taskhostw.exe
    7296: GoogleUpdate.exe
    7096: InstallAgent.exe
    7756: InstallAgent.exe
        Path: C:\Windows\System32\InstallAgent.exe
        Cmd: C:\Windows\System32\InstallAgent.exe -Embedding
    5668: GoogleUpdate.exe
    2400: wuapihost.exe
    2420: WmiPrvSE.exe
    1208: TrustedInstaller.exe
    7560: TiWorker.exe
    3656: explorer.exe
        Path: C:\Windows\explorer.exe
        Cmd: explorer.exe
    7880: explorer.exe
    6740: ShellExperienceHost.exe
        Path: C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
        Cmd: "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
    6736: ShellExperienceHost.exe
    8032: SearchUI.exe
        Path: C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
        Cmd: "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -ServerName:CortanaUI.AppXa50dqqa5gqv4a428c9y1jjw7m3btvepj.mca
    6904: SearchUI.exe
    6724: backgroundTaskHost.exe
        Path: C:\Windows\system32\backgroundTaskHost.exe
        Cmd: "C:\Windows\system32\backgroundTaskHost.exe" -ServerName:CortanaUI.AppXy7vb4pc2dr3kc93kfc509b1d0arkfb2x.mca
    2704: backgroundTaskHost.exe


[2025-09-30 13:55:29] Enumerating user and group information...

[+] Logged-In Users:
     USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
     sccm_svc              console             1  Active      none   9/30/2025 1:48 PM
    >htb-student           rdp-tcp#1           2  Active          .  9/30/2025 1:48 PM

[+] All Users:
    - Administrator
    - DefaultAccount
    - Guest
    - helpdesk
    - htb-student
    - htb-student_adm
    - jordan
    - logger
    - mrb3n
    - sarah
    - sccm_svc
    - secsvc
    - sql_dev

[+] All Groups:
    - Access Control Assistance Operators
    - Administrators
    - Backup Operators
    - Certificate Service DCOM Access
    - Cryptographic Operators
    - Distributed COM Users
    - Event Log Readers
    - Guests
    - Hyper-V Administrators
    - IIS_IUSRS
    - Network Configuration Operators
    - Performance Log Users
    - Performance Monitor Users
    - Power Users
    - Print Operators
    - RDS Endpoint Servers
    - RDS Management Servers
    - RDS Remote Access Servers
    - Remote Desktop Users
    - Remote Management Users
    - Replicator
    - SQLServer2005SQLBrowserUser$WINLPE-SRV01
    - Storage Replica Administrators
    - System Managed Accounts Group
    - Users

[+] Password Policy:
    Force user logoff how long after time expires?:       Never
    Minimum password age (days):                          0
    Maximum password age (days):                          Unlimited
    Minimum password length:                              0
    Length of password history maintained:                None
    Lockout threshold:                                    Never
    Lockout duration (minutes):                           30
    Lockout observation window (minutes):                 30
    Computer role:                                        SERVER


[2025-09-30 13:55:29] Enumeration complete.
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

This project is licensed under the GNU General Public License v3 (GPLv3) - see the [LICENSE](LICENSE) file for details.

<br>

---

<br>

## Disclaimer

This tool is designed for educational purposes and authorized security testing only. The author is not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before using this tool on any system.
