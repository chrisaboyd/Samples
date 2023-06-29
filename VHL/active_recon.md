## Enumeration

Network enumeration is the process of retrieving usernames, shares, services, web directories, groups, and computers.
Enumerating involved port scanning, fingerprinting services, and applications. 

### Host Discovery

**Netdiscover** -Active / Passive ARP reconnaissance to find live hosts

* ` netdiscover -r 10.11.1.0/24` - Scans the subnet for hosts

**Nmap** - Scans for host discovery on the local / remote network

* `nmap -sn 10.11.1.0/24` - does a default ping scan with ICMP to 443 and 80

* `nmap -Pn` - disables host discovery; useful when target is up, but not responding to ICMP 

* [Host Discovery](https://nmap.com/book/man-host-discovery.html)

* [Port Scanning](https://nmap.org/book/man-port-scanning-techniques.html)

* https://nmap.com/book/man.html

* TCP Connect Scan - when SYN scan is not an option, or raw packets can't be send, such as when you do not have root access. Instead, relies on the OS `connect` syscall to establish a connection to a target host:port. Completes a three way handshake over tcp. Because it must complete the hand-shake, is typically much slower.

  * `nmap -sT 10.11.1.3` - **SLOW** initiates the TCP connect scan
  * `sudo nmap -sS 10.11.1.3` - **FAST** - TCP syn scan - does not complete a 3-way handshake. Requires root.

* UDP Port Scanning - DNS (53), NTP (123), SNMP (161/162) are some common UDP services. Generally UDP is much slower and techniques are different. Vulnerable UDP services are common.

  * `nmap -sU 10.11.1.3` - UDP scans, but **VERY SLOW**.

* **Fingerprinting** - Identify services and map to known ports.

  * `nmap -sV 10.11.1.3` - Scan with service detection
  * `sudo nmap -sV -O 10.11.1.3` - Detecs services and OS
  * `sudo nmap -A 10.11.1.3` - LOUD and aggressive. Scans OS, versions, script scanning, and trace route. Takes a long time to run, and ideally run with root. Skips options if not run with root such as OS detection. Generates a lot of network traffic, and can crash unstable services such as ICS.
  * A good practice is to determine open ports with a SYN scan `sudo nmap -sS 10.11.1.3` , then follow up with an aggressive scan on specific ports - `sudo nmap -A -p 80,443,556 10.11.1.3` 
  * [Reducing Scantimes](https://nmap.org/book/reduce-scantime.html)
  * Scan UDP + TCP - `sudo nmap -sU -sS -p U:137-139,T:137-139,445 10.11.1.3`

* **Nmap Scripting Engine** - extension that uses LUA to automate discovery / vulnerability detection

  * [NSE](https://nmap.org/book/nse.html)
  * [LUA](http://www.lua.org/)
  * Updating Nmap - `sudo apt-get update && sudo apt-get install nmap` 
  * Update Script database - `sudo nmap --script-updatedb`
  * `/usr/share/nmap/scripts` - default directory for nmap scripts. 
    * Naming convention is prefixed with protocol - _http_, _ftp_, _snmp_, _mysql_ , _smb_ , etc.
  * `nmap --script-help ftp-anon` - Most scripts have help functions with instructions
  * `nmap --script=http-robots.txt 10.11.1.3` - Executes the script 
  * `nmap --script snmp-sysdescr --script-args creds.snmp=admin 10.11.1.3` - Passing arguments as vars
  * `nmap --script snmp-sysdescr --script-args-file /tmp/test.txt 10.11.1.3` - Passing args via file
  * What if you don't have a script? 
    * `wget https://svn.nmap.org/nmap/scripts/smb-vuln-ms17-010.nse -O /usr/share/nmap/scripts/smb-vuln-ms17-010.nse` 
    * `nmap --script-updatedb` to make it available to nmap afterwards
  * [NSE Usage](https://nmap.org/book/nse-usage.html)

* **SNMP Enumeration** - Operates at layer 7, uses UDP 161. Supports by routers, switches, servers, printers, NAS, firewalls, WLAN controllers, etc. Communicates with each other using the MIB - Management Information Base. 

  * Comprised of 3 components:
    * Managed Device - Also known as a node, is a network device with SNMP enabled and uni or bi-directional communication. Can be any networked device.
    * Agent - Software / service running on the managed device responsible for communication. Translates device specifics into SNMP format.
    * Network Management System (NMS) - The server - software that manages and monitors the networked devices.
  * SNMP Commands - The protocol uses several commands to communicate, and categorized as read, write, trap, and traverse.
    * Read - Sent by NMS to nodes for monitoring
    * Write - Used to control the nodes in the network
    * Trap - unsolicited SNMP messages from an agent **TO** the NMS to inform events like errors
    * Traversal - Check what information is retained on a managed device and retrieve.
  * Uses indexed numbers with dots to refer to objects / values like `1.3.6.1.2.1.1.6` - sysLocation
  * SNMP Community Strings - like a username / password to access the managed device. 
    * SNMPv1 and SNMPv2 _usually_ ship with defaults - `public` for read-only, and `private` for read-write. 
    * SNMPv3 replaces with username + password authentication
    * Because some devices ship out of the box with SNMP enabled, checking for public / private strings is a good check.
  * **Onesixtyone** - fast tool to brute force SNMP community strings.
    * Supply two arguments - one with a list of community strings, and a target host IP
      * `onesixtyone` - for instructions
      * `onesixtyone -c dict.txt -i hosts -o my.log -w 100`
      * [Onesixtyone](http://www.phreedom.org/software/onesixtyone/)
  * **SNMPwalk** - queries MIB values, but requires a read-only community string
    * `snmpwalk --help` 
    * `snmpwalk -c public -v1 10.11.1.3` - Runs snmpwalk on an SNMPv1 device with string `public` 
    * `snmpwalk -c public -v1 10.11.1.3 [oid]` - to request a specific singular object ID (OID)
    * Nmap SNMP script - `ls -l /usr/share/nmap/scripts/snmp*` 

* **SMB Enumeration** - Server Message Block file sharing protocol on a local network. Allows for unauthenticated IPC (inter-process communication). Latest version is 3.1.1 in Windows 10. When client and server mismatch versions, the highest version BOTH support is used.

  * | SMB Version | Windows Version                                       |
    | ----------- | ----------------------------------------------------- |
    | CIFS        | Microsoft Windows NT 4.0                              |
    | SMB 1.0     | WIndows 2000, Windows XP, Server 2003, Server 2003 R2 |
    | SMB 2.0     | Windows Vista, Windows Server 2008                    |
    | SMB 2.1     | Windows 7, Windows Server 2008 R2                     |
    | SMB 3.0     | Windows 8, Windows Server 2012                        |
    | SMB 3.0.2   | Windows 8.1, Windows Server 2012 R2                   |
    | SMB 3.1.1   | Windows 10, Windows Server 2016                       |

    **Fantastic** attack vector - many vulnaerabilities exist, even on the latest SMB 3.1.1

  * *CVE-2017-0143* - Believed to be stolen from NSA, targets Windows XP through Server 2016. 

  * *MS08-067 Netapi* - present in unpatched Windows XP and Server 2003 installation.

  * Uses the following Ports:

    * netbios-ns 137/tcp # NETBios Name Service
    * netbios-ns 137/udp
    * netbios-dgm 138/tcp #NETBios Datagram Service
    * netbios-dgm 138/udp
    * netbios-ssn 139/tcp # Session Service
    * netbios-ssn 139/udp
    * microsoft-ds 445/tcp # IF using Active Directory

  * **rpcclient** - Linux tool to execute MS-RPC functions. A null session with samba or SMB does not require authentication with a password. Default on legacy, but mostly disabled. Uses port 445.

    * `rpcclient -U "" 10.11.1.17` - the `-U` defines a null username - enter a blank password when prompted
    * `querydominfo` - Returns domain, server, users on the system
    * `enumdomusers` - Retrieve a list of users present on the system
    * `queryuser [username]` - Query for more specific details about a user
    * `queryuser pbx`, `queryuser 1000` and `queryuser 0x3e8` are all valid 
    * If using a null session on a Metasploitable machine, you might get `Cannot connect to server. Error was NT_STATUS_CONNECTION_DISCONNECTED`. If this happens, the minimum protocol is `SMB2_02` . You can update the minimum version by updating /etc/samba/smb.conf and setting: 
      * `client min protocol = CORE` 

  * **RID Cycling** - Enumerating users over a null session. `enumdomusers` won't work on all systems, and if it's not supported you wont get meaningful output, and total users will show 0. RID is a relative identifier, of variable length assigned to objects, and become part of an SID (security identifier). 

    * Can determine an SID via `lookupnames [user]`
    * RIDS between `500-1000` are for System accounts. RIDS between `1000-10000` are for Domain users and groups
    * We can use this to query for users, such as:
      * `lookup names pbx` returns `S-1-5-21-532510730-1394270290-3802288464` 
      * Add `-500` to the end and lookupsids: `lookupsids S-1-5-21-532510730-1394270290-3802288464-500` - returns unknown, so lets increment by 1
      * `lookupsids S-1-5-21-532510730-1394270290-3802288464-501` - Returns `PBX\nobody` - a valid user
      * `lookupsids S-1-5-21-532510730-1394270290-3802288464-1000` - Returns `PBX\pbx` - A valid user
      * The same behavior applies for groups:
        * `lookupnames administrators` - Returns `S-1-5-32-544` - A common known user group 
        * The 544 is the RID - so we can change this value to cycle through the rest of the groups:
        * `lookupsids S-1-5-32-546`, `lookupsids S-1-5-32-550` etc.

  * **Enum4linux** - Linux alternative to enum.exe. Written in perl, and a wrapper for smbclient, rpclient, net, and nmblookup.

    * `./enum4linux.pl [options] [ip]`

    * | Flag    | Detail                                             |
      | ------- | :------------------------------------------------- |
      | -U      | Userlist                                           |
      | -M      | Machine list                                       |
      | -S      | Shapeliest                                         |
      | -P      | Password Policy Info                               |
      | -G      | Get group and member list                          |
      | -u user | Specify username - default ""                      |
      | -p pass | Specify password - default ""                      |
      | -a      | Do all simple enumerations -U -S -G -P -r -o -n -i |
      | -o      | OS Information                                     |
      | -i      | Printer Information                                |

  * **Nmap SMB Scripts** - Nmap has a lot - `ls -l /usr/share/nmap/scripts/smb*`

    * `nmap -p 139,445 --script=smb-os-discovery 10.11.1.2` - Runs the OS discovery script
    * `nmap -p 139,445 --script=smb-vuln* 10.11.1.2` - Scans target for all known SMB vulnerabilities
    * **MS17-010 Eternalblue** - Exploits critical vulnerability in SMBv1, and leaves many Windows installations open to RCE. 
      * `nmap -p 445 --script=smb-vuln-ms17-010 10.11.1.13` - Checks to get RCE with system privileges

* **Web Servers** - very common attack vector. Most common are Apache and IIS. Vulnerable to a wide array of exploits, local and remote file inclusion, remote code execution, DoS.

  * Upload a trojan using file upload and execute in context of the webserver
  * Local file inclusion to read contents of /etc/passwd, then use to brute force passwords
  * Read contents of web application config files, like wp-config.php which contains sensitive info
  * **Nikto** - webserver assesment tool. Written in Perl, and standard in Kali. 
    * Quickly enumerate a webserver, web applications running on it, and test for common vulnerabilities
    * Scans for misconfigurations, default files / folders, and outdated software.
    * Not stealthy - generates a lot of requests and fairly obvious.
    * `nikto -h 10.11.1.2`
    * `nikto -p 8080 -h 10.11.1.35` - scan on a different port 
    * `nikto -h 10.11.1.35 -p 80,443,8080` - scan on multiple ports
    * [Scan Tuning](https://github.com/sullo/nikto/wiki/Scan-Tuning) - Define what to test on target host with -Tuning parameters
  * **DIRB** - web content scanner comes pre-configured with wordlists, but can use customized wordlists
    * `dirb [URL]` like `dirb http://10.11.1.2` 
    * `dirb http://10.11.1.2 [wordlist]` - to specify your own custom wordlist
  * **Dirbuster** - web content scanner, multi-threaded with GUI and more wordlists. 
    * `/usr/share/dirbuster/wordlists/` directory for wordlists 
    * Run by `dirbuster` - enter a target URL, number of threads, wordlist to use and `start` 
    * A good wordlist is the most effective tool for DIRB and Dirbuster
    * Tuning - 
      * Wordlist file `/usr/share/wordlists/dirb/common.txt` 
      * Starting options - Brute force dirs (disable brute force files and "Be recursive")
      * Number of threads - 200
    * Once enumerated, you can view the directories in browser if directory listing is enabled
  * **Netcat** - can interact with web servers!
    * `nc 10.11.1.2 80` to connect - then `HEAD / HTTP/1.0` to return with the banner
    * `GET / HTTP/1.0` to return the top level page

* **Web Application Scanners** 

  * **WPScan** - scans for known vulnerabilities in WordPress, enumerate users, themes, plugins, and run dictionary attacks on user accounts. 

    * Free plan includes 25 api requests a day 

    * `wpscan --update` always update to latest database. 

    * **Do not run without explicit, written, prior permission from website owner**.

    * `wpscan --url http://10.11.1.7 --api-token <token>` - 

    * **Active enumeration** - Tests every plugin in the database to determine if present. Usually much more reliable, but noisy, and time consuming. 

      ```bash
      -p - Popular plugins only
      -vp - Vulnerable plugins only
      -ap - All plugins
      
      -t - Popular themes only
      -vt - Vulnerable themes only
      -at - All themes
      
      #Full command with enumeration; `p` means popular plugins only:
      wpscan --url http://10.11.1.17 --enumerate p --plugins-detection aggressive
      
      #Scan all plugins:
      wpscan --url http://10.11.1.17 --enumerate ap --plugins-detection aggressive
      ```

    * **Enumerating Users** - results can be unreliable, as good practice is to note reveal usernames on WordPress. 

      * `wpscan --url http://10.11.1.17 --enumerate u`

      * [WPScan](https://github.com/wpscanteam/wpscan)

      * [VPVulnDb](https://wpvulndb.com/)

        