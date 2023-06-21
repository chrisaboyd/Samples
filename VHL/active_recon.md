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
  * [NSE Usage](https://nmap.org/book/nse-usage.html)

* SNMP Enumeration - Operates at layer 7, uses UDP 161. Supports by routers, switches, servers, printers, NAS, firewalls, WLAN controllers, etc. Communicates with each other using the MIB - Management Information Base. 

  * Comprised of 3 components:

    * Managed Device - Also known as a node, is a network device with SNMP enabled and uni or bi-directional communication. Can be any networked device.
    * Agent - Software / service running on the managed device responsible for communication. Translates device specifics into SNMP format.
    * Network Management System (NMS) - The server - software that manages and monitors the networked devices.

  * SNMP Commands - The protocol uses several commands to communicate, and categorized as read, write, trap, and traverse.

    * Read - Sent by NMS to nodes for monitoring
    * Write - Used to control the nodes in the network
    * Trap - unsolicited SNMP messages from an agent **TO** the NMS to inform events like errors
    * Traversal - Check what information is retained on a managed device and retrieve.

    