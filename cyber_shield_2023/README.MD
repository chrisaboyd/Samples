## Cyber Security Reference Sheet

### Security Onion

Security Onion is a free and open source Linux distribution for threat hunting, enterprise security monitoring, and log management.
It includes Elasticsearch, Logstash, Kibana, Snort, Suricata, Zeek, Wazuh, Sguil, Squert, NetworkMiner, and many other security tools.  
[Documentation Reference](https://docs.securityonion.net/en/2.3/)

| Command | Detail |
| --- | --- |
| `sudo soup` | Update the system |
| `so-sensor-status` | Check sensor stats |
| `sudo so-status` | Check status of all Security Onion services |
| `sguil-client` | Query logs using Sguil |
| `squert` | Start Squert web interface |
| `so-kibana` | Access Kibana interface |
| `so-capme` | Access CapMe for PCAP retrieval |
| `networkminer` | Start NetworkMiner |
| `zless /nsm/zeek/logs/current/conn.log` | Accessing Zeek logs |
| `sudo so-zeek-stop` | Stopping Zeek |
| `sudo so-zeek-start` | Starting Zeek |
| `suricata -c /etc/suricata/suricata.yaml -i eth0` | Run Suricata in IDS mode |
| `sudo suricata-update` | Update Suricata rules |
| `sudo systemctl status suricata` | Check the status of Suricata |
| `tail -f /var/log/suricata/fast.log` | Tail Suricata fast.log file |

### Vyatta

Vyatta provides software-based virtual router, virtual firewall and VPN products for Internet Protocol networks.  
[Documentation Reference](http://www.brocade.com/content/html/en/configuration-guide/vyatta_icg_preface.html)

| Command | Detail |
| --- | --- |
| `show version` | Show version and system information |
| `show interfaces` | Show interfaces |
| `show ip route` | Show IP routing table |
| `show dhcp client leases` | Show DHCP client leases |
| `configure` | Configure system parameters |
| `set firewall name rule number` | Add a firewall rule |
| `commit` | Save configuration changes |
| `discard` | Discard uncommitted changes |
| `exit` | Exit from configuration mode |
| `show firewall` | Show firewall configurations |
| `show nat translations` | Show NAT translations |
| `show vpn ipsec sa` |  Show VPN ipsec settings |
| `show log` | Show system log |
| `clear firewall counters` | Clear firewall counters |
| `restart webproxy` | Restart the webproxy service |

### Ubuntu

Ubuntu is an open-source software platform that runs everywhere from the PC to the server and the cloud.  
[Documentation Reference](https://help.ubuntu.com/)

| Command | Detail |
| --- | --- |
| `sudo apt update` | Update package lists for upgrades and new package installations |
| `sudo apt upgrade` | Upgrade all upgradable packages |
| `apt-cache search <package>` | Search for package in the package lists |
| `sudo apt install <package>` | Install a new package |
| `sudo apt remove <package>` | Remove a package |
| `df -h` | Check disk space |
| `ls -alh` | Display directory contents |
| `cd <directory>` | Navigate to a directory |
| `mkdir <directory>` | Create a new directory |
| `touch <file>` |  Create a new file or update the access/modification time if it exists |
| `cat <file>` | Display the contents of a file |
| `nano <file>` | Edit a file (with nano editor) |
| `wget <url>` | Download a file from the internet |
| `top` | Monitor system processes |
| `tail -f /var/log/syslog` | Monitor system logs |
| `ping <host>` | Check network connectivity | 

### Kali

Kali Linux is a Debian-based Linux distribution aimed at advanced Penetration Testing and Security Auditing.   
[Documentation Reference](https://www.kali.org/docs/)

| Command | Detail |
| --- | --- |
| `sudo soup` | Update the system |
| `so-sensor-status` | Check sensor stats |
| `sudo so-status` | Check status of all Security Onion services |
| `sguil-client` | Query logs using Sguil |
| `squert` | Start Squert web interface |
| `so-kibana` | Access Kibana interface |
| `so-capme` | Access CapMe for PCAP retrieval |
| `networkminer` | Start NetworkMiner |
| `zless /nsm/zeek/logs/current/conn.log` | Accessing Zeek logs |
| `sudo so-zeek-stop` | Stopping Zeek |
| `sudo so-zeek-start` | Starting Zeek |
| `suricata -c /etc/suricata/suricata.yaml -i eth0` | Run Suricata in IDS mode |
| `sudo suricata-update` | Update Suricata rules |
| `sudo systemctl status suricata` | Check the status of Suricata |
| `tail -f /var/log/suricata/fast.log` | Tail Suricata fast.log file |
```
# Update package lists for upgrades and new package installations
sudo apt update

# Upgrade all upgradable packages
sudo apt upgrade

# Start the Metasploit Framework
msfconsole

# Start Wireshark
sudo wireshark

# Launch Burp Suite
burpsuite

# Use Nmap to scan a host/network
nmap <host>

# Use SQLMap to automate SQL injection discovery and exploitation
sqlmap

# Capture network packets (needs interface in monitor mode)
airodump-ng <interface>

# Start the Aircrack-ng tool to crack wireless networks
aircrack-ng

# Use Hydra for brute forcing
hydra

# Sniffing and spoofing with Ettercap
sudo ettercap -G

# File and directory brute forcing with DirBuster
dirbuster

# SSL/TLS analysis with SSLyze
sslyze

# Use Nikto for web server scanning
nikto -h <host>

# Use John the Ripper for password cracking
john

# DNS reconnaissance with dnsrecon
dnsrecon -d <domain>
```

### windows 10

Windows 10 is a series of personal computer operating systems produced by Microsoft as part of its Windows NT family of operating systems.  
[Documentation Reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)

| Command | Detail |
| --- | --- |
| `sudo soup` | Update the system |
| `so-sensor-status` | Check sensor stats |
| `sudo so-status` | Check status of all Security Onion services |
| `sguil-client` | Query logs using Sguil |
| `squert` | Start Squert web interface |
| `so-kibana` | Access Kibana interface |
| `so-capme` | Access CapMe for PCAP retrieval |
| `networkminer` | Start NetworkMiner |
| `zless /nsm/zeek/logs/current/conn.log` | Accessing Zeek logs |
| `sudo so-zeek-stop` | Stopping Zeek |
| `sudo so-zeek-start` | Starting Zeek |
| `suricata -c /etc/suricata/suricata.yaml -i eth0` | Run Suricata in IDS mode |
| `sudo suricata-update` | Update Suricata rules |
| `sudo systemctl status suricata` | Check the status of Suricata |
| `tail -f /var/log/suricata/fast.log` | Tail Suricata fast.log file |
```
# Display IP configuration
ipconfig /all

# Flush DNS cache
ipconfig /flushdns

# Check network connectivity
ping <host>

# Trace the route a packet takes to reach a host
tracert <host>

# Display active network connections
netstat -ano

# Open Windows Firewall settings
wf.msc

# Open Task Manager
taskmgr

# Open Resource Monitor
resmon

# Run a program as administrator
runas /user:<User> <command>

# List all running services
sc query

# Start a service
sc start <service>

# Stop a service
sc stop <service>

# List local users
net user

# Add a new user
net user /add <username> <password>

# Change a user's password
net user <username> *

# View system logs
eventvwr.msc
```
