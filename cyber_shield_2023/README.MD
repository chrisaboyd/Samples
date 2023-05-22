## Cyber Security Reference Sheet

### Security Onion

Security Onion is a free and open source Linux distribution for threat hunting, enterprise security monitoring, and log management.
It includes Elasticsearch, Logstash, Kibana, Snort, Suricata, Zeek, Wazuh, Sguil, Squert, NetworkMiner, and many other security tools.  
[Documentation Reference](https://docs.securityonion.net/en/2.3/)
```

# Update the system
sudo soup

# Check sensor stats
so-sensor-status

# Check status of all Security Onion services
sudo so-status

# Query logs using Sguil
sguil-client

# Start Squert web interface
squert

# Access Kibana interface
so-kibana

# Access CapMe for PCAP retrieval
so-capme

# Start NetworkMiner
networkminer

# Accessing Zeek logs
zless /nsm/zeek/logs/current/conn.log

# Stopping Zeek 
sudo so-zeek-stop

# Starting Zeek
sudo so-zeek-start

# Run Suricata in IDS mode
suricata -c /etc/suricata/suricata.yaml -i eth0

# Update Suricata rules
sudo suricata-update

# Check the status of Suricata
sudo systemctl status suricata

# Tail Suricata fast.log file
tail -f /var/log/suricata/fast.log
```

### Vyatta

Vyatta provides software-based virtual router, virtual firewall and VPN products for Internet Protocol networks.  
[Documentation Reference](http://www.brocade.com/content/html/en/configuration-guide/vyatta_icg_preface.html)
```
# Show version and system information
show version

# Show interfaces
show interfaces

# Show IP routing table
show ip route

# Show DHCP client leases
show dhcp client leases

# Configure system parameters
configure

# Add a firewall rule
set firewall name rule number

# Save configuration changes
commit

# Discard uncommitted changes
discard

# Exit from configuration mode
exit

# Show firewall configurations
show firewall

# Show NAT translations
show nat translations

# Show VPN ipsec settings
show vpn ipsec sa

# Show system log
show log

# Clear firewall counters
clear firewall counters

# Restart the webproxy service
restart webproxy
```

### Ubuntu

Ubuntu is an open-source software platform that runs everywhere from the PC to the server and the cloud.  
[Documentation Reference](https://help.ubuntu.com/)

```
# Update package lists for upgrades and new package installations
sudo apt update

# Upgrade all upgradable packages
sudo apt upgrade

# Search for package in the package lists
apt-cache search <package>

# Install a new package
sudo apt install <package>

# Remove a package
sudo apt remove <package>

# Check disk space
df -h

# Display directory contents
ls -alh

# Navigate to a directory
cd <directory>

# Create a new directory
mkdir <directory>

# Create a new file or update the access/modification time if it exists
touch <file>

# Display the contents of a file
cat <file>

# Edit a file (with nano editor)
nano <file>

# Download a file from the internet
wget <url>

# Monitor system processes
top

# Monitor system logs
tail -f /var/log/syslog

# Check network connectivity
ping <host>

```

### Kali

Kali Linux is a Debian-based Linux distribution aimed at advanced Penetration Testing and Security Auditing.   
[Documentation Reference](https://www.kali.org/docs/)
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
