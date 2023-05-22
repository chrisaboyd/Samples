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
