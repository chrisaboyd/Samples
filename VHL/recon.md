## Nslookup

* `nslookup -type=mx prefect.io` # Lookup mx records from prefect.io domain
* `nslookup -type=axfr`  # Conduct Zone transfer 

```bash
#Check for zone transfer records on google.com
host -t axfr -l google.com ns1.google.com
#Dig for zone transfer records on zonetransfer.me
dig axfr zonetransfer.me
```

## Tools

- Fierce - recon tool in perl to locate non-contiguous IP space and hostname using DNS

  - `fierce --domain google.com` #ind out details about htis domain

  - ```bash 
    fierce --domain google.com --subdomain-file [path to wordlist] 
    # if subdomains.txt has : accounts help support
    # then this will scout
    - help.google.com
    - accounts.google.com
    - support.google.com
    ```

- `sublist3r` - Python tool for enumerating subdomains using public data source. 
  - Has option to brute force subdomains using Subbrute - extensive wordlist and open resolvers to circumvent rate limiting issues
  - `sudo apt update && apt -y install sublist3r` - Install
  -  `sublist3r -d google.com ` - Configure a default scan
  - `sublist3r -d google.com -b -t 100 -e google -v`
    -  -b applies brute-forcing with subbrute
    - -t 100 specifies threads
    - -e google specifies search engine 
    - -v for verbose
- `dnsenum <domainname>` - Perl script that can be used to enumerate the DNS information of a domain
- `dnsrecon -h` # For available options - automated tool to query DNS records
- `dig -t any google.com @8.8.8.8` - Check all records against google.com with 8.8.8.8 as the ns 
- `whois`
- `host`
- `nslookup`
- `fierce`

## E-mail Harvesting

* The Harvester - used for e-mail harvesting via different search engines
  * `apt-get update && apt-get install theharvester`
  * `theHarvester -h` for help options
  * `theHarvester -d cisco.com -b yahoo -l 100` 
    * -d for domain
    * -b for data source
    * -l 100 for limiting to 100 results
* `Recon-ng` - recon framework like metasploit. Can automate e-mail harvesting
  * `recong-ng --version` - If on version 4, upgrade to v5
  * `apt-get install recon-ng` - To upgrade
  * `recon-ng` - Start the application
    * `marketplace refresh` - update the modules list and install
    * `marketplace search