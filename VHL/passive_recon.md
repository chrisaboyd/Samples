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
    * `marketplace search` or `marketplace search hibp` - List available modules
    * `marketplace install recon/contacts-credentials/hibp-breach` - Install this module; requires an API key for HIBP and is $3.50 per month
    * `keys add hip_api [API key]` to add your API key; (https://www.troyhunt.com/authentication-and-the-have-i-been-pwned-api/)[https://www.troyhunt.com/authentication-and-the-have-i-been-pwned-api/]
    * `modules load recon/contacts-credentials/hibp_breach` - Load the module
    * Only needed field is the source field for the e-mail address to search for
    * `options set SOURCE info@microsoft.com` - command to set the search
    * `run` to execute the search
    * All results are stored in a database - can use `show credentials` to show the table 

## Other Search Tools

https://www.google.com
https://www.google.com/maps
https://www.exploit-db.com/google-hacking-database/
https://www.shodan.io
https://www.tineye.com
https://www.netcraft.com
https://pastebin.com
https://haveibeenpwned.com

## Collecting Company Info

* Linkedin! Provides info about people, processes, technologies, products. 
* Used to see what relationships exist with other companies
* Employees which in turn can be used to gather data about technologies in place
* EDGAR - Electronic Data Gathering Analysis and Retrieval System for companies registered with SEC'
  * https://www.sec.gov/edgar/searchedgar/companysearch.html
* California, Nevada and Delaware are also popular for business registrations
  * https://businesssearch.sos.ca.gov
  * https://esos.nv.gov/EntitySearch/OnlineEntitySearch
* Crunchbase - online database of business information about private and public companies, like investment, financing, mergers and acquisitions, founding members, and leadership / C-suite.