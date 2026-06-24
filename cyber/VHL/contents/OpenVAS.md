# OpenVAS

Advanced open source vulnerability scanner and manager. Has more than 82,000 Network Vulnerability TEsts (NVTs).

## Installing OpenVAS 11 on Kali

Recommended to to install a fresh Kali Linux 2020+ VM to run OpenVAS /GVM. 
Requires at least 2 CPU cores, and 4gb of RAM. 

```bash
sudo apt-get update
sudo apt-get install gvm
sudo gvm-setup

### The installation will take a long time. 
### Once complete, the password will be displayed to the screen and require login + change.

#Start the services
sudo gvm-start

#To stop
sudo gvm-stop
```

## Connecting

The service should be listening on `https://127.0.0.1:9392` which can be reached in the browser, using the `admin` user, and the password displayed / changed during setup. Forgot the password?
`sudo gvmd --user=[username] --new-password=[password]` 
`sudo gvmd --user=admin --new-password=[password]`

## Scanning

Three step process:

1. Create and configure a scan task.
   * Select `Scans` -> `Tasks` -> `New Document` -> `New Task`
   * Add a Scan Target
   * Supply authenticated credentials (optional) for SSH/SMB/ESXi/SNMP
2. Create and configure a target
3. Optionally create a custom scan configuration or use a default configuration.

Once a scan task and target are complete, select `Save` then `Start ` from the Actions column. The full and fast selection option can take a while to complete. Once complete, the results can be exported to a .pdf.



