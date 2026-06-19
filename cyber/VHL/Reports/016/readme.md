# Pentest 16 - Quick - 20 - 10.14.1.20

## Scanning and Enumerating


### Nmap
```bash
Nmap scan report for 10.14.1.20
Host is up, received user-set (0.14s latency).
Scanned at 2023-08-06 15:21:26 EDT for 36s
Not shown: 984 closed tcp ports (reset)
PORT      STATE    SERVICE       REASON         VERSION
21/tcp    open     ftp           syn-ack ttl 63 vsftpd 3.0.3
22/tcp    open     ssh           syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7f:80:87:eb:84:af:0d:b6:f5:11:fb:d5:d0:6d:f4:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8mfElx2cHY+nfyVRvvJ5iNEasa9lOKI3SI1iqQdwKda4PO+a9JFrxYmmyA0+T/9IaFL4+MOaySN7ZUYVfHexrErUkloB7py/cgXkO2mrDrM2r/s7EUP9TDk9sbQ/o2xW2w38wEKynluh0eIVrIMVzOmz7qJWLpVk1z5SKSKTqOyiGaXege8KPLMbJ217e+EGV//bBlUsEY45+wxbMMJF+G7abuwx77/kYladcDEWPQ03YIriYKBvvBBrxm7INhWw9xTjS9ig+PQs9XoVUY1eVJ5w1hF96OGD2EPSgR/5cSPQ8qsYBEa6jUyIDQEgGAvEs1614VWHSWb6lpGCI0/OFaDn/MLljbUisa4hz1WEjWPBrUcxW4yaZYhio1y+4TS0+kdkmpspfj5eTpOw/j99NnBuIaaRFgJF8H7qPBvd1isFcTUdfxfvx1QG/MZOAg81nwNpRFMGSlm5cB35TWxYE6XgLICb1Rk9YJIO/KkSQAUVLTaps63DAUkZouYVnEzE=
|   256 24:c5:af:74:66:67:5f:a6:2d:a4:87:0d:0c:cf:60:c9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE/WjWFcGmmQNLodzIonma4N4F6xJZ1PHfN18Ou9zytVjGZftlgupqIIc+lrHa3RaA0u1dAfdXlpG5GIOySOBnE=
|   256 33:31:bc:a5:58:bf:aa:90:c0:fe:2d:b0:d7:b1:00:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOkwZEb3dAs6rDkE3LCsT85EgfhIca6rmkqppAnxkjJQ
80/tcp    open     http          syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: Quick.Cms v6.7
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Quick.Cms - fast and simple content management system
|_http-favicon: Unknown favicon MD5: 3BB71C2058BAE9B643043DD3EA8B57FF
691/tcp   filtered resvc         no-response
1042/tcp  filtered afrog         no-response
1081/tcp  filtered pvuniwien     no-response
1501/tcp  filtered sas-3         no-response
2119/tcp  filtered gsigatekeeper no-response
2260/tcp  filtered apc-2260      no-response
3827/tcp  filtered netmpi        no-response
7200/tcp  filtered fodms         no-response
7999/tcp  filtered irdmi2        no-response
8193/tcp  filtered sophos        no-response
10024/tcp filtered unknown       no-response
10180/tcp filtered unknown       no-response
54328/tcp filtered unknown       no-response
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 4.4 (96%), Linux 2.6.32 or 3.10 (95%), Linux 2.6.32 - 2.6.35 (94%), Linux 2.6.32 - 2.6.39 (94%), Linux 4.0 (94%), Linux 5.0 - 5.4 (93%), Linux 3.11 - 4.1 (92%), Linux 3.2 - 3.8 (92%), Linux 2.6.18 (92%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/6%OT=21%CT=1%CU=38898%PV=Y%DS=2%DC=I%G=Y%TM=64CFF2DA
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=107%TI=Z%TS=A)SEQ(SP=106%GCD
OS:=1%ISR=107%TI=Z%II=I%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11
OS:NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE8
OS:8%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)
OS:T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%
OS:T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)T6(R=N)T7(R=N)U1(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 22.115 days (since Sat Jul 15 12:37:00 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT       ADDRESS
1   144.21 ms 10.14.1.20

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  6 15:22:02 2023 -- 1 IP address (1 host up) scanned in 35.27 seconds

```

OS Type: `Linux 2.6.32 (96%)`

| Port | Service | Protocol | Version |
| -----| ------- | -------- | ------- |
| 21   | FTP | TCP | vsftpd 3.0.3 |
| 22  | SSH | TCP | OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 |
| 80   | HTTP | TCP | Apache httpd 2.4.41 |



### Nikto
```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.14.1.20
+ Target Hostname:    10.14.1.20
+ Target Port:        80
+ Start Time:         2023-08-06 15:22:02 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /admin.php?en_log_id=0&action=config: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /admin.php?en_log_id=0&action=config: EasyNews version 4.3 allows remote admin access. This PHP file should be protected. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5412
+ /admin.php?en_log_id=0&action=users: EasyNews version 4.3 allows remote admin access. This PHP file should be protected. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5412
+ /admin.php: This might be interesting.
+ /files/: Directory indexing found.
+ /files/: This might be interesting.
+ /database/: Directory indexing found.
+ /database/: Database directory found.
+ 7730 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2023-08-06 15:42:13 (GMT-4) (1211 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## Exploitation

### Initial Access

First I loaded up the webpage, and attempted to test out CVE-2006-5412 that I found from Nikto - there was nothing available here however.
![image1](/VHL/Reports/016/images/16_1.png)

I then procedeed to dig through some of the other enumerated files - /database ?
This yielded pretty quick results to get into the CMS system.
![image2](/VHL/Reports/016/images/16_2.png)

| User | Pass |
| ---- | ---- | 
| admin@localhost.local | admin123 | 

I poked around to see if there was anything obvious - I first attempted to upload a reverse shell as the language file, and triggering it by navigating to the page it generated, but this didn't yield any success.

I did have / find [this](https://www.exploit-db.com/exploits/49494) resource available when I was initially researching the services running.
![image3](/VHL/Reports/016/images/16_3.png)

This got me a shell very quickly. 

### Privilege Escalation

Once I had a shell, I enumerated the system to see what was vulnerable on the system. 
`python3.8` had `cap_chown+ep` which means, it has root permissions to change the ownership of items.
![image4](/VHL/Reports/016/images/16_4.png)

I already had a good idea of what to do here - because I could chown files from root to myself, I could do so with `/etc/shadow` and modify the root password.
If I wanted to be less obvious, I could do this with `/etc/passwd` and an unassuming user like `nginx` or something, but with the uid set to 0.
I opted just to update `/etc/shadow` here.
![image5](/VHL/Reports/016/images/16_5.png)

First I created a salted password:
![image6](/VHL/Reports/016/images/16_6.png)

Then I updated `/etc/shadow` with vim; this was honestly pretty challenging, because the terminal was interpreting my `i` and delete commands as things like `[^r` and what not.
I just prepped another root line with the modified password, and closed my eyes while inserting that line, and deleting the original root line that was pushed down.

![image7](/VHL/Reports/016/images/16_7.png)
![image8](/VHL/Reports/016/images/16_8.png)
![image9](/VHL/Reports/016/images/16_9.png)

This did the trick, and we got root. 

## Identified Vulnerabilities

- [CVE-2020-35754](https://nvd.nist.gov/vuln/detail/CVE-2020-35754)

## Remediation

The main factor(s) leading to initial access included:  
- The /database directory was being enumerated, containing a config file with a plain-text password
- QuickCMS 6.7 has a vulnerability allowing authenticated RCE to gain a shell

The main factor(s) leading to privilege escalation here were:  
- CAP_CHOWN on Python3.8 which effectively provides any user with `root` access to any file on the system. 

Remediation steps then include:
- Remove unnecessary files and folders from being served by the web server (like /databases).
- Don't store files containing plain text passwords
- Use a much more secure password
- Remove cap_chown capability from Python. 


### Resources

- https://attackdefense.com/challengedetailsnoauth?cid=1365
- https://www.exploit-db.com/exploits/49494
- https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
- https://tbhaxor.com/exploiting-linux-capabilities-part-3/


