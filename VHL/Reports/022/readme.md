# Pentest <> - <Name> - <Box> - <IP Address>

## Scanning and Enumerating

### Nmap
```bash
# Nmap 7.94 scan initiated Mon Sep  4 09:21:57 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /home/kali/reports/22-dolphin/results/10.14.1.58/scans/_quick_tcp_nmap.txt -oX /home/kali/reports/22-dolphin/results/10.14.1.58/scans/xml/_quick_tcp_nmap.xml 10.14.1.58
adjust_timeouts2: packet supposedly had rtt of -69723 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -69723 microseconds.  Ignoring time.
Nmap scan report for 10.14.1.58
Host is up, received user-set (0.17s latency).
Scanned at 2023-09-04 09:21:57 EDT for 43s
Not shown: 996 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 ProFTPD
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ed:5d:8e:e9:c3:17:74:b3:e8:ee:a4:f1:b8:e3:47:6d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCSRa4gl7ZVb0KnYMNogI4w3ODLEPB59LyGSc9iaxlKzBx19H6ak+CTipmG4B2/bmnEP4DxonSrvm1zTSp5xVd7KNmhdt/AFKE5FGzrW9h2KWAvoCFU/Wx73gpduHrQ67VBca05dluyK+PeK1lSwKNCkFgsmX2BoW5AuPaafwJHbz5UxD+kFX2jrDM8ysVk5q8uwo3i039d/Ccpvtd5KLwOlspxelm7fKT4w0g504Cim5J/9VDm25O6WaEwhuZvfyoqT9OiZOx4hhKMhl7K+qtfeG4zlQWkX/EfwM/dsWiPBCkuyvJZOMsHxoSQcYGGVRIWSi8HPMUeoDYv/UiiC0PGwASRQwyoJDpZ4qOfoadn2/cVFhlhrPSuohg+b8A1p9RFGrZ6ZGcz44TeeZEbefSwS1iF0cmQc5HAuUZ2qJwYk+0Yl2odlXC7+ndqxG1wtCI1GwOrPLmgxn/kwVWuhvr9LM6nNg0whrXprx2hVEVLv98uf0FbJ9B84lkvMsTZaw0=
|   256 99:02:13:1e:71:99:d1:32:23:20:e2:fb:bb:65:5f:b7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBOQWHuTBve0SWDkbMxVjk8e095PdaGN8vEHb7W/M7L57mg8ithParGAlqE/PjWhFZcnXX0zYdROnYEdmzp/1MI=
|   256 75:2c:60:32:65:f9:bd:7c:5b:72:06:97:84:f7:20:a3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGYqSxfAqAOx7Rt4jPV4OEHr9ooWVgcMKNAU8HpHhVYF
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Dolphin CMS
|_http-server-header: Apache/2.4.41 (Ubuntu)
81/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 000BF649CC8F6BF27CFB04D1BCDCD3C7
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: WordPress 6.0
|_http-title: Dolphin
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 2.6.32 or 3.10 (96%), Linux 4.4 (96%), Linux 2.6.32 - 2.6.35 (94%), Linux 2.6.32 - 2.6.39 (94%), Linux 4.0 (94%), Linux 2.6.32 - 3.0 (93%), Linux 5.0 - 5.4 (93%), Linux 3.11 - 4.1 (92%), Linux 3.2 - 3.8 (92%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=9/4%OT=21%CT=1%CU=35360%PV=Y%DS=2%DC=I%G=Y%TM=64F5DA20
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10A%TI=Z%II=I%TS=A)SEQ(SP=10
OS:2%GCD=1%ISR=10A%TI=Z%II=I%TS=A)SEQ(SP=103%GCD=1%ISR=109%TI=Z%TS=A)SEQ(SP
OS:=103%GCD=2%ISR=109%TI=Z%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NN
OS:T11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=
OS:FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%
OS:Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF
OS:=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T7(R=N)U1(R=N)U1(R=Y%DF=N%T=
OS:40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S
OS:)

Uptime guess: 13.718 days (since Mon Aug 21 16:09:07 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT       ADDRESS
1   173.28 ms 10.14.1.58

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep  4 09:22:40 2023 -- 1 IP address (1 host up) scanned in 42.93 seconds
```

OS Type: `Linux 2.6.32 (96%)`

| Port | Service | Protocol | Version |
| -----| ------- | -------- | ------- |
| 21   | FTP | TCP | ProFTPD |
| 22  | SSH | TCP | 8.2p1 Ubuntu 4ubuntu0.5 |
| 80   | HTTP | TCP | Apache httpd 2.4.41 |
| 81   | HTTP | TCP | Apache httpd 2.4.41 |


### Nikto
```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.14.1.58
+ Target Hostname:    10.14.1.58
+ Target Port:        80
+ Start Time:         2023-09-04 09:22:41 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /crossdomain.xml contains a full wildcard entry. See: http://jeremiahgrossman.blogspot.com/2008/05/crossdomainxml-invites-cross-site.html
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /administration/: This might be interesting.
+ /backup/: Directory indexing found.
+ /backup/: This might be interesting.
+ /tmp/: Directory indexing found.
+ /tmp/: This might be interesting.
+ /wordpress/wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version.
+ /wordpress/wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /install.txt: Install file found may identify site software.
+ /administration/: Admin login page/section found.
+ /wordpress/wp-admin/: Uncommon header 'x-redirect-by' found, with contents: WordPress.
+ /help.php: A help file was found.
+ /wordpress/wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wordpress/wp-content/uploads/: Directory indexing found.
+ /wordpress/wp-content/uploads/: Wordpress uploads directory is browsable. This may reveal sensitive information.
+ /wordpress/wp-login.php: Wordpress login found.
+ /.gitignore: .gitignore file found. It is possible to grasp the directory structure.
+ /README.md: Readme Found.
+ 7729 requests: 0 error(s) and 24 item(s) reported on remote host
+ End Time:           2023-09-04 09:47:15 (GMT-4) (1474 seconds)


- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.14.1.58
+ Target Hostname:    10.14.1.58
+ Target Port:        81
+ Start Time:         2023-09-04 09:22:41 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: Uncommon header 'x-redirect-by' found, with contents: WordPress.
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Root page / redirects to: http://10.14.1.58:81/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /images: Drupal Link header found with value: <http://10.14.1.58:81/wp-json/>; rel="https://api.w.org/". See: https://www.drupal.org/
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wp-login.php: Wordpress login found.
+ 7729 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2023-09-04 10:04:47 (GMT-4) (2526 seconds)
---------------------------------------------------------------------------

```
## Exploitation

### Initial Access
First I checked out the results that I had from the web, and nikto - it was running Dolphin CMS, which returned some quick results in Searchsploit.
In fact, getting initial access wasn't really hard at all - the exploit was very straightforward with just the file + address.
![image1](/VHL/Reports/022/images/22_1.png)

![image2](/VHL/Reports/022/images/22_2.png)

![image3](/VHL/Reports/022/images/22_3.png)

![image4](/VHL/Reports/022/images/22_4.png)

### Privilege Escalation
Once I get a shell, I struggled for a bit in trying to upgrade my shell from PHP.
I was getting connection timeouts, or just empty responses when I tried with bash, PHP, and NC.
Eventually, I was able to gain a generic shell, and use wget to pull over a simple shell script with a callback (just to run as a sub-process).

From here, I then ran `linpeas.sh` to enumerate services and binaries on the system.
While the inevitable solution WAS in fact identified with `linpeas.sh` (being `make`), this took me awhile to figure out how to use it properly to accomplish what I needed to accomplish.

In short - `make` had SUID permissions. 
[GTFOBins](https://gtfobins.github.io/gtfobins/make/) had a few solutions for using this, but it was not intuitive, or easy to work with.
First I tried to use make directly to upgrade my shell to root, but that was not successful.

Then, I tried writing a makefile to establish a listener as root (because SUID), and that was not successful.

Eventually, I realized with the example provided, that a file was being created as `root` with `DATA` for contents. 
Could I re-use one of my earlier exploits in adding a new user to `/etc/passwd`?
The syntax is really weird, because in make you have to both escape, and double up on dollar signs, so for instance: `$1` becomes `\$\$1`.
This worked and gained my root by writing a new user using SUID to /etc/passwd:
![image5](/VHL/Reports/022/images/22_5.png)
![image6](/VHL/Reports/022/images/22_6.png)
![image7](/VHL/Reports/022/images/22_7.png)
![image8](/VHL/Reports/022/images/22_8.png)

## Identified Vulnerabilities

- No CVE vulnerabilities
- [DolphinCMS](https://www.exploit-db.com/exploits/40756)


## Remediation

The main factor(s) leading to initial access included:  
- Vulnerable version of dolphin leading to remote access

The main factor(s) leading to privilege escalation here were:  
- SUID permissions on `make` allowing inserting a new user with root privileges

Remediation steps then include:
- Upgrading from Dolphin 7.3.2 to 7.3.5
- Removing SUID from make

Images:

                                                                                              
