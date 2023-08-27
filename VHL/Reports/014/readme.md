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

OS Type: `Linux 2.6.36 (98%)`

| Port | Service | Protocol | Version |
| -----| ------- | -------- | ------- |
| 21   | FTP | TCP | vsftpd 3.0.2 |
| 22  | SSH | TCP | OpenSSH 7.4 (protocol 2.0) |
| 80   | HTTP | TCP | Apache httpd 2.4.6 ((CentOS) PHP/7.4.30) |
| 8080   | HTTP | TCP | Apache httpd 2.4.6 ((CentOS) PHP/7.4.30) |


Notable items:  
Anonymous FTP is permitted
Tiny File Manager on 8080?

### Nikto

## Exploitation

### Initial Access

### Privilege Escalation

## Identified Vulnerabilities

- [CVE]()


## Remediation

The main factor(s) leading to initial access included:  
-

The main factor(s) leading to privilege escalation here were:  
- 

Remediation steps then include:
- 

Images:
![image1](/VHL/Reports/images/014/14_1.png)
![image2](/VHL/Reports/014/images/14_2.png)
![image3](/VHL/Reports/014/images/14_3.png)
![image4](/VHL/Reports/014/images/14_4.png)
![image5](/VHL/Reports/014/images/14_5.png)
![image6](/VHL/Reports/014/images/14_6.png)
![image7](/VHL/Reports/014/images/14_7.png)
![image8](/VHL/Reports/014/images/14_8.png)
![image9](/VHL/Reports/014/images/14_9.png)
![image10](/VHL/Reports/014/images/14_10.png)
![image11](/VHL/Reports/014/images/14_11.png)
![image14](/VHL/Reports/014/images/14_12.png)
![image13](/VHL/Reports/014/images/14_13.png)
![image14](/VHL/Reports/014/images/14_14.png)
![image15](/VHL/Reports/014/images/14_15.png)
![image16](/VHL/Reports/014/images/14_16.png)

| User | Pass |
| ---- | ---- | 
| admin | admin@123 | 
| user | 12345 |

