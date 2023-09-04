
# Pentest 19 - <Name> - <Box> - <IP Address>

## Scanning and Enumerating

### Nmap
```bash
# Nmap 7.94 scan initiated Sun Aug  6 16:36:48 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /home/kali/reports/19-natural/results/10.14.1.77/scans/_quick_tcp_nmap.txt -oX /home/kali/reports/19-natural/results/10.14.1.77/scans/xml/_quick_tcp_nmap.xml 10.14.1.77
adjust_timeouts2: packet supposedly had rtt of -80556 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -80556 microseconds.  Ignoring time.
Nmap scan report for 10.14.1.77
Host is up, received user-set (0.15s latency).
Scanned at 2023-08-06 16:36:48 EDT for 41s
Not shown: 995 closed tcp ports (reset)
PORT    STATE    SERVICE  REASON         VERSION
21/tcp  open     ftp      syn-ack ttl 63 vsftpd 2.2.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0            4096 Mar 22  2017 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 172.16.4.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 2.2.2 - secure, fast, stable
|_End of status
22/tcp  open     ssh      syn-ack ttl 63 OpenSSH 5.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 68:6a:dc:e1:41:57:e1:0d:07:d6:69:cd:6f:da:17:bf (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAN6QtF5Lp+fA3TcGzpOFu1luMbXq5ZiUBHKxdcnVZPch141kvvspzGnXNItj4KOQiIDCSxrCeV+LDZLMjltHkS2wYv3eGfuuYwiaa/AirlPwSv55R2JTwtrzpwbZiKQ/d6L7VqeJHnRN5/s0JogWsvRUQjx/vr4MSFEsVs36XDBDAAAAFQDBu31g2R2qJVMMKkRnA2WvvADWEwAAAIEAyLJEi5PtkhHL0PbYIOuMitrSAp1pCTx4Zxh4ZlFT7qEoquxZIkmUPd/gNxClm6akc3mEV2iVr9cWpYQ8Sg3HH2TzoQemx3/sWjEVbO8TXYtB9XNseR68VDVt/IkiNY16v3Z9LLv/3WZai/rTMrc1Od1w3w2CiEov1PJOkm1zCWwAAACAZn6VvFf38GhHJJx7d9FFXNbuk1OKArq+JYsvV/9T052AAviQMdnzaBbAnhsl0aIsDLDDivLH9H1XceBKUP8eGYn8oqYI/EqX6t4Dp/3bqc0Vk4uJVfY/GllL9dcfq2NOye83YRAVw7x3Ux85qHUjnU+yuTSmGzKxARo1/adoWVE=
|   2048 ae:8d:d1:b5:ed:d3:e1:52:6b:d6:f7:95:ff:39:5d:e5 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwNObHJHk3xfxTYYSXw1mIqIgsl5QAmieHSwLBeUI/MbegwttcTbY7zGioiW45rAfhH73nLYArnbzG8UHP0T2pNGIGiH7nkvlLRV2w0yjPf9M6bllOLZ1fFjqUcXc77p6f0nwKwtFncxSMCbb5BjAKFPtdYW+NHZtG1+mrgwmITxkQgZk7SyrJz9df6mqaP81hLNRzgAXF6FOHht5mYFHqh06ynB3Gk/Xzs5bYKzGeWuPmoG1y/7ZSk5lfNGzsrixYMSdRn+xcuiqjJJrc0GAj7WX5V1bZlI6fcP14cAC4+Mq1ANHkRCOuYSE6rSDY5cYImbfle5fbQHHTJbdjDXabw==
80/tcp  open     http     syn-ack ttl 63 Apache httpd 2.2.15 ((CentOS))
|_http-favicon: Unknown favicon MD5: 129FB6EE5E0A90095DFBA15B6F15C324
|_http-title: Natural Design & Development - Home
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.2.15 (CentOS)
111/tcp filtered rpcbind  no-response
443/tcp open     ssl/http syn-ack ttl 63 Apache httpd 2.2.15 ((CentOS))
|_http-title: Natural Design & Development - Home
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=natural/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@natural/organizationalUnitName=SomeOrganizationalUnit/localityName=SomeCity
| Issuer: commonName=natural/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@natural/organizationalUnitName=SomeOrganizationalUnit/localityName=SomeCity
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-10-02T15:23:02
| Not valid after:  2018-10-02T15:23:02
| MD5:   bffb:f292:8cb0:f86a:14df:d453:ea4c:01d2
| SHA-1: e5f5:08a6:c590:f9ab:003f:cee8:ec83:bb8c:2267:94ca
| -----BEGIN CERTIFICATE-----
| MIID1jCCAr6gAwIBAgICLy8wDQYJKoZIhvcNAQELBQAwgZ8xCzAJBgNVBAYTAi0t
| MRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQK
| DBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxV
| bml0MRAwDgYDVQQDDAduYXR1cmFsMRswGQYJKoZIhvcNAQkBFgxyb290QG5hdHVy
| YWwwHhcNMTcxMDAyMTUyMzAyWhcNMTgxMDAyMTUyMzAyWjCBnzELMAkGA1UEBhMC
| LS0xEjAQBgNVBAgMCVNvbWVTdGF0ZTERMA8GA1UEBwwIU29tZUNpdHkxGTAXBgNV
| BAoMEFNvbWVPcmdhbml6YXRpb24xHzAdBgNVBAsMFlNvbWVPcmdhbml6YXRpb25h
| bFVuaXQxEDAOBgNVBAMMB25hdHVyYWwxGzAZBgkqhkiG9w0BCQEWDHJvb3RAbmF0
| dXJhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALRiIAAkWo4fhvmX
| JrxWBNLdfoV5nqJL2rZlbzqLnXRCXb3HLGymzRXD5BpGG7EMMYi6S/hIckMGhPwI
| MhjAwFuQB6+FL92qkPSJfi2CpxKB74eWGRz9kBIUbeT1TyIj+iDmTX7sEzrw+u59
| BAf24pyzZkPdlthss8wATBuJrP5+GafFSX3aOIZlIEIkeew0+wJd3jH+f9Bjbsn1
| EbbSTxKjiFejSmtZOEjpGWz66bXydSbAcA21mMiD4coG9k+zYkeN34T6l3lj9272
| sqoJy47FiC2cet9OgU/IMA8jj/PhPZ5kWTlGy7vA2TS4vp97jqXq7P+m6VCWB1HU
| XLJm2v0CAwEAAaMaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwDQYJKoZIhvcN
| AQELBQADggEBAKn678/aWvPtmQpZ8tA9/7RSKCsWMcWkCQeiK91zGy+JrZgVgUSE
| OaJZoY+e6b5eg0KmhWIsiYqPynxmB7yRyBl9EjqCcpxosY3K7Y0RWtTGBH7UbmOy
| pp0t+XQTLKDxjYfBNHegDw9d4L4Iu8vwbFsQxppaV7u7ouO/U9QIlmWDw7YYNj3x
| b8Y3ZNFQAFlkRdA5hAb0CuqsHUkEOd0H22sIpFlmUu49GWLCQCHW9g4Y0YQOE15M
| bf5AZMMwCrxlltOZMrIX6PrclZJlZGVnUB2j/xgd7jPt+0mV7GKuU6oriIsUtfCm
| eLRuwlsCRDnXeR0+QR+w6FldGnIIGURNkEU=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-08-06T20:37:25+00:00; -3s from scanner time.
|_http-server-header: Apache/2.2.15 (CentOS)
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 2.6.32 (97%), Linux 2.6.32 - 2.6.39 (95%), Linux 2.6.32 - 3.0 (93%), Linux 3.2 - 3.8 (92%), Linux 3.8 (92%), Linux 2.6.32 or 3.10 (92%), Linux 2.6.38 (91%), Linux 3.10 - 3.12 (91%), Linux 3.6 (91%), WatchGuard Fireware 11.8 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94%E=4%D=8/6%OT=21%CT=1%CU=%PV=Y%G=N%TM=64D00489%P=x86_64-pc-linux-gnu)
SEQ(SP=100%GCD=1%ISR=109%TI=Z%TS=A)
SEQ(SP=100%GCD=1%ISR=109%TI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW6%O2=M5B4ST11NW6%O3=M5B4NNT11NW6%O4=M5B4ST11NW6%O5=M5B4ST11NW6%O6=M5B4ST11)
WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=3890)
ECN(R=Y%DF=Y%TG=40%W=3908%O=M5B4NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=N)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 49.708 days (since Sat Jun 17 23:38:36 2023)
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Unix

Host script results:
|_clock-skew: -3s

TRACEROUTE
HOP RTT       ADDRESS
1   147.18 ms 10.14.1.77

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  6 16:37:29 2023 -- 1 IP address (1 host up) scanned in 41.07 seconds

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
```bash

```
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
![image1](/VHL/Reports/019/images/19_1.png)
![image2](/VHL/Reports/019/images/19_2.png)
![image3](/VHL/Reports/019/images/19_3.png)
![image4](/VHL/Reports/019/images/19_4.png)
![image5](/VHL/Reports/019/images/19_5.png)
![image6](/VHL/Reports/019/images/19_6.png)
![image7](/VHL/Reports/019/images/19_7.png)
![image8](/VHL/Reports/019/images/19_8.png)
![image9](/VHL/Reports/019/images/19_9.png)
![image10](/VHL/Reports/019/images/19_10.png)
![image11](/VHL/Reports/019/images/19_11.png)
![image12](/VHL/Reports/019/images/19_12.png)
![image13](/VHL/Reports/019/images/19_13.png)
![image14](/VHL/Reports/019/images/19_14.png)
![image15](/VHL/Reports/019/images/19_15.png)
![image16](/VHL/Reports/019/images/19_16.png)

| User | Pass |
| ---- | ---- | 
| admin | admin@123 | 
| user | 12345 |

mysql -u root -p 
root  TiKiR00t08@
