# Pentest 17 - Tiki - 39 - 10.14.1.39

## Scanning and Enumerating
![image1](/VHL/Reports/017/images/17_1.png)
![image2](/VHL/Reports/017/images/17_2.png)
![image3](/VHL/Reports/017/images/17_3.png)
![image4](/VHL/Reports/017/images/17_4.png)
![image5](/VHL/Reports/017/images/17_5.png)
![image6](/VHL/Reports/017/images/17_6.png)
![image7](/VHL/Reports/017/images/17_7.png)
![image8](/VHL/Reports/017/images/17_8.png)
![image9](/VHL/Reports/017/images/17_9.png)
![image10](/VHL/Reports/017/images/17_10.png)
![image11](/VHL/Reports/017/images/17_11.png)
![image12](/VHL/Reports/017/images/17_12.png)
![image13](/VHL/Reports/017/images/17_13.png)
![image14](/VHL/Reports/017/images/17_14.png)
![image15](/VHL/Reports/017/images/17_15.png)
![image16](/VHL/Reports/017/images/17_16.png)

### Nmap
```bash

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


| User | Pass |
| ---- | ---- | 
| admin | admin@123 | 
| user | 12345 |
