# Pentest 15 - PBX - 17 - 10.14.1.17

## Scanning and Enumerating

### Nmap
```bash
# Nmap 7.94 scan initiated Sun Aug  6 15:21:21 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /home/kali/reports/15-pbxc/results/10.14.1.17/scans/_quick_tcp_nmap.txt -oX /home/kali/reports/15-pbxc/results/10.14.1.17/scans/xml/_quick_tcp_nmap.xml 10.14.1.17
Nmap scan report for 10.14.1.17
Host is up, received user-set (0.24s latency).
Scanned at 2023-08-06 15:21:21 EDT for 36s
Not shown: 992 closed tcp ports (reset)
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 53:c1:71:52:3e:c3:9c:8d:e1:70:3f:14:e7:73:09:fa (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBANk4MzyzpxEdAaTDp4hL0bFxLAJyUTK5WF2k9mWcnkrt0f7Y2w+GgzbHqzbo0lBqOjpGokxONQyciMSSnlPzFSDAMKP2P8dgglvvTiuCQEgOG6dyRd+MDatjXjTrJcLubkTdOBrA8u5CPNawHx60/jl6x41WTvsG9xHWjfQJqIF3AAAAFQCVSpcBmxtyocLJ85lY06b2yN1SsQAAAIEAmbGZEm2W3ul23a7mXQh3d7OHQIQVYZR6n7sIP2Fe3JDzr1JmE1EAJWowhVige+renRdy7V5RohuS+zFROFDXDOBg9bvG1s9PMVH3eq0mczNZJAqAPpjzasjYdw1smpajTdRxoB19LEp19coFa5GKY6a3DNdphgtdVCU+WBM4aJIAAACAWUd1FTlCB/vEjvqrplxckHstWUE3uLL4UzJF9SfGMjdKGQRlcF7ogdu+2BriBvz1E7VZ5O+qWOp3V/zaDV+plI1//4kLW4MpagGT9l3nkG6j2fqV+9qkzUAh9Y3V/jC/rppA7FFBrseLYREg8Ng4yaYmzx7VpW7Qr2zlgsXCf88=
|   2048 61:67:5a:d2:d9:ee:12:00:70:ef:61:ac:09:85:e3:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDrJItAYvuXmQqNWGNHcXwunPJbmlddQl+6W8w6MLbAf11JP0cFXLrl6JKCNmQ+HgRFJi0qu8DWybh9D3ZFleQjzos19zVNSpcPE2Jurxg1V16anDgA90zKtdvFk7JmJJmflXMlZs74I66aFDdtIirjANbITBs9CGIXzHHmb2Q9VPnmzliGlK/rqUbNcLJ2G1h3pqMoQ7nwDPVULiYCTGcMVc0V7etmazXRqG+KDybu31qWyyV1Uiiwyds0YducCXC2WxxGXeDqnLci+6ptfRCNuHMCxyKANyKtNQqzuzJD9H7qRIxJOIldofGrPk0xjMKrwtnPgJh2+6hzuD0p+jcf
|   256 fc:07:b3:93:03:9e:3d:54:84:f7:ed:41:3d:ca:54:d0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOGYJxf/kcQL+qxbQM4oe4QRvcMpPu5VzmXuncPNG5k1JOitLw60kF6PgAG7NCCUb/DSxFEvCuJT/EbyxIimhWE=
|   256 4e:53:a1:92:2f:fb:dc:43:4a:b1:39:89:9d:4c:4d:b9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDD6T2Zei049Jr/w5pG9NTbdL9kPF1RgD4cjNmH4xHZe
80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.7 ((Ubuntu))
| http-title: 404 Not Found
|_Requested resource was config.php
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.7 (Ubuntu)
110/tcp open  pop3        syn-ack ttl 63 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: TOP RESP-CODES UIDL CAPA SASL AUTH-RESP-CODE STLS PIPELINING
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        syn-ack ttl 63 Dovecot imapd (Ubuntu)
|_imap-capabilities: more IMAP4rev1 ENABLE IDLE STARTTLS Pre-login have ID post-login listed LOGINDISABLEDA0001 capabilities OK LOGIN-REFERRALS SASL-IR LITERAL+
|_ssl-date: TLS randomness does not represent time
445/tcp open             syn-ack ttl 63 Samba smbd 4.1.6-Ubuntu (workgroup: WORKGROUP)
993/tcp open  ssl/imaps?  syn-ack ttl 63
| ssl-cert: Subject: commonName=pbx/organizationName=Dovecot mail server/emailAddress=root@pbx/organizationalUnitName=pbx
| Issuer: commonName=pbx/organizationName=Dovecot mail server/emailAddress=root@pbx/organizationalUnitName=pbx
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2016-10-06T11:26:13
| Not valid after:  2026-10-06T11:26:13
| MD5:   e6b3:151a:2653:1264:ae04:61ef:d172:82ab
| SHA-1: 0f02:7ab2:4226:0d4d:90a7:eb39:4bd9:25dc:483b:8506
| -----BEGIN CERTIFICATE-----
| MIIDeTCCAmGgAwIBAgIJAJw1R0COu7saMA0GCSqGSIb3DQEBCwUAMFMxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxDDAKBgNVBAsMA3BieDEMMAoGA1UEAwwD
| cGJ4MRcwFQYJKoZIhvcNAQkBFghyb290QHBieDAeFw0xNjEwMDYxMTI2MTNaFw0y
| NjEwMDYxMTI2MTNaMFMxHDAaBgNVBAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxDDAK
| BgNVBAsMA3BieDEMMAoGA1UEAwwDcGJ4MRcwFQYJKoZIhvcNAQkBFghyb290QHBi
| eDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcTWNidMYn3tQamF6AU
| nvvjf/iiB8PU7uXvpsnddpFyO4ckydCw6sbA9DVF6uhClEZraek5mqgTiUaTixWg
| pQG431/dILfWXDTLK/CdYKqnrNUVFklQDv3DKmKXxt8q/W7QJwGDCGyqFLrLs88S
| X0VQwCiovURNfb2kQ+5S99UIr6fDj7STw7djGt5vwJqgdG4mu9VBGBllUf4aP1MR
| gp3TntOVwrhxROP1eh7DAuicMd4s/BDoOrfUYzSTAL6Q6YDAdyHFbGTnpJqXTraV
| pZJjl8uGqu48Pl/2wHBjBFZwg0RvLEzD0zKM1TyrP6joIhI8AZM9W+p6Cd4KJlIM
| CEUCAwEAAaNQME4wHQYDVR0OBBYEFIG2jOQIUUVMmDbYm0L7gUNqkO+/MB8GA1Ud
| IwQYMBaAFIG2jOQIUUVMmDbYm0L7gUNqkO+/MAwGA1UdEwQFMAMBAf8wDQYJKoZI
| hvcNAQELBQADggEBAF1OACUL0V82sEFrFCmSb53ZDfCc7ssTxZOny1ULjE/MNvUn
| C3k22e1dEuLKBQ4KET82L/qTbyesnjMgdMT3a16MsCT8a0ijxalRP4pAWj2DKxkZ
| M/ofnVVS9RJMrtFOxArQe7gs7PvQ5EoiIqVr0PN2s9EQDiDnU4fx67d6AApmKWFt
| alsCkkKgu23hOR5tUS1rrjLrTCkdiJIhq7zVtgqf2/O/fQsEvjQdh/9vj4nHvUt+
| wqxsoNQPrNwwbDHfBwpCx+k2Q2pf9huoDrzFNTnaHoiiu0ksK+bHf60vCOulTZuh
| g3U+teEybqB5pX5XTehGmYE/dj9TFUEvHAmimW0=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3s?  syn-ack ttl 63
| ssl-cert: Subject: commonName=pbx/organizationName=Dovecot mail server/emailAddress=root@pbx/organizationalUnitName=pbx
| Issuer: commonName=pbx/organizationName=Dovecot mail server/emailAddress=root@pbx/organizationalUnitName=pbx
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2016-10-06T11:26:13
| Not valid after:  2026-10-06T11:26:13
| MD5:   e6b3:151a:2653:1264:ae04:61ef:d172:82ab
| SHA-1: 0f02:7ab2:4226:0d4d:90a7:eb39:4bd9:25dc:483b:8506
| -----BEGIN CERTIFICATE-----
| MIIDeTCCAmGgAwIBAgIJAJw1R0COu7saMA0GCSqGSIb3DQEBCwUAMFMxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxDDAKBgNVBAsMA3BieDEMMAoGA1UEAwwD
| cGJ4MRcwFQYJKoZIhvcNAQkBFghyb290QHBieDAeFw0xNjEwMDYxMTI2MTNaFw0y
| NjEwMDYxMTI2MTNaMFMxHDAaBgNVBAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxDDAK
| BgNVBAsMA3BieDEMMAoGA1UEAwwDcGJ4MRcwFQYJKoZIhvcNAQkBFghyb290QHBi
| eDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcTWNidMYn3tQamF6AU
| nvvjf/iiB8PU7uXvpsnddpFyO4ckydCw6sbA9DVF6uhClEZraek5mqgTiUaTixWg
| pQG431/dILfWXDTLK/CdYKqnrNUVFklQDv3DKmKXxt8q/W7QJwGDCGyqFLrLs88S
| X0VQwCiovURNfb2kQ+5S99UIr6fDj7STw7djGt5vwJqgdG4mu9VBGBllUf4aP1MR
| gp3TntOVwrhxROP1eh7DAuicMd4s/BDoOrfUYzSTAL6Q6YDAdyHFbGTnpJqXTraV
| pZJjl8uGqu48Pl/2wHBjBFZwg0RvLEzD0zKM1TyrP6joIhI8AZM9W+p6Cd4KJlIM
| CEUCAwEAAaNQME4wHQYDVR0OBBYEFIG2jOQIUUVMmDbYm0L7gUNqkO+/MB8GA1Ud
| IwQYMBaAFIG2jOQIUUVMmDbYm0L7gUNqkO+/MAwGA1UdEwQFMAMBAf8wDQYJKoZI
| hvcNAQELBQADggEBAF1OACUL0V82sEFrFCmSb53ZDfCc7ssTxZOny1ULjE/MNvUn
| C3k22e1dEuLKBQ4KET82L/qTbyesnjMgdMT3a16MsCT8a0ijxalRP4pAWj2DKxkZ
| M/ofnVVS9RJMrtFOxArQe7gs7PvQ5EoiIqVr0PN2s9EQDiDnU4fx67d6AApmKWFt
| alsCkkKgu23hOR5tUS1rrjLrTCkdiJIhq7zVtgqf2/O/fQsEvjQdh/9vj4nHvUt+
| wqxsoNQPrNwwbDHfBwpCx+k2Q2pf9huoDrzFNTnaHoiiu0ksK+bHf60vCOulTZuh
| g3U+teEybqB5pX5XTehGmYE/dj9TFUEvHAmimW0=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.11 - 4.1
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/6%OT=22%CT=1%CU=43365%PV=Y%DS=2%DC=I%G=Y%TM=64CFF2D5
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=109%TI=Z%II=I%TS=8)OPS(O1=M5B
OS:4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6
OS:=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF
OS:=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%
OS:Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6
OS:(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 16.631 days (since Fri Jul 21 00:13:18 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=253 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: PBX; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 4.1.6-Ubuntu)
|   Computer name: pbx
|   NetBIOS computer name: PBX\x00
|   Domain name: 
|   FQDN: pbx
|_  System time: 2023-08-06T21:21:37+02:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 8541/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 37645/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 9657/udp): CLEAN (Timeout)
|   Check 4 (port 32353/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2023-08-06T19:21:37
|_  start_date: N/A
|_clock-skew: mean: -40m03s, deviation: 1h09m16s, median: -4s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:0:0: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: PBX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   PBX<00>              Flags: <unique><active>
|   PBX<03>              Flags: <unique><active>
|   PBX<20>              Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00

TRACEROUTE
HOP RTT       ADDRESS
1   237.01 ms 10.14.1.17

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  6 15:21:57 2023 -- 1 IP address (1 host up) scanned in 36.20 seconds
    
```

OS Type: `Linux 4.1.6 Ubuntu`

| Port | Service | Protocol | Version |
| -----| ------- | -------- | ------- |
| 22  | SSH | TCP | OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 |
| 80   | HTTP | TCP | Apache httpd 2.4.7 ((Ubuntu)  |
| 110   | POP3 | TCP | Dovecot pop3d  |
| 139   | netbios-ssn | TCP | Samba smbd 3.x - 4.x  |
| 143   | imap | TCP | Dovecot imapd  |
| 445   |  ?  | TCP | smbd 4.1.6-ubuntu |
| 993   | imaps | TCP | Samba smbd 3.x - 4.x  |
| 5038   | asterisk | TCP | Asterisk Call Manager 2.8.0  |



### Nikto

## Exploitation

### Initial Access

First thing, I opened up and checked out the website, and can see that it's running FreePBX.
![image1](/VHL/Reports/015/images/15_1.png)

From here, I did some googling for default credentials, which were suggested to be:
| User | Pass |
| ---- | ---- | 
| admin | admin | 
| admin | SangomaRootPassword |
| root | SangomaRootPassword |
| root | root |

![image2](/VHL/Reports/015/images/15_2.png)


`root:root` logged me in:
![image3](/VHL/Reports/015/images/15_3.png)

From here, I can see it is running `FreePBX 13.0.188.8 'VoIP Server'`. Lets see what google has.
It seems like __this__ version in particular patches some vulnerabilities.
Poking around however, I do see that I can upload a tar gzip file containing a FreePBX module from my local system.
![image4](/VHL/Reports/015/images/15_4.png)

Googling for `FreePBX Shell`, seems pretty [promising](https://github.com/DarkCoderSc/freepbx-shell-admin-module)
![image5](/VHL/Reports/015/images/15_5.png)

I git clone the module, tar the archive, and upload it to the import section:
![image6](/VHL/Reports/015/images/15_6.png)

Installing it from the admin module:
![image7](/VHL/Reports/015/images/15_7.png)

We now have a web shell:
![image8](/VHL/Reports/015/images/15_8.png)

This took me a little bit of time, as I was getting some output, but nothing was happening. I realized that the command was executing, then terminating, so my netcat sessions were dropping.
After a little bit of trial and effort, I decided to upload a simple bash script that returned a shell instead of executing it in session. 
![image9](/VHL/Reports/015/images/15_9.png)
![image10](/VHL/Reports/015/images/15_10.png)
![image11](/VHL/Reports/015/images/15_11.png)
![image12](/VHL/Reports/015/images/15_12.png)
![image13](/VHL/Reports/015/images/15_13.png)

Success!


### Privilege Escalation

I'm going to put all the images to the end of this one and just say - first I tried a number of dirty COW exploits, to no avail.
Then, I decided to go back and run `linpeas.sh` to enumerate the system and determine anything I missed.
It highlighted...Dirty COW.

I'm pretty sure I tried and compiled almost every different vulnerability Dirty COW had, and all were missing GLIBC.
At which point I realized...does the target have `gcc` or `g++`? It does...
[40611.c](https://www.exploit-db.com/exploits/40611) ran, but didn't escalate permissions.
[40847.cpp](https://www.exploit-db.com/exploits/40847) successfully escalated permissions.

![image14](/VHL/Reports/015/images/15_14.png)
![image15](/VHL/Reports/015/images/15_15.png)
![image16](/VHL/Reports/015/images/15_16.png)
![image17](/VHL/Reports/015/images/15_17.png)
![image18](/VHL/Reports/015/images/15_18.png)

Success!

## Identified Vulnerabilities

- [CVE-2016-5195](https://nvd.nist.gov/vuln/detail/cve-2016-5195)



## Remediation

The main factor(s) leading to initial access included:  

- Weak / default passwords on PBX
- Module Install Access

The main factor(s) leading to privilege escalation here were:  
- A Dirty COW exploitable version of Linux 

Remediation steps then include:
- Setting a __much__ more secure login password
- Update the Linux Kernel
- Disable module uploads in PBX



