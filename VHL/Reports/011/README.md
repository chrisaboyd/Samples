# Pentest 11 - Backupadmin - 4 - 10.14.1.4

## Introduction

## Scanning and Enumerating

### Nmap scan:
```bash
┌──(autorecon)─(kali㉿kali)-[~/…/11-backupadmin/results/10.14.1.4/scans]
└─$ cat _quick_tcp_nmap.txt 
# Nmap 7.94 scan initiated Sat Aug  5 17:05:19 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /home/kali/reports/11/results/10.14.1.4/scans/_quick_tcp_nmap.txt -oX /home/kali/reports/11/results/10.14.1.4/scans/xml/_quick_tcp_nmap.xml 10.14.1.4
adjust_timeouts2: packet supposedly had rtt of -89278 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -89278 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -112100 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -112100 microseconds.  Ignoring time.
Nmap scan report for 10.14.1.4
Host is up, received user-set (0.16s latency).
Scanned at 2023-08-05 17:05:19 EDT for 27s
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 63 vsftpd 3.0.3
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
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0           32540 Jul 13  2022 backupdirs.txt
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 64:77:04:9b:7b:39:02:78:04:19:90:90:32:a9:58:32 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDvk5SUM67Q0pTVlYJPTMVwMb98XZ94maTx/qPynHsvTLbJ6em+gbSO/A9uukKyLiPZK5Y7/zU28IGLd3RLm0qTXag4wJqRRYPWr+K7AHKmLlwtKMhb7SoWxGCWmlTsCIHI37TysXdbe5gz22L24PlSrI/MqYlOBHXNuhPsEeiCW/MjWXuFK10066IlN5yHUgWgHhc/G0QGc0ljnZtGrGRValfs6BlHEGEOnhojv7GQqXZznE6GSrgkiISTFkB1w2aCnkym6FfQhxjm89ns5DB7LgIrX2OObTnq4smh2oCgPPXy8kJA2pkQDt0UuVU9otM/Lc6+35EeSaaODrXwIHv2J2eQR8owsgBjVap98fsYVYm2i4dGwHabx49axW9VMOs/ehql9ddC3qDSyu+RTBIsbNgtaGw4n0WUPsylAqlPldcsvBAa22O3TuDBZ7VLfiGRMscgvkltoH8rTnflNakD/O5dZ3uV7hoDRKpG37eHqXt747607RYBG1Nk1pPBjuU=
|   256 af:2e:70:d5:fd:44:44:f1:e0:13:57:c1:81:ac:b0:14 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA1Zlk6jJEfD+zVkB2ahFdRwiu3emYf/rPc66jmFLbMHADLF4do2id7PWGw4Ahfk4DElxo6L8Kj2a2GYT04tygw=
|   256 84:53:0e:f2:39:02:fd:d6:8d:2f:23:c3:7e:f0:d7:7b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIQeeF+PLiznYFYwNZDh0Xbz/Ncx/O3TwT5PlE6lb4AF
80/tcp  open  http        syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.6.2
Device type: general purpose|storage-misc|firewall
Running (JUST GUESSING): Linux 2.6.X|3.X|4.X|5.X (92%), Synology DiskStation Manager 5.X (86%), WatchGuard Fireware 11.X (86%)
OS CPE: cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:3.10 cpe:/o:linux:linux_kernel:4.4 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel cpe:/a:synology:diskstation_manager:5.1 cpe:/o:watchguard:fireware:11.8
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 2.6.32 (92%), Linux 2.6.32 or 3.10 (92%), Linux 4.4 (92%), Linux 2.6.32 - 2.6.35 (90%), Linux 2.6.32 - 2.6.39 (90%), Linux 2.6.32 - 3.0 (88%), Linux 5.0 - 5.4 (88%), Linux 3.11 - 4.1 (88%), Linux 3.2 - 3.8 (88%), Linux 4.0 (87%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94%E=4%D=8/5%OT=21%CT=1%CU=%PV=Y%G=N%TM=64CEB9AA%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10B%TI=Z%TS=A)
SEQ(SP=104%GCD=1%ISR=10B%TI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=N)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 33.196 days (since Mon Jul  3 12:23:57 2023)
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: -7s
| nbstat: NetBIOS name: BACKUPADMIN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   BACKUPADMIN<00>      Flags: <unique><active>
|   BACKUPADMIN<03>      Flags: <unique><active>
|   BACKUPADMIN<20>      Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 34893/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 54420/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 44894/udp): CLEAN (Timeout)
|   Check 4 (port 55473/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2023-08-05T21:05:33
|_  start_date: N/A

TRACEROUTE
HOP RTT       ADDRESS
1   161.79 ms 10.14.1.4

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug  5 17:05:46 2023 -- 1 IP address (1 host up) scanned in 27.61 seconds
```

### Nikto scan:
```bash
┌──(autorecon)─(kali㉿kali)-[~/…/results/10.14.1.4/scans/tcp80]
└─$ cat tcp_80_http_nikto.txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.14.1.4
+ Target Hostname:    10.14.1.4
+ Target Port:        80
+ Start Time:         2023-08-05 17:05:47 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 7881 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2023-08-05 17:24:33 (GMT-4) (1126 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## Exploitation
```
https://www.exploit-db.com/exploits/40163
```



## Identified Vulnerabilities
* [CVE-2016-10729](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-10729)
* [CVE-2016-10730](https://nvd.nist.gov/vuln/detail/CVE-2016-10730)
* [CVE-2016-5195](https://nvd.nist.gov/vuln/detail/cve-2016-5195)

## Remediation
