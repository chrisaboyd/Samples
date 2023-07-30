# Pentest 5 - James - 95 - 10.14.1.95

### Introduction

### Scanning and Enumerating
Begin scanning  
```bash
┌──(autorecon)─(kali㉿kali)-[~/reports/5]
└─$ export JAMES=10.14.1.95  
                                                                                                                                                                                          
┌──(autorecon)─(kali㉿kali)-[~/reports/5]
└─$ sudo $(which autorecon) $JAMES  
[*] Scanning target 10.14.1.95
[*] [10.14.1.95/all-tcp-ports] Discovered open port tcp/22 on 10.14.1.95
[*] [10.14.1.95/all-tcp-ports] Discovered open port tcp/25 on 10.14.1.95
[*] [10.14.1.95/all-tcp-ports] Discovered open port tcp/110 on 10.14.1.95
[*] [10.14.1.95/all-tcp-ports] Discovered open port tcp/119 on 10.14.1.95
[*] [10.14.1.95/all-tcp-ports] Discovered open port tcp/4555 on 10.14.1.95
[*] Finished scanning target 10.14.1.95 in 9 minutes, 50 seconds
[*] Finished scanning all targets in 9 minutes, 51 seconds!
[*] Don't forget to check out more commands to run manually in the _manual_commands.txt file in each target's scans directory!
[!] AutoRecon identified the following services, but could not match them to any plugins based on the service name. Please report these to Tib3rius: tcp/4555/james-admin/insecure

cat _full_tcp_nmap.txt  
# Nmap 7.94 scan initiated Sun Jul 30 17:20:17 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/reports/5/results/10.14.1.95/scans/_full_tcp_nmap.txt -oX /home/kali/reports/5/results/10.14.1.95/scans/xml/_full_tcp_nmap.xml 10.14.1.95
Increasing send delay for 10.14.1.95 from 0 to 5 due to 15 out of 36 dropped probes since last increase.
Nmap scan report for 10.14.1.95
Host is up, received user-set (0.18s latency).
Scanned at 2023-07-30 17:20:17 EDT for 589s
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE     REASON         VERSION
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f2:7d:fd:ff:67:07:9e:d7:fd:67:29:c8:8b:24:a5:d0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8YTDG92l323tYiXOU02tBevYpt0hsG3OxbCEGnJAR1IGK+L9e+AgFZ5s4CVaN+3xX/n70geOvprZ8tUghN4UgGvD94triqS2ALk3l7n9h8xEky0W5wEdEV3nz32p3ur6mHvfkLDMB0iqvQmV+UQ/3hXrJ0FIwGjKTW1dfXslilgE0TEI9r3kSZUguAkKPmS04jSqeZbuRBK8zmUw+0ETjtjqGpeNeBEQ57tQAGXNIfxntV3Ho6JK1yEuEQYzKVutwCRcGofy/qnVpiMqdf13YOndGxEFgvfWxMyXTkkSNbNYUEAjjub8CjvxAvtcymBCe2IKmIk0IPiaTlcsC8HOx
|   256 f6:8b:f0:c6:60:85:ba:68:02:b0:3c:18:31:47:53:20 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPT1pqzG+ArPeZG2rro7DteefH8ZEsI5/ZmGscSGI9TcpRNcdrtkoxWhR3qcEZuzLltilSBdGKMimCecCMXbhmY=
|   256 05:52:2f:32:0c:36:f5:fb:98:00:e9:c1:6e:81:94:1f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBL6hc9yLsY8skEL+c8P6FgOgroTSMk0PKrWsfhFymkS
25/tcp   open  smtp        syn-ack ttl 63 JAMES smtpd 2.3.2
|_smtp-commands: james Hello nmap.scanme.org (172.16.4.1 [172.16.4.1])
110/tcp  open  pop3        syn-ack ttl 63 JAMES pop3d 2.3.2
119/tcp  open  nntp        syn-ack ttl 63 JAMES nntpd (posting ok)
4555/tcp open  james-admin syn-ack ttl 63 JAMES Remote Admin 2.3.2
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.11 - 4.1
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=7/30%OT=22%CT=1%CU=33977%PV=Y%DS=2%DC=I%G=Y%TM=64C6D65
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=10A%GCD=1%ISR=10C%TI=Z%II=I%TS=8)OPS(O1=M
OS:5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%
OS:O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%
OS:DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 32.469 days (since Wed Jun 28 06:14:21 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=266 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: james; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT       ADDRESS
1   183.72 ms 10.14.1.95

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 30 17:30:06 2023 -- 1 IP address (1 host up) scanned in 589.41 seconds
```

So we have a few different ports open here to look through.   
1) ssh running OpenSSH 7.2p2 Ubuntu 4ubuntu2.1
2) smtp running smtpd 2.3.2
3) pop3 running pop3d 2.3.2
4) nntp running nntpd (posting ok)
5) "james-admin" running Remote Admin 2.3.2 (Unknown Service?)

Based on this, lets see what we can find for each one, in order. 
Based on the number, I'm going to evaluate vectors first and see if anything looks appropriate, then proceed.

### SSH Vulns
This version of SSH has a few username enumeration vulnerabilities - potential for cracking?
```bash
└─$ searchsploit OpenSSH 7.2p2    
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                                                | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                                                          | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                                                                                                                    | linux/remote/40136.py
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                                | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                                                    | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                                                                                   | linux/remote/40113.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

### SMTP Vulns 
Only one seemingly related / available vuln here; we might not target this first.
```bash
OpenSMTPD < 6.6.3p1 - Local Privilege Escalation + Remote Code Execution                                                                                | openbsd/remote/48140.c
```

### Pop3 Vuln
Looks like only "maybe" 3 here - we can review.
```bash
└─$ searchsploit pop3 2.3.2
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (1)                                                                                                  | linux/remote/1813.c
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (2)                                                                                                  | multiple/remote/2053.rb
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (3)                                                                                                  | linux/remote/2185.pl
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

### NNTP 
All the available nntp results seem to be for windows, and I believe we have determined this to be a Linux system.

### James Admin / Remote Admin
So I didn't realize, James meant Apache James - we have a few hits here specifically for this version, and it does stand out, so lets start with this one?
```
└─$ searchsploit james        
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache James Server 2.2 - SMTP Denial of Service                                                                                                        | multiple/dos/27915.pl
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit)                                                                    | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                                                                                                    | linux/remote/35513.py
Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)                                                                          | linux/remote/50347.py
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Checking the googs, I found [this](https://www.exploit-db.com/docs/english/40123-exploiting-apache-james-server-2.3.2.pdf) article that describes the vulnerability.


### Exploitation

### Remediation
