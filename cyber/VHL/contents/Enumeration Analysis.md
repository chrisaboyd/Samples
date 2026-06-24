## Metasploitable 2 Enumeration



Using previous scanning and enumeration information, a test box has shown the following:

- Running Linux 2.6.9 - 2.6.33 as an OS

- Server hostname is METASPLOITABLE

- 35 User Accounts

- `msfadmin` is the administrator

- No expiry date on the administrator account

- Webserver and SQL running

- The following tables of ports are open:

  | Service                             | Port     |
  | ----------------------------------- | -------- |
  | Vsftpd 2.3.4                        | 21       |
  | OpenSSH 4.7p1 Debian 8ubuntu 1      | 22       |
  | Linux telnetd                       | 23       |
  | Postfix smtpd                       | 25       |
  | ISC Bind 9.4.2                      | 53       |
  | Apache https 2.2.8 Ubuntu DAV/2     | 80       |
  | RPCbind                             | 111      |
  | Samba smbd                          | 139, 445 |
  | 3 r services                        | 512-514  |
  | GNU Class path grmiregsitry         | 1099     |
  | Metasploitable root shell           | 1524     |
  | NFS                                 | 2048     |
  | ProFTPD 1.3.1                       | 2121     |
  | MySQL 5.0.51a-3ubuntu5              | 3306     |
  | PostgreSQL DB                       | 5432     |
  | VNC                                 | 5900     |
  | X11                                 | 6000     |
  | Unreal ircd                         | 6667     |
  | Apache Jserv procol 1.3             | 8009     |
  | Apache Tomcat/Coyote JSP Engine 1.1 | 8180     |
  | dRub (with Nmap -p-)                | 8787     |
  |                                     |          |

As we don't know what services CAN be exploited at this time, we will use different tools to search for any vulnerabilies that could apply. 

* Exploit-db from Offensive Security
* Open Source Vulnerability Database (OSVDB)
* Google
* Searchsploit 

### Assessing VSFTPD 

We know VSFTPD version 2.3.4 is running, so let's start there. Googling 'vsftpd 2.3.4 exploit' yields a [backdoor](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor).  
We can also find a Metasploit module that exploits this vulnerability:

> CVE-2011-02523
> OSVDB: 73573

### Assessing dRuby RMI server 1.8 

It's important to run a full port scan to ensure open ports aren't missed. 
dRuby is a distributed object system for RUby, and writte in ruby. 
By default, nmap does not scan 8787, unless all ports are scanned with `-p-`. 

* Scanning this service specifically:
  	`nmap -sV [IP] -p8787` 

### Assessing Unreal ircD vulnerabilities

Well known IRC service supporting different platforms. 
To determine service version, and identify potential for vulnerabilites, we can use netcat. 

* Grabbing a banner:
  	`nc [target IP] 6667` 
* Checking with nmap as well:
  	`sudo nmap -A -p 6667 [target host]`
* We can also install an irc client and test the connection:

```bash
sudo apt install ircii
irc test [targetIP]:6667
```

With the version information that we determined `Unreal3.2.8.1` Google reveals the potential for a [backdoor](https://www.rapid7.com/db/modules/exploit/unix/irc/unreal_ircd_3281_backdoor)

### Assesing Samba smbd 3.x

Samba has a track record with known vulnerabilities. Lets scan Samba specifically to get more details:

`sudo nmap -A 10.11.1.250 -p139` 

This dicovered the exact version number using the SMB OS Discovery script. Samba 3.0.20-Debian is the version running. Again, back to using Google, we can see this contains a command execution [vulnerability](https://www.rapid7.com/db/modules/exploit/multi/samba/usermap_script). 