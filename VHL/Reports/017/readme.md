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
Nmap scan report for 10.14.1.39
Host is up, received user-set (0.17s latency).
Scanned at 2023-08-06 15:46:12 EDT for 310s
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 cd:bb:37:7a:fc:a2:56:3f:25:69:54:27:94:2a:81:a4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSrdpa5qh6sj/Kdq5O8bk6ycPGelVOORiXAg2B/p2429w3fjWDuwkPE8ou0WLBK3ZlgdsCcj12CxGrAM5A7abSBVcoAeOxFxlR6OivL9IpU66c3ROWSSBU18QXoj5rLWoWEmanVE8Y8VUv+pgWuMgLP1NbxtT0qi0lTYp401WMADwUWMMZa5HGB7nubUchZvipLpzOyrV+gwfTeArOILY50gQzePAw0Wy4Kyl6J99MvZaPOYXQei17L8arAUsDi/N+CWIKjQwXk76bL43DvuSJ5USEDwNg4iQJiA+vGrIBO7FYcmGx0gyIww+vuirJ0Cf0vQMNoRIXZCoH6ej9ezTh
|   256 f7:fc:b9:bd:45:b6:e8:40:9d:ee:68:19:d4:48:f5:1d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGLxoj7H/MQ2XFw74rOPmxYEulmhZmNf/Aqkvb83c90EKpdJv0CDHk6t/QkCars2MaTXrSXzG1ApXtq1csIO44c=
|   256 10:2c:35:1c:5c:8b:62:73:40:0a:30:00:9a:9a:d5:2a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBtCUEx5djFMO04UrUZ0ADBjZIrQppBl51sse2O28gsl
80/tcp   open  http       syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) PHP/7.2.34)
|_http-generator: Tiki Wiki CMS Groupware - https://tiki.org
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 8039B86E4B5DA2D0A2B0C406ED2CE2E4
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.2.34
| http-title: Tiki | HomePage
|_Requested resource was http://10.14.1.39/tiki-index.php
| http-robots.txt: 40 disallowed entries 
| / /tiki-forums.php /tiki-view_forum.php 
| /tiki-index.php /tiki-read_article.php /tiki-view_blog.php 
| /tiki-list_file_gallery.php /tiki-view_forum_thread.php /*structure=*  /temp/ 
| /addons/ /admin/ /backup/ /db/ /doc/ /dump/ /installer/ /lang/ 
| /maps/ /mods/ /modules/ /permissioncheck/ /popups/ 
| /templates/ /tests/ /vendor* /get_strings.php /tiki-admin 
| /*sort_mode=* /*latest=1* /*PHPSESSID= /*display=print* 
| /*show_comzone=* /*page_ref_id=* /*topics_offset=-1* /*show_details=* 
|_/*offset=0* /*print=y* /*fullscreen=y* /*mode=mobile*
3306/tcp open  mysql      syn-ack ttl 63 MySQL (unauthorized)
8080/tcp open  http-proxy syn-ack ttl 63
|_http-favicon: Unknown favicon MD5: F6EE149072C0F07CF229A508B6CD4A74
|_http-title: File Browser
| http-methods: 
|_  Supported Methods: GET
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: no-cache, no-store, must-revalidate
|     Content-Type: text/html; charset=utf-8
|     X-Xss-Protection: 1; mode=block
|     Date: Sun, 06 Aug 2023 19:46:19 GMT
|     <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no"><title>File Browser</title><link rel="icon" type="image/png" sizes="32x32" href="/static/img/icons/favicon-32x32.png"><link rel="icon" type="image/png" sizes="16x16" href="/static/img/icons/favicon-16x16.png"><link rel="manifest" id="manifestPlaceholder" crossorigin="use-credentials"><meta name="theme-color" content="#2979ff"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black"><meta name="apple-mobile-web-app-title" content="assets"><link rel="appl
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Cache-Control: no-cache, no-store, must-revalidate
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sun, 06 Aug 2023 19:46:19 GMT
|     Content-Length: 14
|     Found
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94%I=9%D=8/6%Time=64CFF88C%P=x86_64-pc-linux-gnu%r(Get
SF:Request,11AC,"HTTP/1\.0\x20200\x20OK\r\nCache-Control:\x20no-cache,\x20
SF:no-store,\x20must-revalidate\r\nContent-Type:\x20text/html;\x20charset=
SF:utf-8\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Sun,\x2006\x
SF:20Aug\x202023\x2019:46:19\x20GMT\r\n\r\n<!DOCTYPE\x20html><html\x20lang
SF:=\"en\"><head><meta\x20charset=\"utf-8\"><meta\x20http-equiv=\"X-UA-Com
SF:patible\"\x20content=\"IE=edge\"><meta\x20name=\"viewport\"\x20content=
SF:\"width=device-width,initial-scale=1,user-scalable=no\"><title>File\x20
SF:Browser</title><link\x20rel=\"icon\"\x20type=\"image/png\"\x20sizes=\"3
SF:2x32\"\x20href=\"/static/img/icons/favicon-32x32\.png\"><link\x20rel=\"
SF:icon\"\x20type=\"image/png\"\x20sizes=\"16x16\"\x20href=\"/static/img/i
SF:cons/favicon-16x16\.png\"><link\x20rel=\"manifest\"\x20id=\"manifestPla
SF:ceholder\"\x20crossorigin=\"use-credentials\"><meta\x20name=\"theme-col
SF:or\"\x20content=\"#2979ff\"><meta\x20name=\"apple-mobile-web-app-capabl
SF:e\"\x20content=\"yes\"><meta\x20name=\"apple-mobile-web-app-status-bar-
SF:style\"\x20content=\"black\"><meta\x20name=\"apple-mobile-web-app-title
SF:\"\x20content=\"assets\"><link\x20rel=\"appl")%r(HTTPOptions,DF,"HTTP/1
SF:\.0\x20404\x20Not\x20Found\r\nCache-Control:\x20no-cache,\x20no-store,\
SF:x20must-revalidate\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:X-Content-Type-Options:\x20nosniff\r\nDate:\x20Sun,\x2006\x20Aug\x20202
SF:3\x2019:46:19\x20GMT\r\nContent-Length:\x2014\r\n\r\n404\x20Not\x20Foun
SF:d\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(FourOhFourRequest,11AC,"HTTP/1\.0\x20200\x20OK\r
SF:\nCache-Control:\x20no-cache,\x20no-store,\x20must-revalidate\r\nConten
SF:t-Type:\x20text/html;\x20charset=utf-8\r\nX-Xss-Protection:\x201;\x20mo
SF:de=block\r\nDate:\x20Sun,\x2006\x20Aug\x202023\x2019:46:19\x20GMT\r\n\r
SF:\n<!DOCTYPE\x20html><html\x20lang=\"en\"><head><meta\x20charset=\"utf-8
SF:\"><meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"><meta
SF:\x20name=\"viewport\"\x20content=\"width=device-width,initial-scale=1,u
SF:ser-scalable=no\"><title>File\x20Browser</title><link\x20rel=\"icon\"\x
SF:20type=\"image/png\"\x20sizes=\"32x32\"\x20href=\"/static/img/icons/fav
SF:icon-32x32\.png\"><link\x20rel=\"icon\"\x20type=\"image/png\"\x20sizes=
SF:\"16x16\"\x20href=\"/static/img/icons/favicon-16x16\.png\"><link\x20rel
SF:=\"manifest\"\x20id=\"manifestPlaceholder\"\x20crossorigin=\"use-creden
SF:tials\"><meta\x20name=\"theme-color\"\x20content=\"#2979ff\"><meta\x20n
SF:ame=\"apple-mobile-web-app-capable\"\x20content=\"yes\"><meta\x20name=\
SF:"apple-mobile-web-app-status-bar-style\"\x20content=\"black\"><meta\x20
SF:name=\"apple-mobile-web-app-title\"\x20content=\"assets\"><link\x20rel=
SF:\"appl");
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 4.4 (96%), Linux 2.6.32 or 3.10 (95%), Linux 2.6.32 - 2.6.35 (94%), Linux 2.6.32 - 2.6.39 (94%), Linux 4.0 (93%), Linux 5.0 - 5.4 (93%), Linux 3.11 - 4.1 (92%), Linux 3.2 - 3.8 (92%), Linux 2.6.18 (92%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/6%OT=22%CT=1%CU=44274%PV=Y%DS=2%DC=I%G=Y%TM=64CFF9BA
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10B%TI=Z%II=I%TS=A)SEQ(SP=10
OS:7%GCD=1%ISR=10B%TI=Z%TS=A)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%II=I%TS=A)OPS(O1
OS:=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW
OS:7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=
OS:Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%R
OS:D=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q
OS:=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=
OS:G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 24.805 days (since Wed Jul 12 20:31:37 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT       ADDRESS
1   169.56 ms 10.14.1.39

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  6 15:51:22 2023 -- 1 IP address (1 host up) scanned in 310.28 seconds

PORT     STATE SERVICE REASON         VERSION
3306/tcp open  mysql   syn-ack ttl 63 MySQL (unauthorized)
| banner: C\x00\x00\x00\xFFj\x04Host '172.16.4.1' is not allowed to conne
|_ct to this MySQL server
|_mysql-empty-password: Host '172.16.4.1' is not allowed to connect to this MySQL server

```

OS Type: `Linux 2.6.32 (96%)`

| Port | Service | Protocol | Version |
| -----| ------- | -------- | ------- |
| 22  | SSH | TCP | OpenSSH 7.4 |
| 80   | HTTP | TCP | Apache httpd 2.4.6 ((CentOS) PHP/7.4.30) |
| 3306   | mysql | TCP | ? |
| 8080   | HTTP | TCP | ? |


Notable items:  
MySQL is exposed, but I can't connect from my host.
8080 is serving another undetected webpage.

### Nikto
```bash
+ Server: Apache/2.4.6 (CentOS) PHP/7.2.34
+ /: Retrieved x-powered-by header: PHP/7.2.34.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie javascript_enabled_detect created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ Root page / redirects to: http://10.14.1.39/tiki-index.php
+ /mods/: Directory indexing found.
+ /robots.txt: Entry '/mods/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/permissioncheck/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: contains 44 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ PHP/7.2.34 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /files/: Directory indexing found.
+ /files/: This might be interesting.
+ /icons/: Directory indexing found.
+ /README: README file found.
+ /xmlrpc.php: xmlrpc.php was found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /license.txt: License file found may identify site software.
+ /composer.json: PHP Composer configuration file reveals configuration information. See: https://getcomposer.org/
+ 8523 requests: 0 error(s) and 19 item(s) reported on remote host
+ End Time:           2023-08-06 16:22:00 (GMT-4) (1837 seconds)

+ Target IP:          10.14.1.39
+ Target Hostname:    10.14.1.39
+ Target Port:        8080
+ Start Time:         2023-08-06 15:51:23 (GMT-4)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /css/: This might be interesting.
+ /img/: This might be interesting.
+ /js: This might be interesting.
+ /fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /FCKeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /Script/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /sites/all/modules/fckeditor/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /modules/fckeditor/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /class/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /inc/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /sites/all/libraries/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /js/editor/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /includes/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /include/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /modules/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /plugins/fckeditor/editor/dialog/fck_flash.html: FCKeditor could allow files to be updated or edited by remote attackers.
+ /composer.json: PHP Composer configuration file reveals configuration information. See: https://getcomposer.org/
+ 7737 requests: 0 error(s) and 19 item(s) reported on remote host
+ End Time:           2023-08-06 16:19:15 (GMT-4) (1672 seconds)

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
