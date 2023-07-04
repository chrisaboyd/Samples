# Compiling Linux Kernel Exploits

Linux kernels have a history of privilege escalation of vulnerabilities, allowing non-privileged users to escalate their privileges to root. 

* DirtyCOW (CVE-2016-5195 and CVE-2017-6074) leaves a lot of hosts vulnerable

## Compiling C -> Assembly

Looking at the following exploit from Exploit DB:
```bash 
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty Cow' /proc/self/mem Race Condition Privilege Escalation (SUID) - https://exploit-db.com/exploits/40616
```

This exploit creates a passwd binary file with SUID permissions, and upgrades the terminal session with root privileges.  Because the exploit is written in C, it must be compiled first using GCC (GNU Compiler Collection).

```bash 
gcc cowroot.c -o cowroot -pthread
# Source code -> output binary, and -pthread for POSIX thread support.
```

Lets look at another one:

```bash 
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) -'overlayfs' Privilege Escalation - https://exploit-db.com/exploits/37292
```

Information in the source code contains how to compile:

```bash
gcc ofs.c -o ofs
./ofs
```

 ### Local Vs Remote Compilation

If the remote host has compilation tooling, it's best to compile the exploit on the target host. This can help with missing packages, dependencies, and system variables like architecture. If the target does not have the necessary tooling, you will need to compile locally.

> If you receive errors to linked libraries not present, you can fix by appending -static to the compilation.

