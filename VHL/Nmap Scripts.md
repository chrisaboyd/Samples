# Nmap Scripts

We can start metasploit to see if a service is vulnerable, but we can already start with Nmap much easier to see if it can be exploited. Let's look at a couple examples that contain Nmap scripts already:

1. [ftp-vsftpd-backdoor](https://nmap.org/nsedoc/scripts/ftp-vsftpd-backdoor.html)
2. irc-unrealircd-backdoor



### VSFTPD v2.3.4 Nmap Script

Tests the targeted service installation for a backdoor. Executing like:
```bash 
nmap --script ftp-vsftpd-backdoor -p 21 [target host]
# Returns the service is vulnerable - CVE:CVE-2011-2523
```

### Unreal IRCd Nmap Script

Checks the target host for unrealircd vulnerability. Executing like:

```bash
nmap -sV -p6667 --script=irc-unrealirc-backdoor [target host]
# Only returns 'looks like trojaned version'
```

Because the script issues a command on the target using the backdoor, but the command output isn't returned to verify, we can't be 100% percent.