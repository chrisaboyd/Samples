# Generating Password Lists

Password dictionary and brute force attacks involve creating a file of obvious / popular passwords. They are combined with reasoning and research to optimize the attacks, based on identifying character length, and character set. We can also use knowledge about the user, such as birthdays, vacation spots, family members, etc. as well as previously exposed / compromised passwords. We can lastly modify the character sets such as substition - 0 for an O, S for a 5, etc.

### Password Spraying

A password dictionary attack that attempts to bypass lockouts and rate limits. Instead of targeting a specific account, it attempts common passwords on a large number of accounts.  This helps when deterining what the lockout policies are, and testing just under this threshold, such as 25 failed attempts in a 30 minute window. 

### Default Passwords

Many systems on network decices, services, and applications come with a default password. Keep an eye out for IP cameras, IP phones, routers, switches, applications, and services. You can use password dictionary files, but also just product documentation to get in. 

## Generating Lists

### Crunch

A tool that can generate custom password lists uses for brute forcing. Can create lists that contain:

* All possible combinations for a given number of letters
* All combinations for a range of characters followed by text
* Specified Ranges 

Usage:
`crunch [min length] [max length] [charset] [options]`

```bash
# Create list of passwords consisting of 4 capital letters in all possible combos
crunch 4 4 ABCDEFGHIJKLMNOPQRSTUVWXYZ -o /root/Desktop/wordlist.txt
# Create for all possible combinations of 5 digits
crunch 5 5 0123456789 -o /root/Desktop/numbers.txt
# Create all possible 4 capital letters + 1980
crunch 8 8 ABCDEFGHIJKLMNOPQRSTUVWXYZ -t @@@@1980 -o /root/Desktop/wordlist.txt
# -p Prevents Characters or Words from being repeated
crunch 1 2 -p Virtual Hacking Labs
```

### Cewl

Indexes all pages of a website based on the parameters set, and outputs a list of all words it finds.

```bash
# -d max depth to scrape
# -m Minimum word length to save
# -o offsite - to leave current website and go to another
# -w specify file output location
cewl -d 1 -m 8 -w /root/Desktop/cewl.txt https://www.kali.org
```

:exclamation: - If Cewl isn't working as expected, try using `-v` - it's possible a WAF is blocking requests because this generates a large number. 