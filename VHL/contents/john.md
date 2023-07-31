# John

John can brute force NTLM, MD5, and SHA1 hashes. It's important to first identify the hashes however, to facilitate this process.

### Hash-identifier

Command line tool that can be used for identifying the types of hashes. Started as a binary by typing the name, then inputting the hash - 

```bash
# First generate a test hash
echo -n admin | md5sum
# Start hash-identifier
hash-identifier
# Paste the hash - it's determined as either MD5 or MD4
```

### Crack the hash

Once the hash is by itself in a text file we can try to crack it:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt -format=Raw-MD5 /root/Desktop/john.txt
```

