# Pentest 21 - NAS - 121 - 10.14.1.121

## Scanning and Enumerating

### Nmap
```bash

```

OS Type: `Linux 2.6.36 (98%)`

| Port | Service | Protocol | Version |
| -----| ------- | -------- | ------- |
| 21   | FTP | TCP | vsftpd 3.0.2 |
| 22  | SSH | TCP | OpenSSH 7.4 (protocol 2.0) |
| 80   | HTTP | TCP | Apache httpd 2.4.6 ((CentOS) PHP/7.4.30) |
| 8080   | HTTP | TCP | Apache httpd 2.4.6 ((CentOS) PHP/7.4.30) |


Notable items:  


### Nikto
```bash

```
## Exploitation

### Initial Access
I already had the password from [Anthony](/VHL/Reports/007/readme.md), which was `admin:nas4free123`. 
Once I connected, I poked around the browser, finding a file uploader AND editor.
Additionally, based on my scanning results, I could see on 8080 there were files being enumerated in `/var/www/html`.
I re-used my `shell.php` and triggered this - I got a shell!

### Privilege Escalation
There was no privilege escalation here, but I was also not running as root in this case. 
I didnt have uname, or wget, to enumerate. Going back and reading the notes, it seems like I just needed to get the `key.txt`? 
What I noticed interesting, was that the filebrowser had the path in the URL that it was constructing like :
`?action=list&dir=var%2Fwww%2Fhtml%2Ffiles&order=name&srt=yes`

What if I just checked `/root?`

Success!
## Identified Vulnerabilities

- [CVE]()


## Remediation

The main factor(s) leading to initial access included:  
- The administrator password was saved in a previous scenario, allowing me access to the administrator panel.

The main factor(s) leading to privilege escalation here were:  
- The web browser was running with root permissions, allowing me to enumerate the filesystem as root through the web interface. 

Remediation steps then include:
- Run as a lesser privileged user
- Change the password

Images:
![image1](/VHL/Reports/012/images/12_1.png)
![image2](/VHL/Reports/012/images/12_2.png)
![image3](/VHL/Reports/012/images/12_3.png)
![image4](/VHL/Reports/012/images/12_4.png)
![image5](/VHL/Reports/012/images/12_5.png)
![image6](/VHL/Reports/012/images/12_6.png)
![image7](/VHL/Reports/012/images/12_7.png)
![image8](/VHL/Reports/012/images/12_8.png)
![image9](/VHL/Reports/012/images/12_9.png)
![image10](/VHL/Reports/012/images/12_10.png)
![image11](/VHL/Reports/012/images/12_11.png)
![image12](/VHL/Reports/012/images/12_12.png)
![image13](/VHL/Reports/012/images/12_13.png)
![image14](/VHL/Reports/012/images/12_14.png)
![image15](/VHL/Reports/012/images/12_15.png)
![image16](/VHL/Reports/012/images/12_16.png)

| User | Pass |
| ---- | ---- | 
| admin | admin@123 | 
| user | 12345 |
