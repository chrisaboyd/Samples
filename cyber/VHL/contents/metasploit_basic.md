# Metasploit Basic Commands

First thing first, need to start metasploit. Lets group commands into three categories - 

* Basic - `search`, `use`, `back`, `help`, `info`, `exit`
* Exploit - `set` for variables, `show` for options, targets payloads
* Exploit execution - `run` and `exploit`

### Search

There are almost 2100 different exploits, so its imperative to know how to find what you're looking for. 
`search flash` - Searches for exploits either related to flash, or with flash in the name. 
`search cve:2020 type:exploit` - Searches for CVEs from 2020 or containining the number 2020, that are exploits.
`search cve:2020 platform:windows` - Same as above, but searches for windows specifically

### Use, Back, Exit

`use` activates a module and changes the msfconsole command line to that module. 
`back` leaves the exploit context.
`exit` returns you to the Linux command line. 

### Help

Can be used to get details at each context - 
`help exploit` - Gets details about the current exploit context

### Info

Shows options, targets, description, general info, disclosure date.

### Adding A New Module to Metasploit 

You can add exploit modules that are not yet included in the framework.
For example, - [Zero Shell 3.9.0 - cgi-bin/kerbynet](https://www.exploit-db.com/exploits/49096) can be found on Exploit-DB.

```bash
# Choose a directory to store the exploit
cd /usr/share/metasploit-framework/modules/exploits/linux/http

# Download the exploit
sudo wget https://www.exploit-db.com/download/49096 -O 49096.rb

# Start msfconsole
msfconsole
# Reload modules
reload_all
# Verify
search 49096
```

