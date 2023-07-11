# Remote Code Execution

RCE allows an attacker to execute arbitrary code on the target through a web application. This is sometimes considered code injection, but is not the same as remote command execution. 
With remote command execution, the commands are directly executed on the OS.
With Remote code execution vulnerabilities , the injected code is executed by the web application in the language it's running in. If a site running PHP is vulnerable to remote code execution, the attacker is limited to inject and executing PHP.

A common way to exploit remote code execution is by injecting code that allows executing system commands.
Commands like `shellexec()` in PHP and the `system` command in Perl. The ability to execute any code means we are close to a shell.

### Remote Code Execution Example

Looking at the folloing PHP code that is vulnerable:
```php
<?php $code = $_GET['code'];
eval($code); ?>
```

The first line retrieves code from the URL, while the second evaluates it. 
So we can run something like the following to run the `phpinfo()` command:
`http://[IP]/rce.php?code=phpinfo();` 

Let's try some others:
`http://[IP]/rce.php?code=system('id');` 
Unfortunately the default behavior is to only print the _last_ line, so if we want more, we need to format all the output as a string.  We can do this with the `shell_exec()` php function instead of `system()`. 
https://secure.php.net/manual/en/function.shell-exec.php

Lets test with IFConfig:

`http://[IP]/rce.php?code=echo shell_exec('/sbin/ifconfig eth0');`

From here the next step might be to enumerate the system, or inject shellcode to get a reverse shell. 