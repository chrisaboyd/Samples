# Web Application Passwords

Breaking passwords with brute force techniques is one way. This revolves around extracting hashes brute forcing on a local machine using password lists. What if we could brute web application passwords with Burp Suite and Hydra?

Most web apps require login forms for accessing user functionality and admin panels. This involves a pretty simple HTTP GET or HTTP POST request. The first part of this is to determine - what exactly gets sent when you fill in a form and click `submit` ? We could then modify the payload and send the request using Burp Suite or Hydra. 

### Set Up Burp Suite

The first step is to setup your local browser (Firefox) to use a proxy - in this case we will set it to 127.0.0.1 and port 8080. Ensure proxying is not happening for the localhost.

Once this is done, and Burp Suite is started we can submit credentials in a form and click submit. For demonstration purposes, the following is submitted:

* Username: uNameField
* Password: pwField

Once this is submitted, we can the the request is submitted like:
`GET /dvwa/vulnerabilities/brute/?username=uNameField&password=pwField&Login=Login HTTP/1.1`.
Now we can use Burp Suite and select `Send to Intruder`. This will allow us to repeatedly send the request with different inputs. 
At this point we can turn off the proxy and intercept mode - the rest of the work would be conducted in Burp Suite. 
Now we can pivot to using `Intruder` - we can see that the details are already filled in with the target + port .
The next tab `positions` identifies the items that we wish to attempt. We want to specify a **designated** user, and position like the password to brute force. 
Next we can load the password lists on the payloads tab. Here we can choose a simple list and look under /usr/share/wordlists. Long lists are loaded into memory which can take a while. If you are using a large wordlist such as "rockyou.txt" - it's best to specify a runtime list as the payload as it's read from disk when the attack is launched.

Last, we can separate a failed login from a successful one  in the options tab using the `Grep - Match`. We can add the literal "Username and/or password incorrect" or whatever response we received when we tested manually to filter out the negatives. Now we can click "Start Attack".

Results will be displayed in a new window with the response indicated by the check mark.

## Hydra

Hydra is another great tool for brute forcing web forms with GET and POST requests. Same as before our first step is to setup a proxy server with Burp Suite to intercept the request. This provides our baseline for what inputs are submitted, and what the response is. From this information, we can determine that the following might be required:

* IP Address
* GET/POST: http-get-form or http-post-form
* Username: -l for a static username or -L for a list
* Password: -p for static password or -P for a password list
* Number of threads: -t 

```sh
# Hydra
hydra [ip] [form: <url>: <form parameters>:<failure string>:Cookie]
# example
hydra 10.11.1.250 -t 2 -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"
```

This is great, but what if we need a session cookie?
What if there is another parameter such a `login` parameter? 
In this case, we can add some fields / settings to the hydra command as follows:

```bash
# We add the H=Cookie, security=Low, and `Login` returns field
hydra 10.11.1.250 -t 2 -l admin -P /usr/share/wordlists/rockyou.txt http-form-get "/dvwa/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=low;PHPSESSID=409e45633a8281adb8f182021cfacd14"
# -v for verbose mode
# -V to display each attempt
# -D for debugging
```

One issue with Hydra failed attempts could be an invalid or missing session ID. Hydra requires precision and accurate configuration - it's important to ensure no typos in command or parameters