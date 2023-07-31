# Cross-Site Scripting (XSS)

Client-side scripts are executed in the users' web browser. This adds behavior to a webpage, without needing to switch or reload web pages. An example might be a webpage that notifies you of the strength of a password as you enter it. They can also be used to transfer information, handle responses, load content. This does introduce attack vectors however, and allow injection - executing code in user's browsers.  At tis core, this allows an attacker to inject malicious client-side scripts to a webpage. This targets a vulnerable webpage, that then delivers the payload to another visitor. 

The most severe XSS vulnerabilities can be exploited allowing:

* Hijacking of accounts
* Stealing sensitive information
* Modifying Page content
* Defacing websites
* Redirecting users to another page
* Facilitating phishing campaigns
* Recording keystrokes
* Trick users into downloading files / entering information

## Reflected XSS

Known as non-persistent XSS - the XSS payload originates from a user request. This occurs when a request contains user input included in the HTTP request response, like when JavaScript is executed when a webpage is rendered. 
Commonly found in search functions on websites, or in username / passwords values in a login form. If the submitted page shows the search results, and the results show the keywords searches, it's an indication of an XSS vulnerability.

```bash
alert('xss') # Common way to demonstrate XSS vulnerabilities that pops an alert box
```

Simple example of XSS is instering an alert to a search function:
![XSS](/Users/christopherboyd/repos/Samples/VHL/xss-05.png)

Basically, we can disguise a URL like this:
```html
<a href="http://domain/?search=<script>alert('XSS')</script>"> Click me!</a>
```

## Stored XSS

Stored cross-site scripting, or persistent XSS is when user input is permanently stored in a database and included in a webpage. With storage XSS, the script originates from a data source instead of a user request. When an unsuspecting victim visits a page, the script is inserted into the webpage, and executed by the browser. The results are generally the same, but the audience is far wider.

For example, what if we submit a comment with the following to a vulnerable page?
```text
This is a comment!
<script>alert("XSS")</script>
```

Once this is submitted, the page reloads, and you are immediately presented with an alert. When viewing the comment however, only `This is a comment!` is present. The implications here, could be what if something much more malicious took place like downloading user credentials. 

## Mitigating and Preventing XSS

Escapting Input - escape all user input in response to HTML via `htmlspecialchars()`.  

| Character        | Replacement                                  |
| ---------------- | -------------------------------------------- |
| & (ampersand)    | &amp;                                        |
| ” (double quote) | &quot;, unless ENT_NOQUOTES is set           |
| ‘ (single quote) | &#039; or &apos; only when ENT_QUOTES is set |
| < (less than)    | &lt;                                         |
| > (greater than) | &gt;                                         |

### Sanitizing Input

Sanitization removes / replaces the characets and html tags entirely. It's important to ensure the data is still usable. zz

### Validating Input 

Its important to ensure data is input appropriately - think zip codes, or phone numbers should meet very specific criterias. 

### Web Application Firewall

Monitors traffic and blocks content defines as unwanted or malicious. It applies a set of rules to detect malicious activity such as SQL injection, cross-site scripting, and file inclusion. 

### HTTPOnly Flag

Sets JavaScript from accessing cookies, and only sends it to the server. Prevents cookie theft and session hijacking. If a browser detects HttpOnly on a cookie requested, it returns an empty string. Only prevents protected cookies. 