---
tags:
- helpdeskz
- graphql
- port3000
- sqli
- file-upload
- linux-kernel
- 4.4.0-116
created: 2025-04-19
lastmod: 2025-04-22
published: 2025-04-22
image: /static/completed-screenshots/htb-help.png
description: Help is an Easy Linux box which has a GraphQL endpoint which can be enumerated get a set of credentials for a HelpDesk software. The software is vulnerable to blind SQL injection which can be exploited to get a password for SSH Login. Alternatively an unauthenticated arbitrary file upload can be exploited to get RCE. Then the kernel is found to be vulnerable and can be exploited to get a root shell.
---

![HTB-Help thumbnail](/static/note-thumbnails/htb-help.png)
## Initial Enumeration

>[!code]- Open ports (22, 80, 3000)
>![](Images/Pasted%20image%2020250421053714.png)
### Port 80

>[!code]- Add `help.htb` to `/etc/hosts`
>###### The IP address redirects to `help.htb`
>![Pasted image 20250419061657](Images/Pasted%20image%2020250419061657.png)
>###### Add `help.htb` to `/etc/hosts`
>![Pasted image 20250419061835](Images/Pasted%20image%2020250419061835.png)

>[!code]- Web server is running Apache 2.4.18
>###### Landing page shows a default Apache page
>![Pasted image 20250419061915](Images/Pasted%20image%2020250419061915.png)
>###### Not found page shows Apache version
>![Pasted image 20250419062113](Images/Pasted%20image%2020250419062113.png)

>[!code]- Find the `/support` page for a service called `HelpDeskZ`
>###### FFUF bruteforce
>![Pasted image 20250419062212](Images/Pasted%20image%2020250419062212.png)
>###### `/support` page
>![Pasted image 20250419062232](Images/Pasted%20image%2020250419062232.png)
### Port 3000

>[!code]- Find a GraphQL instance running at `/graphql`
>At first I requested the landing page to receive this message:
>
>![](Images/Pasted%20image%2020250421054832.png)
>
>I tried to enumerate other pages but didn't get anywhere. I also tried parameter fuzzing with no success.
>
>After doing some research, I found that port 3000 with a node.js instance can be related to graphql. [Hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html) suggested to try `/graphql` - which I did with success. It turns out this key term isn't included in common wordlists, like `common.txt` or `directory-listing-2.3-medium.txt` etc.
>
>![](Images/Pasted%20image%2020250421055037.png)

>[!code]- Enumerate `/graphql` for a schema
>From the last command we got:
>
>![](Images/Pasted%20image%2020250421055037.png)
>
>It say there's a missing GET parameter, so I add one:
>
>![[Images/Pasted image 20250421055129.png]]
>
>It says to provide a query string - so I try to add one (using an example query from [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html) to enumerate the schema (and whilst escaping curly brackets to avoid Bash errors)):
>
>![[Images/Pasted image 20250421055705.png]]
>
>![[Images/Pasted image 20250421055722.png]]
>
>After a few unsuccessful tries, I remove the `get` parameter and replace it with `query`, which works:
>
>![[Images/Pasted image 20250421055809.png]]
#### Find user credentials

>[!code]- Enumerate `/graphql` to discover user credentials (email:hash)
>From the output in the browser, we can more clearly see the schema. It shows a `User` object with the values `Username` and `Password`
>
>![[Images/Pasted image 20250421060544.png]]
>
>[HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html) shows how we can enumerate a objects values:
>
>![[Images/Pasted image 20250421060706.png]]
>
>So lets try that for the `User` object
>
>```powershell
>http://10.10.10.121:3000/graphql?query={user{username,password}}
>```
>
>URL encode first:
>
>![[Images/Pasted image 20250421063313.png]]
>
>Get back a username and password:
>- email: `helpme@helpme.com`
>- hash: `5d3c93182bb20f07b994a7f617e99cff`
>
>![[Images/Pasted image 20250421063346.png]]

>[!code]- Crack the hash (`godhelpmeplz`)
>Identify the hash as MD5:
>
>![[Images/Pasted image 20250421065344.png]]
>
>Use HashCat to crack it:
>- `-m 0` to specify md5
>
>![[Images/Pasted image 20250421065513.png]]
>![[Images/Pasted image 20250421065537.png]]
>
## Local user
### File upload vulnerability

>[!code]- Login to the HelpDeskZ support portal
>
>![[Images/Pasted image 20250421065833.png]]
>![[Images/Pasted image 20250421065849.png]]

>[!code]- Execute a file upload exploit
>[This exploit](https://www.exploit-db.com/exploits/40300) suggests we can upload a PHP reverse shell via the `Submit Ticket` page, and then execute that shell by brute forcing the possible file names. The exploit suggests the uploaded file's name will be derived from a MD5 hash of the current time combined with the original file name:
>
>```python
>plaintext = fileName + str(currentTime - x)
>md5hash = hashlib.md5(plaintext).hexdigest()
> "http://10.10.10.121/support/" + md5hash + ".php"
>```
>
>Create a PHP reverse shell (Ivan Sincek variant) using [revshells.com](https://www.revshells.com/):
>
>![[Images/Pasted image 20250421114652.png]]
>
>Upload the shell when submitting a support ticket on HelpDeskZ:
>
>![[Images/Pasted image 20250421114840.png]]
>
>I get a `File is not allowed` error:
>
>![[Images/Pasted image 20250421114951.png]]
>
>I uploaded the file by changing its name from `shell.php` to `shell.txt` using Burp, but then could not identify the file afterwards.
>
>I found this exploit, which suggests the files are uploaded to `/support/uploads/tickets/`:
>
>![[Images/Pasted image 20250421170128.png]]
>
>I run the exploit (having setup a listener) and catch the reverse shell:
>
>![[Images/Pasted image 20250421170159.png]]

>[!info]- There is also an SQLi vulnerability - but not needed
>[This exploit](https://www.exploit-db.com/exploits/41200) suggests one of the `param[]` parameters at 
>Submit a support ticket and include an attachment (as per the exploit, which says the attachments table needs to be populated for the exploit to work):
> 
>![[Images/Pasted image 20250421120633.png]]
>
>I got access to the MySQL DBMS using sqlmap -r request, having captured the GET request that is made when clicking the attachment within the ticket, having viewed the tickets at `My Tickets`. I won't detail this path any further because, whilst it did reveal a password for `root`, I could not use it to SSH into the machine.
### Shell access

>[!success]- Obtain user.txt
>![[Images/Pasted image 20250421170545.png]]
>
## Root user
### Enumeration

>[!code]- The Linux kernel is potentially vulnerable (`4.4.0-116`)
>Enumerate the system information:
>
>![[Images/Pasted image 20250422053028.png]]
>
>Find a possible exploit on searchsploit (bottom result):
>
>![[Images/Pasted image 20250422053141.png]]
### Kernel exploit

>[!fail]- Attempt to transfer a pre-compiled version of the exploit
>Having compiled the C code on my attacking machine, I transferred it to the victim and attempted to execute it, but I received an error relating to a missing package of some sort:
>
>![[Images/Pasted image 20250422053903.png]]
>
 >This prompted me to see whether I could compile the file on the victim machine instead. Fortunately the victim machine had `gcc` installed, so I could:
 >
 >![[Images/Pasted image 20250422053957.png]]

>[!code]- Compile and execute the exploit on the victim to obtain root permissions
>Compile the exploit C code and assign the compiled copy executable permissions:
>
>![[Images/Pasted image 20250422054104.png]]
>
>Run it to obtain a root shell:
>
>![[Images/Pasted image 20250422054149.png]]

>[!success]- Obtain root.txt
>![[Images/Pasted image 20250422054217.png]]

![[Images/Pasted image 20250422054448.png]]

