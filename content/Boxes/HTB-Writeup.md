---
created: 2025-04-22
modified: 2025-05-04
tags:
- sqli
- CMS Made Simple
- run-parts
- PATH
- SSH
image: /static/completed-thumbnails/htb-writeup.png
description: Writeup is an easy difficulty Linux box with DoS protection in place to prevent brute forcing. A CMS susceptible to a SQL injection vulnerability is found, which is leveraged to gain user credentials. The user is found to be in a non-default group, which has write access to part of the PATH. A path hijacking results in escalation of privileges to root.
---
<img src="/static/note-thumbnails/htb-writeup.png" alt="htb writeup" style="max-width: 450px; height: auto; display: block; margin: 0 auto; box-shadow: 0px 0px 14px 0px rgba(0,0,0,0.9);">

## Initial Enumeration

>[!code]- Open ports (22, 80)
>![[Images/Pasted image 20250422182640.png]]
### Port 80

>[!code]- Find the `/writeup/` subdirectory
>Landing page:
>
>![[Images/Pasted image 20250422181433.png]]
>
>`/robots.txt`:
>
>![[Images/Pasted image 20250422181506.png]]
>
>`/writeup/`:
>
>![[Images/Pasted image 20250422181538.png]]

>[!code]- Cannot brute force for other content
>The web app has a DoS filter in place, which bans your IP address if it causes too many HTTP 40x errors. I ran into this problem several times when attempting to bypass the filter. It meant I couldn't search for subdirectories or subdomains.
>
>The `/writeup/index.php` page, for example, has a `?page` parameter which might introduce a LFI vulnerability, but I wasn't able to enumerate possible payloads because my requests after so many failed attempts got blocked.
>
>![[Images/Pasted image 20250423054012.png]]

>[!code]- `/writeup/admin` requires a HTTP basic auth prompt
>![[Images/Pasted image 20250423054411.png]]
>
>I tried a few default credentials, but no luck.
## Local user

>[!code]- The web app is vulnerable to SQLi which reveals login credentials (`jkr`:`raykayjay9`)
>The site is using CMS Made Simple:
>
>![[Images/Pasted image 20250423055614.png]]
>
>I found [an SQLi exploit](https://www.exploit-db.com/exploits/46635) for version <2.2.10, which gives us a user hash:
>
>![[Images/Pasted image 20250423063104.png]]
>![[Images/Pasted image 20250423063044.png]]
>
>I cracked the password using Hashcat and the rockyou wordlist, ensuring my hash was of the format `hash:salt`:
>
>![[Images/Pasted image 20250424055221.png]]
>
>Because that was the format the exploit was assuming:
>
>![[Images/Pasted image 20250424055345.png]]

>[!code]- Those credentials work with SSH to access as `jkr`
>SSH into the machine using `jkr`:`raykayjay9`:
>
>![[Images/Pasted image 20250424055813.png]]

>[!success]- Obtain user.txt
>(Screenshot taken after a successful root, which has caused the different shell prompt)
>
>![[Images/Pasted image 20250504161647.png]]
## Root user
### Enumeration

>[!code]- We can write to `/usr/local/sbin` (among others)
>Our user `jkr` is in the `staff` group (`id` = `50`) which gives us writeable permissions (`-perm 020`) to some unusual files:
>
>![[Images/Pasted image 20250424063927.png]]
>
>Among those writeable files are `/usr/local/sbin` and `/usr/local/bin`, which usually hold binaries that are executed by user or system processes. If `root` runs something that calls upon a binary within one of these two directories, we can edit those binaries to perform something malicious.
>
>Alternatively, if root's PATH includes one of those directories at the start, or early on, and root executes a binary without specifying where to find it, there's a good chance we can have a malicious version of that binary executed instead, by placing it within either `/usr/local/bin` or `/sbin`.

>[!code]- A cron job is running `cleanup.pl` as root
>Its running `/root/bin/cleanup.pl`:
>
>![[Images/Pasted image 20250424060804.png]]
>
>We don't have read access to `cleanup.pl` so we can't see whether it runs a binary that we could edit.
>
>The `PATH` variable for cron jobs is set to have `/usr/local/sbin` first, which means any binaries mentioned (like `cleanup.pl`) are looked for within `/usr/local/sbin` first. That, however, doesn't necessarily mean that the same setup can be said for the root user.
>
>![[Images/Pasted image 20250424063903.png]]
>
>I tried writing test copies (which logged messages of whether they were run to a test log in `/tmp`) of various system binaries (eg `cp`, `touch`, `mkdir`, `ls`) into both `/usr/local/bin` and `/usr/local/sbin` in the hope that the `cleanup.pl` script uses one of those binaries which will cause one of my custom binaries to run, but I had no success. This option might not be variable.

>[!code]- Root executes a binary `run-parts` in `/usr/local/sbin`
>When SSH'ing into the machine, the `run-parts` binary is executed by root (`UID=0`) without the full path for that binary being specified.  Following that, the environmental `PATH` variable, which will be used when finding the `run-parts` binary, is specified, and it starts with `/usr/local/sbin`, which we can write to (on the left is output from `pspy64` - which logs running processes):
>
>![[Images/Pasted image 20250425062032.png]]
>
>Because our user has write permissions to that directory (`/usr/local/sbin`), and because `run-parts` path is not defined, we can write a malicious `run-parts` binary to `/usr/local/sbin` which will be executed by root when we SSH into the machine again.
### PATH exploit

>[!code]- Create a malicious `run-parts` within `/usr/local/sbin`
>Having SSH'd into the machine as `jkr`, I create a `run-parts` binary, stored within `/usr/local/sbin`, which enables the SUID bit for the `/bin/bash` binary. This will allow any user to start a bash shell as the owner - which is root.
>
>![[Images/Pasted image 20250504155906.png]] 
>
>I list the current permissions on the `/bin/bash` binary:
>
>![[Images/Pasted image 20250504155942.png]]
>
>Then I SSH into the machine in order to cause root to execute the command which contains the `run-parts` binary. Because the `PATH` is set to look inside `/usr/local/sbin` first, root will execute my malicious `run-parts` binary which enables the SUID bit on `/bin/bash`.
>
>![[Images/Pasted image 20250504160138.png]]
>
>I list the permissions on the `/bin/bash` binary to show that the SUID bit has now been enabled.
>
>![[Images/Pasted image 20250504160221.png]]
>
>From here, I can execute `/bin/bash` with the `-p` flag, which allows me to inherit the privileges of the owner of the file (`root`). You can see that, whilst my `uid` is still `1000` (`jkr`), my `euid` (effective uid) is `0` (`root`):
>
>![[Images/Pasted image 20250504171610.png]]

>[!success]- Obtain root.txt
>![[Images/Pasted image 20250504160423.png]]

<img src="/static/completed-thumbnails/htb-writeup.png" alt="htb writeup" style="max-width: 450px; height: auto; display: block; margin: 0 auto; box-shadow: 0px 0px 14px 0px rgba(0,0,0,0.9);">