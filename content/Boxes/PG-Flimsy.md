---
tags:
- apisix
- cve-2022-24112
- exploit-50829
- bash-p
- apt-get
- apt-conf-d
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---

>[!code]- Find open ports (22, 80, 3306, 43500)
>![Pasted image 20240702061310](Pasted%20image%2020240702061310.png)
#### Foothold and Access

>[!code]- Find and use an exploit for port 43500 APISIX/2.8
>The Apache server running on port 43500 us vulnerable to CVE-2022-24112 which allows a remote code execution [exploit](https://www.exploit-db.com/exploits/50829).
>
>![Pasted image 20240704043728](Pasted%20image%2020240704043728.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20240704044041](Pasted%20image%2020240704044041.png)
#### Privilege Escalation

>[!code]- Find a vulnerable cron job associated with apt-get
>Every minute the command **apt-get** runs as root.
>
>![Pasted image 20240704052423](Pasted%20image%2020240704052423.png)
>
>The directory **/etc/apt/apt.conf.d/** contains scripts that should be run before and after the apt-get command is executed. Linpeas shows this directory is writeable by us, so we can add a malicious script.
>
>![Pasted image 20240704050205](Pasted%20image%2020240704050205.png)
> 
> [This guide](https://systemweakness.com/code-execution-with-apt-update-in-crontab-privesc-in-linux-e6d6ffa8d076) explains how the number at the start of each scripts filename dictates when its executed. If we create a script starting **00**, it should be executed first when **apt-get** is ran.

>[!code]- Add a malicious script to /etc/apt/apt.conf.d/ and obtain root privileges
>[This guide](https://systemweakness.com/code-execution-with-apt-update-in-crontab-privesc-in-linux-e6d6ffa8d076) shows the syntax to use in the script. It will enable the SUID bit to the **/bin/bash** executable, to allow us to run it with root privileges.
>
>![Pasted image 20240704054307](Pasted%20image%2020240704054307.png)
>
>After the cron job runs, our malicious script is executed, and the permissions on **/bin/bash** change: 
>>[!code]- Permissions before
>>![Pasted image 20240704052851](Pasted%20image%2020240704052851.png)
>
>>[!code]- Permissions after
>>![Pasted image 20240704053446](Pasted%20image%2020240704053446.png)
>
>We can then run **/bin/bash/** as root:
>
![Pasted image 20240704053519](Pasted%20image%2020240704053519.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240704053545](Pasted%20image%2020240704053545.png)
