#atlassian #confluence #cve-2022-26134 #cron #bash-p

>[!code]- Find open ports (22, 8090, 8091)
>
>![Pasted image 20240807044250](Pasted%20image%2020240807044250.png)
#### Foothold

>[!code]- Find port 8090 is running Atlassian Confluence v7.13.6
>
>![Pasted image 20240807055510](Pasted%20image%2020240807055510.png)
#### Access

>[!code]- Find an exploit for v7.13.6 and obtain RCE
>First I found this [Github repo](https://github.com/Habib0x0/CVE-2022-26134), which allowed me to execute some commands. However, I would have trouble executing commands with spaces...
>
>![Pasted image 20240807044848](Pasted%20image%2020240807044848.png)
>
>...but found I could get round that by URL encoding the payloads.
>
>![Pasted image 20240807044829](Pasted%20image%2020240807044829.png)

>[!code]- Find a better exploit which obtains a reverse shell
>I then found this [Github repo](https://github.com/jbaines-r7/through_the_wire) which allowed a reverse shell to be obtained.
>
>![Pasted image 20240807052809](Pasted%20image%2020240807052809.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20240807053120](Pasted%20image%2020240807053120.png)
#### Privilege Escalation

>[!code]- Find a cron job running a script we can edit
>Linpeas identified a script in the **/opt** directory, which the user I controlled owned.
>
>![Pasted image 20240807054252](Pasted%20image%2020240807054252.png)
>
>![Pasted image 20240807054600](Pasted%20image%2020240807054600.png)
>
>Pspy showed a cron job running which executed this script.
>
>![Pasted image 20240807054518](Pasted%20image%2020240807054518.png)

>[!code]- Edit the script to obtain a shell with root privileges
>Editing the script:
>
>![Pasted image 20240807060140](Pasted%20image%2020240807060140.png)
>
>This caused the SUID bit to be set on **/bin/bash**
>
>![Pasted image 20240807054817](Pasted%20image%2020240807054817.png)
>
>Ran **/bin/bash** as root
>
>![Pasted image 20240807054835](Pasted%20image%2020240807054835.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20240807054849](Pasted%20image%2020240807054849.png)

