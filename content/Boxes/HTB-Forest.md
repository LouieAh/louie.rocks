---
tags:
- spn
- ad
- dcsync
- kerberoast
- asreproast
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---

>[!code]- Find open ports
>![Pasted image 20240828170119](Images/Pasted%20image%2020240828170119.png)

>[!code]- Discover the domain name (htb.local)
>Taken from the above Nmap scan:
>
>![Pasted image 20240829110139](Images/Pasted%20image%2020240829110139.png)

>[!code]- Use rpcclient to list all domain users
>It appears anonymous authentication is allowed, and rpcclient enumeration is allowed (via port 445).
>
>`-N` no password
>`-U` username
>`-c` command to execute (rather than entering the rpcclient terminal)
> ```powershell
rpcclient -N -U "" 10.10.10.161 -c enumdomusers
>```
>
>![Pasted image 20240829090857](Images/Pasted%20image%2020240829090857.png)
>
>Extract the usernames and paste into a list:
>
>![Pasted image 20240829104946](Images/Pasted%20image%2020240829104946.png)
#### Foothold

>[!code]- Obtain password hash for **svc-alfresco** account
>Using the list of users obtained from the rpcclient enumeration, see whether any have Kerberos Pre-authentication disabled, and if so if, whether we can obtain that accounts password hash.
>
>![Pasted image 20240829110841](Images/Pasted%20image%2020240829110841.png)

>[!code]- Crack the password hash for the **svc-alfresco** account
>Find which hash type to use (18200):
>
>![Pasted image 20240829111438](Images/Pasted%20image%2020240829111438.png)
>
>Crack the hash using rockyou (s3rvice):
>
>![Pasted image 20240829111610](Images/Pasted%20image%2020240829111610.png)
#### Access

>[!code]- Obtain a shell as svc-alfresco using WinRM protocol (port 5985)
>The Nmap scan showed port 5985 was open. If the svc-alfresco account has admin privileges on the victim machine, we can use the WinRM protocol to obtain a remote session.
>
>![Pasted image 20240829112204](Images/Pasted%20image%2020240829112204.png)

>[!success]- Obtain user.txt
>![Pasted image 20240829134729](Images/Pasted%20image%2020240829134729.png)
#### Privilege Escalation

>[!code]- Find a possible compromise chain that leads to root (set SPN for **su** user then perform a DCSync attack)
>
>![Pasted image 20240829145712](Images/Pasted%20image%2020240829145712.png)
>
>svc-alfresco owns su:
>
>![Pasted image 20240829140555](Images/Pasted%20image%2020240829140555.png)

>[!code]- Set an SPN for su user
>
>![Pasted image 20240829141523](Images/Pasted%20image%2020240829141523.png)

>[!code]- Kerberoast su user (obtain su hash)
>
>![Pasted image 20240829142457](Images/Pasted%20image%2020240829142457.png)

>[!code]- Crack the password for the su account (abc123!)
>Find Hashcat mode:
>
>![Pasted image 20240829142632](Images/Pasted%20image%2020240829142632.png)
>
>Crack:
>
>![Pasted image 20240829142746](Images/Pasted%20image%2020240829142746.png)

>[!code]- Obtain a session as **su**
>
>![Pasted image 20240829142950](Images/Pasted%20image%2020240829142950.png)
#### Privilege Escalation

>[!code]- Find **su** has suitable privileges on htb.local to perform a DCSync attack
>
>![Pasted image 20240829143552](Images/Pasted%20image%2020240829143552.png)

>[!code]- Perform a DCSync attack and obtain Administrator hash
>
>![Pasted image 20240829144118](Images/Pasted%20image%2020240829144118.png)

>[!code]- Obtain shell as Administrator
>
>![Pasted image 20240829145430](Images/Pasted%20image%2020240829145430.png)

>[!success]- Obtain root.txt
>
>![Pasted image 20240829145521](Images/Pasted%20image%2020240829145521.png)