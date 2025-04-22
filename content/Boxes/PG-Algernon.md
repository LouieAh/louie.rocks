---
tags:
- smartmail
- port9998
- distinct32
- exploit-49216
- cve-2019-7214
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---
## Enumerate

> [!NOTE] Nmap -sS -p-
> ![Pasted image 20240609135540](Pasted%20image%2020240609135540.png)

>[!question]- 21 - FTP
>Anonymous access allowed
>![Pasted image 20240609062027](Pasted%20image%2020240609062027.png)
>
>Only the Logs folder contains files
>
>In the Logs folder, only _2020.05.23-administrative.log_ contains either *admin, user, pass or login* 
>
>The _2020.05.23-administrative.log_ suggests theres an 'admin' user for the webmail
>![Pasted image 20240609062418](Pasted%20image%2020240609062418.png)

>[!failure] 80 - HTTP
##### Directory Enumeration

>[!code] Gobuster
>Common.txt:
>- aspnet_client
>
>Directory list medium:
>![Pasted image 20240609063141](Pasted%20image%2020240609063141.png)

- http://$ip/aspnet_client
	- Response:
		- ![Pasted image 20240609061649](Pasted%20image%2020240609061649.png)
### 135/139/445 - SMB

- Listing shares with no password failed
### 9998 - "distinct32"

- http://$ip:9998 forwards to _http://192.168.203.65:9998/interface/root#/login_
	- SmarterMail
	- ![Pasted image 20240609070135](Pasted%20image%2020240609070135.png)
	- Source code shows build number as 6919
		- ![Pasted image 20240609080654](Pasted%20image%2020240609080654.png)
	- **Searchsploit has an [RCE exploit](https://www.exploit-db.com/exploits/49216) for builds before 6985**
		- Running the exploit results in not standard out (seemingly does nothing)
		- <mark style="background: #FFB86CA6;">(After hints) I edited the exploit to catch the reverse shell on local port 80 (so that it gets passed the firewall, and sent the connection request to port 17001 on the victim (not found in my initial Nmap scan as I didn't scan all ports)).</mark>

## Foothold

- After executing the exploit we gain a shell as _nt authority\system_:
	- ![Pasted image 20240609140408](Pasted%20image%2020240609140408.png)

## Proof

![Pasted image 20240609142759](Pasted%20image%2020240609142759.png)
