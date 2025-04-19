- All: #grav-cms #grav #exploit-49973 #suid #php 
- Foothold: #grav-cms #grav #exploit-49973 
- Priv Esc: #suid #php
#### Enumeration

>[!code]- Rustscan - ports 22, 80
>Simple:
>- Port 22
>- Port 80
>
>![Pasted image 20240612052807](Images/Pasted%20image%2020240612052807.png)
>
>With additions:
>- Port 22 - OpenSSH 8.2p1 Ubuntu
>- Port 80 - Apache 2.4.41 Ubuntu
>
>![Pasted image 20240612052835](Images/Pasted%20image%2020240612052835.png)

>[!code]- Navigate to port 80 (Grav CMS) and discover `/grav-admin/`
>/
>
>![Pasted image 20240612053158](Images/Pasted%20image%2020240612053158.png)
>
>/grav/admin/
>
>![Pasted image 20240612053324](Images/Pasted%20image%2020240612053324.png)

>[!code]- Discover `/grav-admin/admin` directory
>Directory enumeration with Gobuster (common.txt and only 200 codes):
>- /admin
>- /forgot_password
>- /home (redirects to landing page)
>- /login
>- /robots.txt
>
>>[!code]- Full output
>>![Pasted image 20240612054038](Images/Pasted%20image%2020240612054038.png)
>___
>
>>[!code]- /grav-admin/admin
>>![Pasted image 20240612054129](Images/Pasted%20image%2020240612054129.png)
>
>>[!code]- /grav-admin/forgot_password
>>![Pasted image 20240612054602](Images/Pasted%20image%2020240612054602.png)
>
>>[!code]- /grav-admin/login
>>![Pasted image 20240612054220](Images/Pasted%20image%2020240612054220.png)
>>
>>[!code]- /grav-admin/robots.txt
>>![Pasted image 20240612053924](Images/Pasted%20image%2020240612053924.png)

>[!exploit]- Foothold - Obtain a reverse shell whilst unauthenticated
>Exploit [here](https://www.exploit-db.com/exploits/49973).
>>[!code]- 49973.py
>>- Change the `target` variable and the base64 payload
>>
>>![Pasted image 20240613052221](Images/Pasted%20image%2020240613052221.png)
>
>Catch the reverse shell on Kali.

>[!exploit]- Priv Esc - Abuse SUID bit on the PHP binary
>List the SUID-marked binaries and see that the PHP7.4 binary is included.
>>[!code]- SUID binaries
>>![Pasted image 20240613052512](Images/Pasted%20image%2020240613052512.png)
>
>[GTFOBins](https://gtfobins.github.io/gtfobins/php/) shows how to exploit this:
>>[!code]- Screenshot from GTFOBins
>>![Pasted image 20240613052623](Images/Pasted%20image%2020240613052623.png)
>
>Exploiting this on the victim machine to obtain a shell as root:
>- I changed the shell binary to execute from `/bin/sh` to `/bin/bash`
>
>![Pasted image 20240613052818](Images/Pasted%20image%2020240613052818.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240613052805](Images/Pasted%20image%2020240613052805.png)
