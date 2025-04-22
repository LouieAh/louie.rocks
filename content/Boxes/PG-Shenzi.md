---
tags:
- always-install-elevated
- wordpress
- msi
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---

>[!code]- Find open ports (21, 80, 135, 139, 443, 445, 3306)
>
>![Pasted image 20240917045903](Images/Pasted%20image%2020240917045903.png)
>![Pasted image 20240917045922](Images/Pasted%20image%2020240917045922.png)
#### Port 21

>[!code]- FileZilla Server version 0.9.41 beta
>
>![Pasted image 20240917050542](Images/Pasted%20image%2020240917050542.png)
#### Port 80

>[!code]- Landing page
>
>![Pasted image 20240917050110](Images/Pasted%20image%2020240917050110.png)
>

>[!code]- Find evidence of a WordPress site
###### Shenzi WordPress Site

>[!code]- Find a WordPress site (/shenzi)
>###### Feroxbuster (no significant results)
>![Pasted image 20240917053542](Images/Pasted%20image%2020240917053542.png)
>###### Try name of the box
>![Pasted image 20240917053617](Images/Pasted%20image%2020240917053617.png)

>[!code]- Login to /admin with credentials found on SMB share
>###### Admin console
>![Pasted image 20240917054211](Images/Pasted%20image%2020240917054211.png)
###### shenzi

>[!code]- Exploit 404 php code to obtain a shell as shenzi
>###### Edit the source code
>![Pasted image 20240917055933](Images/Pasted%20image%2020240917055933.png)
>###### Copy nc.exe to victim via cmd parameter then use cmd parameter to export cmd.exe via nc.exe
>![Pasted image 20240917060009](Images/Pasted%20image%2020240917060009.png)
>###### Catch reverse shell
>![Pasted image 20240917055901](Images/Pasted%20image%2020240917055901.png)
###### root

>[!code]- Find .msi files execute as root
>###### Check registry
>![Pasted image 20240918044037](Images/Pasted%20image%2020240918044037.png)

>[!code]- Execute malicious .msi to obtain root shell
>###### Generate the malicious .msi file
>![Pasted image 20240918044121](Images/Pasted%20image%2020240918044121.png)
>###### Execute it
>![Pasted image 20240918044144](Images/Pasted%20image%2020240918044144.png)
>###### Catch the reverse shell
>![Pasted image 20240918044211](Images/Pasted%20image%2020240918044211.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20240917062151](Images/Pasted%20image%2020240917062151.png)
#### Port 445

>[!code]- Find Shenzi share
>###### Anonymous bind
>![Pasted image 20240917050703](Images/Pasted%20image%2020240917050703.png)

>[!code]- Download all material
>###### List material
>![Pasted image 20240917050854](Images/Pasted%20image%2020240917050854.png)
>###### Recursively download

>[!code]- Find evidence of a WordPress site
>###### From the downloaded material find login credentials
>![Pasted image 20240917053412](Images/Pasted%20image%2020240917053412.png)