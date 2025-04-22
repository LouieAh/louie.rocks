---
tags:
- manageengine
- service
- default-credentials
- cve-2014-5301
- war
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---

>[!code]- Find open ports (135, 139, 445, 3389, 8080)
>![Pasted image 20240709061742](Pasted%20image%2020240709061742.png)
#### Foothold

>[!code]- Log into the portal on port 8080 using default credentials
>As per [this webpage](https://help.servicedeskplus.com/introduction/start-servicedeskplus-server.html), the default credentials are **administrator**:**administrator**
>>[!code]- Screenshot
>>![Pasted image 20240710051243](Pasted%20image%2020240710051243.png)
#### Access

>[!code]- Find an authenticated file upload exploit that obtains a reverse shell
>Exploit [here](https://github.com/PeterSufliarsky/exploits/blob/master/CVE-2014-5301.py).
>- As explained in the exploit's comments, first create a **war** payload with msfvenom
>- Setup a listener on attacking
>- Run the exploit
>Create the war payload:
>
>![Pasted image 20240710052015](Pasted%20image%2020240710052015.png)
>
>Run the exploit:
>
>![Pasted image 20240710052116](Pasted%20image%2020240710052116.png)
>
>Catch the shell:
>
>![Pasted image 20240710052152](Pasted%20image%2020240710052152.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240710052253](Pasted%20image%2020240710052253.png)
