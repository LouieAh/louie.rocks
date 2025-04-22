---
tags:
- hp-power-manager
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---

>[!code]- Open ports
>![Pasted image 20241129045008](Images/Pasted%20image%2020241129045008.png)
>![Pasted image 20241129045032](Images/Pasted%20image%2020241129045032.png)

>[!code]- Access the admin panel using default credentials (admin:admin)
>###### Login page
>![Pasted image 20241129051525](Images/Pasted%20image%2020241129051525.png)
>###### Admin panel
>![Pasted image 20241129051549](Images/Pasted%20image%2020241129051549.png)

>[!code]- Use an exploit for the service version (4.2) to obtain a root shell
>###### Find the version in the Logs page
>![Pasted image 20241129052705](Images/Pasted%20image%2020241129052705.png)
>###### Create a payload to edit [this exploit](https://github.com/Muhammd/HP-Power-Manager/blob/master/hpm_exploit.py)and paste the payload in
>![Pasted image 20241129052819](Images/Pasted%20image%2020241129052819.png)
>###### Execute the exploit
>![Pasted image 20241129052900](Images/Pasted%20image%2020241129052900.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241129052928](Images/Pasted%20image%2020241129052928.png)


