---
tags:
- redis
- ld-library-path
- cron
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---

>[!code]- Find open ports (21, 22, 80, 6379)
>
>![Pasted image 20240930042751](Images/Pasted%20image%2020240930042751.png)
#### Port 21

>[!code]- Anoynmous authentication enabled
>###### List contents
>![Pasted image 20240927052639](Images/Pasted%20image%2020240927052639.png)
>###### Pub directory empty
>![Pasted image 20240930043251](Images/Pasted%20image%2020240930043251.png)

>[!code]- Can upload files
>###### Upload
>![Pasted image 20240930043445](Images/Pasted%20image%2020240930043445.png)
#### Port 6379

>[!code]- Redis version is vulnerable to RCE exploit
>###### Version 5.0.9
>![Pasted image 20240930043616](Images/Pasted%20image%2020240930043616.png)
###### Pablo

>[!code]- Upload malicious shared library to [obtain RCE](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis)
>###### Upload via FTP server
>![Pasted image 20240930045448](Images/Pasted%20image%2020240930045448.png)
>###### Load malicious module (assume upload directory is /var/ftp/)
>![Pasted image 20240930045824](Images/Pasted%20image%2020240930045824.png)
>###### Check module loaded
>![Pasted image 20240930045922](Images/Pasted%20image%2020240930045922.png)
>###### Execute reverse shell
>![Pasted image 20240930050800](Images/Pasted%20image%2020240930050800.png)
>###### Catch on listener
>![Pasted image 20240930050824](Images/Pasted%20image%2020240930050824.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20240930051021](Images/Pasted%20image%2020240930051021.png)

###### root

>[!code]- Find cron job running /usr/bin/log-sweeper and LD_LIBRARY_PATH
>###### Crontab
>![Pasted image 20240930055340](Images/Pasted%20image%2020240930055340.png)
>###### log-sweeper relies on utils.so
>![Pasted image 20241001042847](Images/Pasted%20image%2020241001042847.png)
>###### But it can't find it
>It is looking within /usr/local/lib/dev/ first
>![Pasted image 20240930055426](Images/Pasted%20image%2020240930055426.png)
>###### We own /usr/local/lib/dev/
>![Pasted image 20241001043034](Images/Pasted%20image%2020241001043034.png)

>[!code]- Create a malicious shared library file
>###### Create a c file which changes SUID bit on /bin/bash
>![Pasted image 20240930060742](Images/Pasted%20image%2020240930060742.png)
>###### Compile it on the victim
>![Pasted image 20240930060805](Images/Pasted%20image%2020240930060805.png)
>###### Move it to /usr/local/lib/dev/ and rename to utils.so and make it executable
>![Pasted image 20240930060818](Images/Pasted%20image%2020240930060818.png)
>![Pasted image 20240930060830](Images/Pasted%20image%2020240930060830.png)

>[!code]- Wait for cron to job to run and execute the malicious shared library file
>###### /Bin/bash now executable as root
>![Pasted image 20240930060707](Images/Pasted%20image%2020240930060707.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20241001043328](Images/Pasted%20image%2020241001043328.png)

