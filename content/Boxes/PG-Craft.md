---
tags:
- odt
- macros
- seimpersonateprivilege
- printspoofer
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---
>[!code]- Open ports (80)
>![Pasted image 20241121065140](Images/Pasted%20image%2020241121065140.png)
#### Thecybergeek shell

>[!code]- Upload an malicious .ODT file to obtain a reverse shell
>###### On the homepage there is a file upload feature which only accepts ODT files
>![Pasted image 20241122070051](Images/Pasted%20image%2020241122070051.png)
>###### Use [this tool](https://github.com/0bfxgh0st/MMG-LO) to create an ODT file containing a reverse shell
>![Pasted image 20241122070126](Images/Pasted%20image%2020241122070126.png)
>###### Upload the file
>![Pasted image 20241122052355](Images/Pasted%20image%2020241122052355.png)
>###### Catch the reverse shell
>![Pasted image 20241122052419](Images/Pasted%20image%2020241122052419.png)

>[!success]- Obtain local.txt
>![Pasted image 20241122052619](Images/Pasted%20image%2020241122052619.png)
#### Apache shell

>[!code]- We have write access to the Apache web server root which is run by apache service account
>###### Write access
>![Pasted image 20241122061844](Images/Pasted%20image%2020241122061844.png)
>###### Apache service account exists
>![Pasted image 20241122061948](Images/Pasted%20image%2020241122061948.png)
>###### Apache account running the web server
>![Pasted image 20241122062105](Images/Pasted%20image%2020241122062105.png)

>[!code]- Obtain a reverse shell as the Apache user
>###### Create a malicious rev.php file
>![Pasted image 20241122062142](Images/Pasted%20image%2020241122062142.png)
>###### Copy rev.php to victim then navigate to rev.php on HTTP server
>![Pasted image 20241122062216](Images/Pasted%20image%2020241122062216.png)
>###### Catch reverse shell
>![Pasted image 20241122062238](Images/Pasted%20image%2020241122062238.png)
#### root shell

>[!code]- Use Apache's SeImpersonatePrivilege to obtain root shell
>###### List privileges
>![Pasted image 20241122062356](Images/Pasted%20image%2020241122062356.png)
>###### Execute PrintSpoofer
>![Pasted image 20241122064228](Images/Pasted%20image%2020241122064228.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241122070307](Images/Pasted%20image%2020241122070307.png)



