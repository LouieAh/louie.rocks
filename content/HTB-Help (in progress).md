---
tags:
created: 2025-04-19
image: /static/note-thumbnail-htb-help.png
draft: true
description: Help is an Easy Linux box which has a GraphQL endpoint which can be enumerated get a set of credentials for a HelpDesk software. The software is vulnerable to blind SQL injection which can be exploited to get a password for SSH Login. Alternatively an unauthenticated arbitrary file upload can be exploited to get RCE. Then the kernel is found to be vulnerable and can be exploited to get a root shell.
---

>[!code]- Open ports (22, 80, 3000)

#### Port 80 (HTTP)

>[!code]- Add `help.htb` to `/etc/hosts`
>###### The IP address redirects to `help.htb`
>![Pasted image 20250419061657](Images/Pasted%20image%2020250419061657.png)
>###### Add `help.htb` to `/etc/hosts`
>![Pasted image 20250419061835](Images/Pasted%20image%2020250419061835.png)

>[!code]- Web server is running Apache 2.4.18
>###### Landing page shows a default Apache page
>![Pasted image 20250419061915](Images/Pasted%20image%2020250419061915.png)
>###### Not found page shows Apache version
>![Pasted image 20250419062113](Images/Pasted%20image%2020250419062113.png)

>[!code]- Find the page `/support`
>###### FFUF bruteforce
>![Pasted image 20250419062212](Images/Pasted%20image%2020250419062212.png)
>###### `/support` page
>![Pasted image 20250419062232](Images/Pasted%20image%2020250419062232.png)





