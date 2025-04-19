#asreproast #generateADusernames #autologon #registry #DCsync

>[!code]- Find open ports
>
>![Pasted image 20240829153257](Images/Pasted%20image%2020240829153257.png)

>[!code]- Find domain name (egotistical-bank.local)
>
>![Pasted image 20240829154303](Images/Pasted%20image%2020240829154303.png)

>[!code]- On port 80 find possible AD usernames (including **Fergus Smith**)
>On the website, in 'Our Team' page.
>
>![Pasted image 20240829155556](Images/Pasted%20image%2020240829155556.png)

>[!code]- Use those names to generate a list of possible usernames (including **FSmith**)
>I used [this GitHub repo](https://github.com/w0Tx/generate-ad-username)
>
>![Pasted image 20240829162015](Images/Pasted%20image%2020240829162015.png)

>[!code]- AS-REP Roast the possible usernames and find **fsmith** user exists
>
>![Pasted image 20240829161945](Images/Pasted%20image%2020240829161945.png)

>[!code]- Crack password hash for **fsmith** user (Thestrokes23)
>
>![Pasted image 20240829162236](Images/Pasted%20image%2020240829162236.png)

>[!code]- Obtain a shell as **fsmith**
>
>![Pasted image 20240829162411](Images/Pasted%20image%2020240829162411.png)

>[!success]- Obtain user.txt
>
>![Pasted image 20240829163826](Images/Pasted%20image%2020240829163826.png)
#### Lateral Movement

>[!code]- Find autologon credentials for **'svc_loanmanager'** (Moneymakestheworldgoround!)
>
>![Pasted image 20240830060444](Images/Pasted%20image%2020240830060444.png)

>[!code]- Link **'svc_loanmanager'** with the **svc_loanmgr** user
>There is no **svc_loanmanager** user, but there is a **svc_loanmgr** user... Worth a try.
>
![Pasted image 20240830101318](Images/Pasted%20image%2020240830101318.png)

>[!code]- Obtain a shell as **svc_loanmgr**
>
>![Pasted image 20240830101600](Images/Pasted%20image%2020240830101600.png)
#### Privilege Escalation

>[!code]- Run SharpHound and find that **svc_loanmgr** can perform a DCSync attack
>
>![Pasted image 20240830104251](Images/Pasted%20image%2020240830104251.png)

>[!code]- Obtain Administrator NTLM hash via a DCSync attack (823452073d75b9d1cf70ebdf86c7f98e)
>
>![Pasted image 20240830115019](Images/Pasted%20image%2020240830115019.png)

>[!code]- Obtain shell as Administrator
>
>![Pasted image 20240830115146](Images/Pasted%20image%2020240830115146.png)

>[!success]- Obtain root.txt
>
>![Pasted image 20240830115220](Images/Pasted%20image%2020240830115220.png)



