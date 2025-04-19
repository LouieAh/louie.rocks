#rsync #fail2ban #actiond

>[!code]- Find open ports (22, 873)
>Forgot to get a screenshot.
#### Foothold

>[!code]- Find Rsync running on port 873
>
>![Pasted image 20240806043853](Images/Pasted%20image%2020240806043853.png)

>[!code]- Interact with Rsync by enumerating files and uploading **authorized_keys**
>We can list what files are available:
>
>![Pasted image 20240806044324](Images/Pasted%20image%2020240806044324.png)
>
>![Pasted image 20240806044721](Images/Pasted%20image%2020240806044721.png)
>
>We see that we have access to files in the home directory for **fox**. We can then attempt to upload a malicious, like **authorized_keys**, which contains my public key.
>
>![Pasted image 20240806045310](Images/Pasted%20image%2020240806045310.png)
#### Access

>[!code]- SSH into victim
>Now that my public key is in the tampered with **authorized_keys** file in the home directory for **fox**, I can SSH using my private key.
>
>![Pasted image 20240806045353](Images/Pasted%20image%2020240806045353.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20240806061408](Images/Pasted%20image%2020240806061408.png)
#### Privilege Escalation

>[!code]- Find a cron job running for Fail2Ban
>
>![Pasted image 20240806045931](Images/Pasted%20image%2020240806045931.png)
>
>That binary is being run as root.
>
>![Pasted image 20240806050001](Images/Pasted%20image%2020240806050001.png)

>[!code]- Find we are in the fail2ban group and can edit **action.d** directory files
>
>![Pasted image 20240806050737](Images/Pasted%20image%2020240806050737.png)
>
>![Pasted image 20240806051328](Images/Pasted%20image%2020240806051328.png)
>
>[This guide](https://juggernaut-sec.com/fail2ban-lpe/#Hunting_for_Users_in_the_fail2ban_Group) gives the steps required to elevate our privileges.
>

>[!code]- Exploit our permissions to obtain root privileges
>As per this guide, first edit the **/action.d/iptables-multiport.conf** file so that the **/bin/bash** binary gets SUID bit added when we trigger a ban.
>
>![Pasted image 20240806054507](Images/Pasted%20image%2020240806054507.png)
>
>Then ban will apply to SSH after 2 failed attempts.
>
>![Pasted image 20240806054016](Images/Pasted%20image%2020240806054016.png)
>
>![Pasted image 20240806061925](Images/Pasted%20image%2020240806061925.png)
>
>Trigger a ban.
>
>![Pasted image 20240806060721](Images/Pasted%20image%2020240806060721.png)
>
>Watch as **/bin/bash** gets SUID bit enabled as a result.
>
>![Pasted image 20240806060734](Images/Pasted%20image%2020240806060734.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20240806060834](Images/Pasted%20image%2020240806060834.png)