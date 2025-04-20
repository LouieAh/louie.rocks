#snmp #clamav #sendmail #exploit-4761

>[!code]- Find open ports (22, 25, 80, 139, 199, 445, 60000)
>**All ports:**
>![Pasted image 20240614060228](Pasted%20image%2020240614060228.png)
>
>___
>
>Versions:
>![Pasted image 20240614060514](Pasted%20image%2020240614060514.png)
#### Foothold

>[!code]- Discover that ClamAV software is running by enumerating the SNMP port
>Using snmp-check:
>```bash
>snmp-check 192.168.221.42
>```
>![Pasted image 20240619054458](Pasted%20image%2020240619054458.png)

>[!code]- Find an exploit that relates to the Sendmail and ClamAV software
>The victim is running Sendmail on port 25 and the ClamAV software. There is an exploit that obtains RCE.
>
>![Pasted image 20240619054751](Pasted%20image%2020240619054751.png)
#### Access

>[!code]- Execute the exploit and connect to the bind-shell on port 31337 as root
>Executing the exploit opens a bind shell on the victim:
>![Pasted image 20240619054856](Pasted%20image%2020240619054856.png)
>
>We can then connect to the bind shell:
>![Pasted image 20240619055005](Pasted%20image%2020240619055005.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240619055157](Pasted%20image%2020240619055157.png)