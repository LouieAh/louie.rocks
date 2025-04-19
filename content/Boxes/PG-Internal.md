#cve-2009-3103 #ms09-050

>[!code]- Find open ports (53, 135, 139, 445, 3389, 5357, 49152-8)
>![Pasted image 20240712043019](Images/Pasted%20image%2020240712043019.png)

>[!code]- Find victim is vulnerable to CVE-2009-3103
>```bash
>nmap -sV --script vuln -p 135,139,445,49152-49157 192.168.171.40 
>```
>
>![Pasted image 20240712050020](Images/Pasted%20image%2020240712050020.png)
>

>[!code]- MSFConsole to obtain root shell
>###### MSFconsole
>![Pasted image 20241203062004](Images/Pasted%20image%2020241203062004.png)
>![Pasted image 20241203062027](Images/Pasted%20image%2020241203062027.png)