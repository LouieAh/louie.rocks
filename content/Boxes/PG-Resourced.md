---
tags:
- ntds-dit
- genericall-computer
- constrained-delegation
- resourced-based-constrained-delegation
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---

>[!code]- Open ports (53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 9389)
>###### Full list
>![Pasted image 20241104164105](Images/Pasted%20image%2020241104164105.png)
>###### With scripts and versions
>![Pasted image 20241104164130](Images/Pasted%20image%2020241104164130.png)

>[!code]- Get the domain name (resourced.local)
>###### Ldapsearch
>![Pasted image 20241104164312](Images/Pasted%20image%2020241104164312.png)
###### SMB share

>[!code]- Find credentials via SMB null authentication (v.ventz:HotelCalifornia194!)
>###### enum4linux
>![Pasted image 20241104165004](Images/Pasted%20image%2020241104165004.png)
>###### Check credentials
>![Pasted image 20241104165404](Images/Pasted%20image%2020241104165404.png)

>[!code]- Find a ntds.dit and SYSTEM file on a SMB share (using above credentials)
>###### List shares
>![Pasted image 20241104173758](Images/Pasted%20image%2020241104173758.png)
>###### Contents of the Password Audit share
>![Pasted image 20241104174030](Images/Pasted%20image%2020241104174030.png)
###### ntds.dit

>[!code]- Enumerate which user(s) are in the Remote Desktop/Management Users groups (l.livingstone)
>###### List all groups
>![Pasted image 20241105042655](Images/Pasted%20image%2020241105042655.png)
>###### Members of the Remote Desktop/Management Users groups
>![Pasted image 20241105042814](Images/Pasted%20image%2020241105042814.png)

>[!code]- Identify NTLM hash for l.livingstone (19a3a7550ce8c505c2d46b5e39d6f808)
>###### Impacket secrets dump
>![Pasted image 20241105044018](Images/Pasted%20image%2020241105044018.png)
###### Evil-winrm (l.livingstone)

>[!code]- Connect via winrm (port 5985)
>###### evil-winrm
>![Pasted image 20241105044036](Images/Pasted%20image%2020241105044036.png)

>[!success]- Obtain local.txt
>![Pasted image 20241105044107](Images/Pasted%20image%2020241105044107.png)

>[!code]- L.Livingstone has GenericAll permissions on the DC
>###### PowerView
>![Pasted image 20241105054823](Images/Pasted%20image%2020241105054823.png)

>[!exploit]- Kerberos Resource-based Constrained Delegation exploit
>###### Add a computer account
>![Pasted image 20241107044728](Images/Pasted%20image%2020241107044728.png)
>###### Check that the computer object was created
>![Pasted image 20241107044910](Images/Pasted%20image%2020241107044910.png)
>###### Set the delegation attributed for the computer account
>![Pasted image 20241107045015](Images/Pasted%20image%2020241107045015.png)
>###### Check that delegation was successful
>![Pasted image 20241107045615](Images/Pasted%20image%2020241107045615.png)
>###### Get ticket for Administrator
>![Pasted image 20241107050712](Images/Pasted%20image%2020241107050712.png)
>Ticket saved to current folder
>![Pasted image 20241107050840](Images/Pasted%20image%2020241107050840.png)
>###### Set environmental variable
>![Pasted image 20241107051101](Images/Pasted%20image%2020241107051101.png)
>###### Add domain name to hosts file
>![Pasted image 20241107051132](Images/Pasted%20image%2020241107051132.png)
>###### Psexec as Administrator (using the cached Kerberos ticket)
>![Pasted image 20241107051249](Images/Pasted%20image%2020241107051249.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241107051343](Images/Pasted%20image%2020241107051343.png)

