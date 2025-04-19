#gpp-cached-password #smb #smbclient #kerberoast

>[!code]- Find open ports
>
>![Pasted image 20240830134649](/Images/Pasted%20image%2020240830134649.png)

>[!code]- Access the **Replication** SMB share and identify a cached GPP encrypted password for **svc_tgs** user
>List the shares (anonymous authentication allowed)
>
>![Pasted image 20240830140355](/Images/Pasted%20image%2020240830140355.png)
>
>Download all files within the Replication share:
>
>![Pasted image 20240830140323](/Images/Pasted%20image%2020240830140323.png)
>
>Find the cached GPP password within the downloaded files:
>
>![Pasted image 20240830140113](/Images/Pasted%20image%2020240830140113.png)

>[!code]- Decrypt the password for **svc_tgs** user (GPPstillStandingStrong2k18)
![Pasted image 20240830141054](/Images/Pasted%20image%2020240830141054.png)

>[!success]- Obtain user.txt by accessing **Users** share with **svc_tgs** credentials
>Download all available files (which includes **user.txt** within the user's Desktop):
>
>![Pasted image 20240830154811](/Images/Pasted%20image%2020240830154811.png)
>
>![Pasted image 20240830154902](/Images/Pasted%20image%2020240830154902.png)

>[!code]- Find that the **Administrator** user is running a **service**
>Find that it exists (as expected):
>
>![Pasted image 20240830155343](/Images/Pasted%20image%2020240830155343.png)
>
>Obtain password hash for Administrator by requesting a TGS for the service:
>
>![Pasted image 20240830155442](/Images/Pasted%20image%2020240830155442.png)

>[!code]- Crack the **Administrator** user's password (Ticketmaster1968)
>
>![Pasted image 20240830155526](/Images/Pasted%20image%2020240830155526.png)

>[!code]- Obtain shell as root user using Adminstator's password
>
>![Pasted image 20240830155628](/Images/Pasted%20image%2020240830155628.png)

>[!success]- Obtain root.txt
>
>![Pasted image 20240830155949](/Images/Pasted%20image%2020240830155949.png)
