192.168.120.122
hutch.offsec

#laps #ldap #ms-mcs-admpwd #pylaps #webdav #scheduled-task 

>[!code]- Open ports
>![Pasted image 20241204055636](/Images/Pasted%20image%2020241204055636.png)

>[!code]- Enumerate LDAP and find credentials (fmcsorley:CrabSharkJellyfish192)
>###### Get the domain name then enumerate all objects
>![Pasted image 20241204055939](/Images/Pasted%20image%2020241204055939.png)
>###### Description of fmcsorley reveals a possible password
>![Pasted image 20241204060016](/Images/Pasted%20image%2020241204060016.png)
>###### Check the credentials
>![Pasted image 20241204055909](/Images/Pasted%20image%2020241204055909.png)

>[!code]- Run BloodHound and find fmcsorley can read the LAPS password
>###### Bloodhound collection
>![Pasted image 20241205045655](/Images/Pasted%20image%2020241205045655.png)
>###### BloodHound
>![Pasted image 20241205045641](/Images/Pasted%20image%2020241205045641.png)

>[!code]- Enumerate LDAP to read the LAPS password
>###### Credentialed search for all objects
>![Pasted image 20241205045838](/Images/Pasted%20image%2020241205045838.png)
>###### LDAP password
>![Pasted image 20241205045806](/Images/Pasted%20image%2020241205045806.png)
>...
>![Pasted image 20241205045750](/Images/Pasted%20image%2020241205045750.png)

>[!code]- PsExec as Admin with the credentials
>###### PsExec
>![Pasted image 20241205045457](/Images/Pasted%20image%2020241205045457.png)

>[!success]- Obtain proof.txt (and local.txt)
>![Pasted image 20241205045530](/Images/Pasted%20image%2020241205045530.png)
>![Pasted image 20241205045542](/Images/Pasted%20image%2020241205045542.png)
#### Alternative to obtaining RCE

>[!code]- Upload a web shell via WebDav
>###### Nmap shows webdav is in use
> ![Pasted image 20241205050805](/Images/Pasted%20image%2020241205050805.png)
> ###### Cadaver to sign into webdav and upload a web shell
> ![Pasted image 20241205050828](/Images/Pasted%20image%2020241205050828.png)
> ###### Access the webshell
> ![Pasted image 20241205050842](/Images/Pasted%20image%2020241205050842.png)

>[!code]- Use the webshell to obtain remote code execution
>###### Generate a reverse shell
>![Pasted image 20241205051504](/Images/Pasted%20image%2020241205051504.png)
>###### Upload the shell to the webdav server
>![Pasted image 20241205051528](/Images/Pasted%20image%2020241205051528.png)
>###### Execute the reverse shell using the web shell
>![Pasted image 20241205051548](/Images/Pasted%20image%2020241205051548.png)
>###### Catch it on the listener
>![Pasted image 20241205051606](/Images/Pasted%20image%2020241205051606.png)

>[!code]- User has SeImpersonatePrivilege - use GodPotato to add a new Administrator user
>###### List privileges
>![Pasted image 20241205052422](/Images/Pasted%20image%2020241205052422.png)
>###### Use GodPotato to add a new user (bubbleman) to Administrators and Remote Desktop users group
>![Pasted image 20241205052508](/Images/Pasted%20image%2020241205052508.png)
>![Pasted image 20241205052520](/Images/Pasted%20image%2020241205052520.png)
>![Pasted image 20241205052535](/Images/Pasted%20image%2020241205052535.png)
>###### EvilWinRm as bubbleman
>![Pasted image 20241205052601](/Images/Pasted%20image%2020241205052601.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241205052629](/Images/Pasted%20image%2020241205052629.png)
#### Alternative to privilege escalation

>[!code]- Execute a scheduled task to run a reverse a shell as Administrator (using the found LAPS admin password)
>###### Taken from Offsec walkthrough
>![Pasted image 20241205052906](/Images/Pasted%20image%2020241205052906.png)

