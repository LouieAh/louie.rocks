#fuguhub #default-credentials #lsp #lua #barracuda

>[!code]- Find open port (22, 80, 8082, 9999)
>![Pasted image 20240710053300](Images/Pasted%20image%2020240710053300.png)
#### Foothold

>[!code]- Find the webpage on port 8082 which lets us setup the admin account
>The website doesn't appear to have been configured fully yet; many pages require us to first setup the administrator account.
>
>![Pasted image 20240710053710](Images/Pasted%20image%2020240710053710.png)
>
>Set admin credentials as **bubbleman**:**bubbleman**
>
>![Pasted image 20240710053842](Images/Pasted%20image%2020240710053842.png)
>
>Login as admin. This is accessed either via **/private/manage/** or clicking **CMS Admin**.
>
>![Pasted image 20240710054126](Images/Pasted%20image%2020240710054126.png)
>![Pasted image 20240710054209](Images/Pasted%20image%2020240710054209.png)
#### Access

>[!code]- Find an exploit which obtains a reverse shell
>[This exploit](https://github.com/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697) shows how you can edit a page by adding in malicious Lua Server Page (LSP) tags, which obtain a reverse shell.
>
>Edit the Home page by logging into the CMS Admin Page then visiting the Home page and clicking the file icon, as described by the 'Edit this page as follows' guide on the far right.
>
>![Pasted image 20240710061314](Images/Pasted%20image%2020240710061314.png)
>
>Visit [revshells.com](https://www.revshells.com/) to obtain a suitable Lua reverse shell (Lua #1 didn't work):
>
>![Pasted image 20240710061451](Images/Pasted%20image%2020240710061451.png)
>
>Setup a listener on attacking then paste the Lua reverse shell code into the page editor window.
>
>![Pasted image 20240710061215](Images/Pasted%20image%2020240710061215.png)
>
>Receive the reverse shell.
>
>![Pasted image 20240710061601](Images/Pasted%20image%2020240710061601.png)

>[!code]- Obtain a more stable shell
>The current shell doesn't let us wonder outside /var/www/html/
>
>![Pasted image 20240711055807](Images/Pasted%20image%2020240711055807.png)
>
>So we can try to initiate a (hopefully better) bash shell.
>
>![Pasted image 20240711060100](Images/Pasted%20image%2020240711060100.png)
>
It works!
>
>![Pasted image 20240711060118](Images/Pasted%20image%2020240711060118.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240711060232](Images/Pasted%20image%2020240711060232.png)

>[!tip]- Alternative
>See [this guide](https://github.com/ojan2021/Fuguhub-8.1-RCE/blob/main/Fuguhub-8-1-RCE-Report.pdf) to obtain RCE through a file upload vulnerability.



