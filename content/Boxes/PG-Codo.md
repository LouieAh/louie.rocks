#### Tags:
- All: #codoforum #default-credentials #file-upload #exploit-50978 #su #config-password
- Foothold: #codoforum #default-credentials 
- Access: #file-upload #exploit-50978 
- Privilege Escalation: #su #config-password

>[!code]- Discover open ports (22, 80)
>![Pasted image 20240619060806](Pasted%20image%2020240619060806.png)
>![Pasted image 20240619060828](Pasted%20image%2020240619060828.png)
#### Foothold

>[!code]- Find the admin directory on the webserver
>
>![Pasted image 20240620043841](Pasted%20image%2020240620043841.png)

>[!code]- Login as admin using credentials `admin:admin`
>
>![Pasted image 20240620043935](Pasted%20image%2020240620043935.png)
#### Access

>[!code]- Obtain a reverse shell using a malicious file upload
>Upload a PHP reverse shell via the logo upload within the Global Settings of the admin console:
>![Pasted image 20240620051427](Pasted%20image%2020240620051427.png)
>
>Setup a listener and then execute the PHP reverse shell at `http://$ip/sites/default/assets/img/attachments/php-reverse-shell.php`:
>![Pasted image 20240620051552](Pasted%20image%2020240620051552.png)
#### Privilege Escalation

>[!code]- Find a password within a config file and use it to switch to root user
>Credentials found within a config file (with the help of linpeas):
>
![Pasted image 20240620054019](Pasted%20image%2020240620054019.png)
>___
>
>Switch to root user using that password:
>
>![Pasted image 20240620055151](Pasted%20image%2020240620055151.png)
>

>[!success]- Obtain proof.txt
>![Pasted image 20240620055211](Pasted%20image%2020240620055211.png)

