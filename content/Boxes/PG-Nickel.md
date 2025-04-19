#api #john2pdf #pdf-password #pdf-decrypt #ssh-port-forward #psexec #scp

>[!code]- Find open ports (21, 22, 135, 139, 445, 3389, 5040, 8089, 33333)
>
>/list-current-deployments
#### Port 8089

>[!code]- Landing page
>![Pasted image 20241001044955](Images/Pasted%20image%2020241001044955.png)

>[!code]- Source code shows requests made to external machine
>###### Source code
>![Pasted image 20241001052358](Images/Pasted%20image%2020241001052358.png)

>[!code]- Discover SSH creds by listing running procs
>###### Make GET/POST request
>![Pasted image 20241001052453](Images/Pasted%20image%2020241001052453.png)
>###### Add length to POST request
>![Pasted image 20241001052520](Images/Pasted%20image%2020241001052520.png)
>###### Find SSH creds in output
>![Pasted image 20241001052624](Images/Pasted%20image%2020241001052624.png)
>###### Decode creds
>![Pasted image 20241001052947](Images/Pasted%20image%2020241001052947.png)
#### ariah

>[!code]- SSH as ariah
>###### SSH
>![Pasted image 20241001053130](Images/Pasted%20image%2020241001053130.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20241001053246](Images/Pasted%20image%2020241001053246.png)
###### root

>[!code]- Find an encrypted PDF in the ftp folder
>###### PDF
>![Pasted image 20241002055251](Images/Pasted%20image%2020241002055251.png)
>###### Convert PDF to john hash
>```powershell
>pdf2john Infrastructure.pdf > pdf.txt
>john --wordlist=rockyou.txt pdf.txt     # ariah4168
>```
>###### Open PDF
>![Pasted image 20241001060846](Images/Pasted%20image%2020241001060846.png)

>[!code]- Find an internal web server on port 80
>###### PDF content suggest command injection available
>![Pasted image 20241001060846](Images/Pasted%20image%2020241001060846.png)
>###### netstat shows running port 80
>![Pasted image 20241002053645](Images/Pasted%20image%2020241002053645.png)
>###### The running processes from the 8089 server shows port 80 running
>![Pasted image 20241002050802](Images/Pasted%20image%2020241002050802.png)

>[!code]- Setup a SSH port forward to reach internal web server 
>###### SSH local port forward
>![Pasted image 20241002050738](Images/Pasted%20image%2020241002050738.png)

>[!code]- Execute commands on the internal web server as system
>###### Whoami
>![Pasted image 20241002055654](Images/Pasted%20image%2020241002055654.png)
>###### Create a command to add ariah to Remote Desktop Users and Administrators group
>![Pasted image 20241002051346](Images/Pasted%20image%2020241002051346.png)
>###### Execute that command on the web server
>![Pasted image 20241002051323](Images/Pasted%20image%2020241002051323.png)

>[!code]- Once ariah is an Admin, execute PsExec to obtain shell as system
>###### Copy PsExec to Windows
>![Pasted image 20241002053114](Images/Pasted%20image%2020241002053114.png)
>###### Execute PsExec to obtain system shell
>![Pasted image 20241002053023](Images/Pasted%20image%2020241002053023.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241002055928](Images/Pasted%20image%2020241002055928.png)