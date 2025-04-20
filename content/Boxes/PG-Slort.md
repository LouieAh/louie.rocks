#rfi #php-data-filter #tftp-exe

>[!code]- Find open ports (21, 135, 139, 445, 3306, 4443, 8080)
>
>![Pasted image 20240924045908](Images/Pasted%20image%2020240924045908.png)
#### Port 4443 - HTTP server

>[!code]- Find LFI/RFI vulnerability
>###### Find /site/ directory
>![Pasted image 20240925043437](Images/Pasted%20image%2020240925043437.png)
>###### Landing page
>![Pasted image 20240925043606](Images/Pasted%20image%2020240925043606.png)
>###### LFI can reach an external machine (attacking Kali machine)
>![Pasted image 20240925043741](Images/Pasted%20image%2020240925043741.png)
>![Pasted image 20240925043809](Images/Pasted%20image%2020240925043809.png)
>###### PHPinfo shows data:// filter is enabled (we can execute system commands)
>![Pasted image 20240925044250](Images/Pasted%20image%2020240925044250.png)
>![Pasted image 20240925044224](Images/Pasted%20image%2020240925044224.png)
###### rupert

>[!code]- Use RFI with data:// filter to obtain reverse shell
>###### List current directory contents
>![Pasted image 20240925044400](Images/Pasted%20image%2020240925044400.png)
>###### Retrieve nc.exe from Kali
>![Pasted image 20240925044526](Images/Pasted%20image%2020240925044526.png)
>![Pasted image 20240925044545](Images/Pasted%20image%2020240925044545.png)
>###### Export cmd.exe with nc.exe to obtain reverse shell
>![Pasted image 20240925045203](Images/Pasted%20image%2020240925045203.png)
>###### Catch resultant shell on Kali
>![Pasted image 20240925045237](Images/Pasted%20image%2020240925045237.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20240924061723](Images/Pasted%20image%2020240924061723.png)
###### Administrator

>[!code]- Find scheduled task and `C:\Backup\TFTP.EXE`
>###### List `C:\Backup`
>![Pasted image 20240925054049](Images/Pasted%20image%2020240925054049.png)
>###### Cat info.txt
>![Pasted image 20240925054117](Images/Pasted%20image%2020240925054117.png)
>###### We have full control over TFTP.EXE
>![Pasted image 20240925054229](Images/Pasted%20image%2020240925054229.png)

>[!code]- Replace TFTP.EXE to obtain reverse shell as admin
>###### Generate malicious exe
>![Pasted image 20240925054307](Images/Pasted%20image%2020240925054307.png)
>###### Move original exe
>![Pasted image 20240925054357](Images/Pasted%20image%2020240925054357.png)
>###### Transfer malicious exe
>![Pasted image 20240925054417](Images/Pasted%20image%2020240925054417.png)
>###### Wait for reverse shell to execute
>![Pasted image 20240925054522](Images/Pasted%20image%2020240925054522.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20240925054810](Images/Pasted%20image%2020240925054810.png)

