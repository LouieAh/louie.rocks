#squid #proxy #default-credentials #phpmyadmin #sql #into-outfile #local-service #fullpowers

>[!code]- Open ports
>![Pasted image 20241206044327](/Images/Pasted%20image%2020241206044327.png)

>[!code]- Discovery port 8080 via the Squid proxy (port 3128)
>###### [Hacktricks article](https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid) suggests to use [this tool](https://github.com/aancw/spose) to enumerate ports accessible via the Squid proxy
>![Pasted image 20241205061155](/Images/Pasted%20image%2020241205061155.png)

>[!code]- Setup Firefox to use the Squid proxy to access port 8080
>###### FoxyProxy
>![Pasted image 20241205061110](/Images/Pasted%20image%2020241205061110.png)
>###### Navigate to port 8080 via port 3128
>![Pasted image 20241205061127](/Images/Pasted%20image%2020241205061127.png)

>[!code]- Discover phpMyAdmin on port 8080 and login with default creds
>###### Feroxbuster scan via the proxy on port 3128
>![Pasted image 20241205063133](/Images/Pasted%20image%2020241205063133.png)
>![Pasted image 20241205063112](/Images/Pasted%20image%2020241205063112.png)
>###### MyPHPAdmin index page
>![Pasted image 20241205063057](/Images/Pasted%20image%2020241205063057.png)
>###### Login with default credentials (root:`<no password>`)
>![Pasted image 20241206044952](/Images/Pasted%20image%2020241206044952.png)

>[!code]- Use SQL to upload a php file with a command inject vulnerability at the web root
>###### Find the web root (C:/wamp/www) via phpinfo
>![Pasted image 20241206045316](/Images/Pasted%20image%2020241206045316.png)
>###### Create a new file to the document root
>![Pasted image 20241206050014](/Images/Pasted%20image%2020241206050014.png)
>###### Use the command injection vulnerability with the new file
>![Pasted image 20241206050109](/Images/Pasted%20image%2020241206050109.png)
#### Local Service shell

>[!code]- Use command injection to obtain a reverse shell
>###### Upload nc.exe
>![Pasted image 20241206051357](/Images/Pasted%20image%2020241206051357.png)
>###### Export cmd.exe via nc.exe
>![Pasted image 20241206051416](/Images/Pasted%20image%2020241206051416.png)
>###### Catch the reverse shell
>![Pasted image 20241206051437](/Images/Pasted%20image%2020241206051437.png)

>[!success]- Obtain local.txt
>![Pasted image 20241205065118](/Images/Pasted%20image%2020241205065118.png)
#### Privileged shell

>[!code]- Regain full privileges for the current Local Service account
>###### Create an execute a scheduled task
>![Pasted image 20241206055106](/Images/Pasted%20image%2020241206055106.png)
>###### Catch the reverse shell from the scheduled task
>![Pasted image 20241206055144](/Images/Pasted%20image%2020241206055144.png)
>###### Regain SeImpersonatePrivilege via [FullPowers.exe](https://github.com/itm4n/FullPowers/releases/tag/v0.1)
>![Pasted image 20241206055642](/Images/Pasted%20image%2020241206055642.png)
#### root shell

>[!code]- Exploit SeImpersonatePrivilege to execute a reverse shell with GodPotato
>###### Execute the reverse shell
>![Pasted image 20241206060049](/Images/Pasted%20image%2020241206060049.png)
>###### Catch the reverse shell
>![Pasted image 20241206060111](/Images/Pasted%20image%2020241206060111.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241206060136](/Images/Pasted%20image%2020241206060136.png)


