#cs-cart #lfi #default-credentials #sudo-l

>[!code]- Open ports
>![Pasted image 20241120060507](Images/Pasted%20image%2020241120060507.png)
>![Pasted image 20241120060522](Images/Pasted%20image%2020241120060522.png)
>![Pasted image 20241120060536](Images/Pasted%20image%2020241120060536.png)
>![Pasted image 20241120060555](Images/Pasted%20image%2020241120060555.png)
#### Port 80 (HTTP)

>[!code]- Find a LFI vulnerability
>###### [This exploitDB guide](https://www.exploit-db.com/exploits/48890) reveals the LFI vulnerability
>![Pasted image 20241120063014](Images/Pasted%20image%2020241120063014.png)
>###### FFUF
>![Pasted image 20241120063103](Images/Pasted%20image%2020241120063103.png)
>###### /etc/passwd
>![Pasted image 20241120063120](Images/Pasted%20image%2020241120063120.png)
>###### /home/patrick/local.txt
>![Pasted image 20241120065620](Images/Pasted%20image%2020241120065620.png)

>[!code]- Login with admin:admin on /admin
>###### Find /admin with feroxbuster
>![Pasted image 20241121044240](Images/Pasted%20image%2020241121044240.png)
>###### Default creds work (admin:admin)
>![Pasted image 20241120065704](Images/Pasted%20image%2020241120065704.png)
#### www-data shell

>[!code]- Exploit an [authenticated RCE vulnerability](https://gist.github.com/momenbasel/ccb91523f86714edb96c871d4cf1d05c) to obtain a reverse shell
>###### Rename typical web shell to have a phtml extension
>![Pasted image 20241121045101](Images/Pasted%20image%2020241121045101.png)
>###### Navigate to the Template Editor in the admin console
>![Pasted image 20241121045120](Images/Pasted%20image%2020241121045120.png)
>###### Upload the phtml webshell and navigate to the /skins/ directory
>![Pasted image 20241121045222](Images/Pasted%20image%2020241121045222.png)
>###### Catch the reverse shell
>![Pasted image 20241121045246](Images/Pasted%20image%2020241121045246.png)

>[!success]- Obtain local.txt
>![Pasted image 20241121045951](Images/Pasted%20image%2020241121045951.png)
#### Patrick shell

>[!code]- Switch to patrick user by guessing password 'patrick'
>###### See patrick user exists
>![Pasted image 20241121062129](Images/Pasted%20image%2020241121062129.png)
>###### Su to patrick using password 'patrick'
>![Pasted image 20241121062200](Images/Pasted%20image%2020241121062200.png)
>

>[!code]- List sudo privileges
>###### Patrick is part of the 'adm' group so not surprising he can perform anything with sudo
>![Pasted image 20241121062402](Images/Pasted%20image%2020241121062402.png)
#### Root shell

>[!code]- Execute /bin/bash with sudo
>###### Sudo
>![Pasted image 20241121062431](Images/Pasted%20image%2020241121062431.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241121062510](Images/Pasted%20image%2020241121062510.png)

