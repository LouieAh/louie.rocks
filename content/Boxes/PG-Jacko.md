#h2-console #path-fixing #god-potato #exploit-49382 #paperstream #twain

>[!code]- Find open ports (80, 135, 139, 445, 5040, 8082, 9092)
>
>![Pasted image 20240925060032](Images/Pasted%20image%2020240925060032.png)
#### Port 8082

>[!code]- Connect to H2 database console (no password needed)
>###### Landing page
>![Pasted image 20240925060400](Images/Pasted%20image%2020240925060400.png)
>###### Logged in landing page
>![Pasted image 20240925060444](Images/Pasted%20image%2020240925060444.png)

>[!code]- Find exploit for H2 console v1.4.199
>###### Use [exploit](https://www.exploit-db.com/exploits/49384) to obtain RCE (enter commands into the SQL statement box)
>![Pasted image 20240926044930](Images/Pasted%20image%2020240926044930.png)
>
###### jacko

>[!code]- Use exploit to obtain a reverse shell
>###### Transfer netcat to victim
>![Pasted image 20240926045541](Images/Pasted%20image%2020240926045541.png)
>![Pasted image 20240926045834](Images/Pasted%20image%2020240926045834.png)
>###### Export cmd.exe shell with netcat
>![Pasted image 20240926051150](Images/Pasted%20image%2020240926051150.png)
>###### Catch reverse shell
>![Pasted image 20240926051214](Images/Pasted%20image%2020240926051214.png)

>[!code]- Fix $PATH variable
>The $PATH variable is set such that I cannot execute simple commands like 'dir' and 'whoami'.
>###### See environment variables
>![Pasted image 20240926052023](Images/Pasted%20image%2020240926052023.png)
>###### Change environment variable
>![Pasted image 20240926052548](Images/Pasted%20image%2020240926052548.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20240926052916](Images/Pasted%20image%2020240926052916.png)
###### Administrator

>[!code]- Find jacko has SeImpersonatePrivilege

>[!code]- Use GodPotato to exploit SeImpersonate and obtain reverse shell
>###### Execute GodPotato
>![Pasted image 20240926061348](Images/Pasted%20image%2020240926061348.png)
>###### Catch reverse shell
>![Pasted image 20240926061433](Images/Pasted%20image%2020240926061433.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20240926060540](Images/Pasted%20image%2020240926060540.png)
###### Administrator - alternative method

>[!code]- Hijack dll (see [guide](https://benheater.com/proving-grounds-jacko/))
>###### Edit exploit.ps1 from [here](https://www.exploit-db.com/exploits/49382)
>![Pasted image 20240927051154](Images/Pasted%20image%2020240927051154.png)
>###### Generate malicious dll (-a x86 due to vulnerable application located in x86 Program Files)
>![Pasted image 20240927051044](Images/Pasted%20image%2020240927051044.png)
>###### Execute exploit.ps1
>![Pasted image 20240927051235](Images/Pasted%20image%2020240927051235.png)
>###### Catch reverse shell
>![Pasted image 20240927051007](Images/Pasted%20image%2020240927051007.png)