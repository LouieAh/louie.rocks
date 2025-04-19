#box-billing #cve-2022-3552 #git-dumper #git #sudo #bash-p

>[!code]- Find open ports (22, 80)
>![Pasted image 20240724054337](Images/Pasted%20image%2020240724054337.png)
#### Foothold

>[!code]- Find web server is using a domain name of bullbox.local
>Navigating to the web server in the browser window ultimately reveals it when the request times out, but using curl reveals it faster.
>
>![Pasted image 20240724054751](Images/Pasted%20image%2020240724054751.png)

>[!code]- Find a **.git** directory via directory enumeration
>Using gobuster and the **big** wordlist:
>
>![Pasted image 20240724063501](Images/Pasted%20image%2020240724063501.png)

>[!code]- Dump the git repository
>Using the tool from this [Github repository](https://github.com/arthaud/git-dumper), we can dump the contents of the git repository.
>
>![Pasted image 20240724063706](Images/Pasted%20image%2020240724063706.png)

>[!code]- Find admin credentials within the dumped repository
>The repository contained the following folders:
>
>![Pasted image 20240724063800](Images/Pasted%20image%2020240724063800.png)
>
>The **bb-config.php** file contained admin credentials:
>
>![Pasted image 20240724063840](Images/Pasted%20image%2020240724063840.png)
#### Access

>[!code]- Find and use an authenticated RCE exploit
>A Google search for Box Billing exploit led to this [Github repo](https://github.com/kabir0x23/CVE-2022-3552).
>
>The exploit contained a PHP reverse shell, which I updated my the attacking details:
>
>![Pasted image 20240725044112](Images/Pasted%20image%2020240725044112.png)
>
>Then ran the exploit (gobuster found the **/bb-admin** page which suggested the admin username was an email address - so I added on **\@bullybox.local**)
>
> ![Pasted image 20240725044151](Images/Pasted%20image%2020240725044151.png)
> 
> ![Pasted image 20240725044445](Images/Pasted%20image%2020240725044445.png)
> 
#### Privilege Escalation

>[!code]- Obtain root permissions by using sudo to enable SUID bit on the **/bin/bash** binary
>We can run all commands with sudo without need for password:
>
>![Pasted image 20240725044713](Images/Pasted%20image%2020240725044713.png)
>
>Enable the SUID bit:
>
>![Pasted image 20240725044800](Images/Pasted%20image%2020240725044800.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240725044849](Images/Pasted%20image%2020240725044849.png)

