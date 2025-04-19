#barracuda #lua #sqli #xp-cmd-sh 

192.168.249.127

>[!code]- Find open ports

#### Port 8000

>[!code]- Landing page (admin account not set)
>###### Admin account is not set
>![Pasted image 20241023052519](Images/Pasted%20image%2020241023052519.png)

>[!code]- Set the admin account (bubbleman:bubbleman)
>###### Credentials of bubbleman:bubbleman
>![Pasted image 20241023052636](Images/Pasted%20image%2020241023052636.png)
>###### Success
>![Pasted image 20241023052729](Images/Pasted%20image%2020241023052729.png)

>[!code]- Edit the home page to inject a Lua reverse shell
>###### Once logged in, reload the home page, then click the Edit page icon
>![Pasted image 20241023053213](Images/Pasted%20image%2020241023053213.png)
>###### Click "Expert" button
>![Pasted image 20241023053325](Images/Pasted%20image%2020241023053325.png)
>###### Select "Enable LSP" button
>![Pasted image 20241023053355](Images/Pasted%20image%2020241023053355.png)
>###### Generate a Lua reverse shell (Lua 1 didn't work)
>![Pasted image 20241023055410](Images/Pasted%20image%2020241023055410.png)
>###### Inject the reverse shell
>![Pasted image 20241023054128](Images/Pasted%20image%2020241023054128.png)
>###### Click Save
###### Root

>[!code]- Catch a reverse shell as root
>###### Catch it
>![Pasted image 20241023054257](Images/Pasted%20image%2020241023054257.png)

>[!success]- Obtain local.txt and proof.txt
>![Pasted image 20241023055533](Images/Pasted%20image%2020241023055533.png)



![Pasted image 20241023062237](Images/Pasted%20image%2020241023062237.png)

![Pasted image 20241023062250](Images/Pasted%20image%2020241023062250.png)