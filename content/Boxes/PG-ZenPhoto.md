#zen-photo #busybox #linux-kernel #kernel-2-6-32 #kernel-exploit #linux-2-6-32

>[!code] Find open ports (22, 23, 80, 3306)
>![Pasted image 20241028064832](Images/Pasted%20image%2020241028064832.png)
#### www-data

>[!code]- Port 80 has a /test/ directory
>###### Feroxbuster result
>![Pasted image 20241101050820](Images/Pasted%20image%2020241101050820.png)
>###### /test/ landing page
>![Pasted image 20241101050802](Images/Pasted%20image%2020241101050802.png)
>

>[!code]- Port 80 is running zenphoto version 1.4.1.4
>###### Source page for /test/ reveals the version
>![Pasted image 20241101051013](Images/Pasted%20image%2020241101051013.png)

>[!code]- A RCE exploit exists for version 1.4.1.4
>###### Searchsploit
>![Pasted image 20241101051116](Images/Pasted%20image%2020241101051116.png)
>###### Obtain a shell
>![Pasted image 20241101051907](Images/Pasted%20image%2020241101051907.png)

>[!code]- Obtain a reverse shell
>###### Busybox shell
>![Pasted image 20241101052520](Images/Pasted%20image%2020241101052520.png)
>###### Catch reverse shell
>![Pasted image 20241101052547](Images/Pasted%20image%2020241101052547.png)

>[!success]- Obtain local.txt
>![Pasted image 20241101052740](Images/Pasted%20image%2020241101052740.png)
#### root

>[!code]- Machine vulnerable to PwnKit
>###### PwnKit version <0.120
>![Pasted image 20241101054639](Images/Pasted%20image%2020241101054639.png)
>###### Compile PwnKit.c to obtain root shell
>![Pasted image 20241101054725](Images/Pasted%20image%2020241101054725.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241101054810](Images/Pasted%20image%2020241101054810.png)
#### root (alternatives)

>[!success]- Linux kernel vulnerability (<= 2.6.36)
>###### Kernel <= 2.6.36
>![Pasted image 20241101055924](Images/Pasted%20image%2020241101055924.png)
>###### Obtain [exploit](https://www.exploit-db.com/exploits/15285)
>###### Compile exploit on victim machine
>![Pasted image 20241101060030](Images/Pasted%20image%2020241101060030.png)
>###### Execute the compiled binary
>![Pasted image 20241101060051](Images/Pasted%20image%2020241101060051.png)



