#zookeeper #exhibitor #cve-2019-5029 #exploit-48654 #gcore #strings #su #sudo-l

>[!code]- Open ports
>![Pasted image 20241120044139](Images/Pasted%20image%2020241120044139.png)
#### Web shell (charles)

>[!code]- Landing page reveals Exhibitor for ZooKeeper "v1.0"
>###### Exhibitor for ZooKeeper v1.0
>![Pasted image 20241120044827](Images/Pasted%20image%2020241120044827.png)

>[!code]- Find a RCE exploit for Exhibitor
>###### [The exploit](https://www.exploit-db.com/exploits/48654) on searchsploit
>![Pasted image 20241120050822](Images/Pasted%20image%2020241120050822.png)
>###### Use the suggested curl command
>![Pasted image 20241120050854](Images/Pasted%20image%2020241120050854.png)
>###### Edit the data.json file to fit my IP address and replace all double quote characters with direction independent double quotes
>![Pasted image 20241120051014](Images/Pasted%20image%2020241120051014.png)
>###### Setup a listener and execute the curl command
>![Pasted image 20241120051041](Images/Pasted%20image%2020241120051041.png)
>###### Catch the reverse shell
>![Pasted image 20241120051112](Images/Pasted%20image%2020241120051112.png)

>[!success]- Obtain local.txt
>![Pasted image 20241120051431](Images/Pasted%20image%2020241120051431.png)
#### root shell

>[!code]- /usr/bin/gcore enabled for sudo
>###### Sudo -l
>![Pasted image 20241120053937](Images/Pasted%20image%2020241120053937.png)

>[!code]- Use gcore to read root password
>###### GTFOBins suggests exploit method
>![Pasted image 20241120054023](Images/Pasted%20image%2020241120054023.png)
>###### [This video](https://www.youtube.com/watch?app=desktop&v=-8Mca4ZV7rU&t=0s) suggests to use gcore to read a password process
>![Pasted image 20241120054125](Images/Pasted%20image%2020241120054125.png)
>###### Find a similar 'password-store' process running as root
>![Pasted image 20241120054207](Images/Pasted%20image%2020241120054207.png)
>###### Use gcore to create a dump of that process
>![Pasted image 20241120054253](Images/Pasted%20image%2020241120054253.png)
>###### Use strings to output readable text in the dump
>![Pasted image 20241120054332](Images/Pasted%20image%2020241120054332.png)
>###### Find a password for root in the strings dump
>![Pasted image 20241120054359](Images/Pasted%20image%2020241120054359.png)

>[!code]- Switch to root user using found password (ClogKingpinInning731)
>###### Su
>![Pasted image 20241120054436](Images/Pasted%20image%2020241120054436.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241120054509](Images/Pasted%20image%2020241120054509.png)