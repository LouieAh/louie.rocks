192.168.219.105

>[!code]- Open ports
>![Pasted image 20241212054212](/Images/Pasted%20image%2020241212054212.png)

>[!code]- Find files on a SMB share
>###### Download all the files in the Commander share
>![Pasted image 20241212054934](/Images/Pasted%20image%2020241212054934.png)

>[!code]- Find a vulnerable plugin on a wordpress site
>###### Find the wordpress site
>![Pasted image 20241212061702](/Images/Pasted%20image%2020241212061702.png)
>###### Enumerate the plugins
>![Pasted image 20241212061729](/Images/Pasted%20image%2020241212061729.png)
>...
>![Pasted image 20241212061748](/Images/Pasted%20image%2020241212061748.png)

>[!code]- Exploit a vulnerable plugin (simple-file-list) to obtain a reverse shell
>###### [Find an exploit](https://www.exploit-db.com/exploits/48979) for version 4.2.2
>![Pasted image 20241212061852](/Images/Pasted%20image%2020241212061852.png)
>###### Edit the IP address and port in the exploit
>![Pasted image 20241212061955](/Images/Pasted%20image%2020241212061955.png)
>###### Execute the exploit
>![Pasted image 20241212062016](/Images/Pasted%20image%2020241212062016.png)
>###### Catch the reverse shell
>![Pasted image 20241212062037](/Images/Pasted%20image%2020241212062037.png)

>[!success]- Obtain local.txt
>![Pasted image 20241212062224](/Images/Pasted%20image%2020241212062224.png)