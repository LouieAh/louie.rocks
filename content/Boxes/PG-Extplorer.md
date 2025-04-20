#extplorer #default-credentials #php-reverse-shell #htusers #hashcat #disk-group

>[!code]- Find open ports (22, 80)
>
>![Pasted image 20240802054155](Pasted%20image%2020240802054155.png)
#### Foothold

>[!code]- Find a directory called **/filemanager**
>
>![Pasted image 20240802060512](Pasted%20image%2020240802060512.png)
>
>![Pasted image 20240805061205](Pasted%20image%2020240805061205.png)

>[!code]- Find and login using default admin credentials for **/filemanager**
>The page shows **extplorer** is running. A google search returns default admin credentials that work.
>
>![Pasted image 20240802061238](Pasted%20image%2020240802061238.png)
>
>![Pasted image 20240802060451](Pasted%20image%2020240802060451.png)
#### Access

>[!code]- Edit a php file to obtain a reverse shell
>When we request the index page for port 80, we are redirected to **/wp-admin/setup-config.php**.
>
>![Pasted image 20240805061513](Pasted%20image%2020240805061513.png)
>
>The extplorer app lets us access the file system.
>
>![Pasted image 20240805043455](Pasted%20image%2020240805043455.png)
>
>We can edit the **setup-config.php** file to execute a reverse shell. I tried several PHP payloads but those using **exec** or **system** failed. This one worked, though.
>
>![Pasted image 20240805051918](Pasted%20image%2020240805051918.png)
#### Lateral move (www-data -> dora)

>[!code]- Find a hash for the dora user
>As **www-data** I can see the **local.txt** file is at **/home/dora/** but I don't have permissions to access it. I must find a way to obtain a shell as **dora**. Searching for dora in **/var/www/html/** I find **.htusers.php**
>
>![Pasted image 20240805054317](Pasted%20image%2020240805054317.png)

>[!code]- Crack the hash and switch to dora user
>Identifying the hash type:
>
>![Pasted image 20240805054429](Pasted%20image%2020240805054429.png)
>
>Find the corresponding Hashcat mode:
>
>![Pasted image 20240805054609](Pasted%20image%2020240805054609.png)
>
>Cracking the hash:
>
>![Pasted image 20240805054739](Pasted%20image%2020240805054739.png)
>
>Switching to dora user:
>
>![Pasted image 20240805054819](Pasted%20image%2020240805054819.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20240805055010](Pasted%20image%2020240805055010.png)
#### Privilege Escalation

>[!code]- Find that dora is part of the **disk** group
>
>![Pasted image 20240805061034](Pasted%20image%2020240805061034.png)
>

>[!success]- Exploit the disk group privileges to get a root shell and obtain **proof.txt**
>Using [this guide](https://www.hackingarticles.in/disk-group-privilege-escalation/), exploit the disk group to get read access to **/root/proof.txt**.
>
>Find where **/** is mounted, then read **/root/proof.txt** (but after that, for completeness, read **/etc/shadow** and get the hash for root user). 
>
>![Pasted image 20240805060950](Pasted%20image%2020240805060950.png)
>
>Crack the root hash.
>
>![Pasted image 20240805060915](Pasted%20image%2020240805060915.png)
>
>Switch to root user.
>
>![Pasted image 20240805061105](Pasted%20image%2020240805061105.png)