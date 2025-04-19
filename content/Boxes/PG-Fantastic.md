#grafana #cve-2021-43798 #exploit-50581 #go #pbkdf2 #disk-group #port3000 #ppp

>[!code]- Find open ports (22, 3000 http, 9090 http)
>![Pasted image 20240701044601](/Images/Pasted%20image%2020240701044601.png)
#### Foothold

>[!code]- Find an exploit for the Grafana web app (port 3000)
>Grafana version 8.3.0 is installed:
>>[!code]- Screenshot
>>![Pasted image 20240701060823](/Images/Pasted%20image%2020240701060823.png)
>
>___
>
>We find an [exploit](https://www.exploit-db.com/exploits/50581) for version 8.3.0 (CVE-2021-43798) that allows arbitrary file reads:
>
>>[!code]- Screenshot
>>![Pasted image 20240701061058](/Images/Pasted%20image%2020240701061058.png)
>
>___
>
>There's a couple of more in-depth repositories ([here](https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798/tree/main), [here](https://github.com/jas502n/Grafana-CVE-2021-43798/tree/main)) which use the same exploit to download the Grafana database, read the admin username and password, then decrypt the password using the key stored in Grafana's config file.
>- Grafana database file: **/var/lib/grafana/grafana.db**
>- Grafana configuration file: **/etc/grafana/grafana.ini**
>We can then use the exploit to read a file on the victim:
>![Pasted image 20240702052154](/Images/Pasted%20image%2020240702052154.png)

>[!code]- Use the exploit to obtain the admin hash and decryption key
>The config file contains the decryption key:
>
>![Pasted image 20240702052235](/Images/Pasted%20image%2020240702052235.png)
>![Pasted image 20240701053615](/Images/Pasted%20image%2020240701053615.png)
>
>The database contains the admin's hash (within the **data_source** table and the **secure_json_data** column):
>
>![Pasted image 20240702052343](/Images/Pasted%20image%2020240702052343.png)
>![Pasted image 20240701055238](/Images/Pasted%20image%2020240701055238.png)
#### Access

>[!code]- Decrypt the hash to obtain the plaintext admin password
>[This repository](https://github.com/jas502n/Grafana-CVE-2021-43798/tree/main)shows how the AESDecrypt go script is used to decrypt the obtained hash.
>
>___
>
>Before running the AESDecrypt script, I need to initialise the **go.mod** file then download the **pbkdf2** module:
>
>![Pasted image 20240702052943](/Images/Pasted%20image%2020240702052943.png)
>
>Then in the script I edit the variables that store the hash and the key:
>
>![Pasted image 20240702053035](/Images/Pasted%20image%2020240702053035.png)
>
>Then I run the script to decrypt the hash using the key:
>
>![Pasted image 20240702053102](/Images/Pasted%20image%2020240702053102.png)

>[!code]- SSH using the admin username and password
>
>![Pasted image 20240702053435](/Images/Pasted%20image%2020240702053435.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20240702053712](/Images/Pasted%20image%2020240702053712.png)
#### Privilege Escalation (root)

>[!code]- Use the permissions I have as part of the Disk group
>Linpeas shows I'm part of the Disk group:
>
>![Pasted image 20240702054420](/Images/Pasted%20image%2020240702054420.png)
>
>[HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe) suggests I can use this privilege to read any file on the system:
>
>- **df -h** to find out which filesystem **/** is mounted
>- **debugfs /dev/sda2** to start reading files with root permissions
>
>>[!code]- Screenshot
>>![Pasted image 20240702054502](/Images/Pasted%20image%2020240702054502.png)
>>![Pasted image 20240702054717](/Images/Pasted%20image%2020240702054717.png)
>
>___
>
>Alternatively, I can read root's private SSH key and then SSH into victim as root:
>
>>[!code]- Screenshot
>>![Pasted image 20240702055357](/Images/Pasted%20image%2020240702055357.png)
>>![Pasted image 20240702055332](/Images/Pasted%20image%2020240702055332.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20240702054838](/Images/Pasted%20image%2020240702054838.png)
