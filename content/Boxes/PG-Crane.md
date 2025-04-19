#suitecrm #sugarcrm #sugarcrm-7-12-3 #default-credentials #sudo #service

>[!code]- Find open ports (22, 80, 3306, 33060)
>![Pasted image 20240726060214](Images/Pasted%20image%2020240726060214.png)
#### Foothold

>[!code]- Login to port 80 with default credentials (**admin:admin**)
>![Pasted image 20240726060331](Images/Pasted%20image%2020240726060331.png)
>
>![Pasted image 20240726060345](Images/Pasted%20image%2020240726060345.png)

>[!code]- Download a diagnostics report to get SuiteCRM version
>Admin > Diagnostics Tool > *Run the tool* > Download the Diagnostic file
>
>![Pasted image 20240727065119](Images/Pasted%20image%2020240727065119.png)
>![Pasted image 20240727065145](Images/Pasted%20image%2020240727065145.png)
>![Pasted image 20240727065235](Images/Pasted%20image%2020240727065235.png)
>
>Unzip it. Then find version number in **config.php**:
>
>![Pasted image 20240727065359](Images/Pasted%20image%2020240727065359.png)
>![Pasted image 20240727065429](Images/Pasted%20image%2020240727065429.png)
#### Access

>[!code]- Find and use an authenticated SuiteCRM v7.12.3 exploit
>From a Google search I find this [Github repo](https://github.com/manuelz120/CVE-2022-23940).
>
>Execute the exploit:
>
>![Pasted image 20240727070439](Images/Pasted%20image%2020240727070439.png)
>![Pasted image 20240727070457](Images/Pasted%20image%2020240727070457.png)

>[!success]- Obtain local.txt
>![Pasted image 20240727071154](Images/Pasted%20image%2020240727071154.png)
#### Privilege Escalation

>[!code]- Find **www-data** has sudo privileges to execute **/usr/sbin/service**
>![Pasted image 20240727070748](Images/Pasted%20image%2020240727070748.png)

>[!code]- Run **service** with sudo to obtain a root privileged shell
>[GTFOBins shows](https://gtfobins.github.io/gtfobins/service/) the service binary is vulnerable:
>
>![Pasted image 20240727070909](Images/Pasted%20image%2020240727070909.png)
>
>Execute the exploit:
>
>![Pasted image 20240727070958](Images/Pasted%20image%2020240727070958.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240727071208](Images/Pasted%20image%2020240727071208.png)
