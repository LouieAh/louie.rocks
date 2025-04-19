#robots-txt #app_dev #symfony #fragment #lfi #proftp #sql-conf #mysql #authorized-keys #sudo-i

>[!code]- Find open ports (21, 22, 80)
#### Foothold

>[!code]- Directory enumerate the web server and find /robots.txt
>
>![Pasted image 20240708051147](/Images/Pasted%20image%2020240708051147.png)

>[!code]- Visit robots.txt and find /app_dev.php
>Visiting robots.txt:
>
![Pasted image 20240704055820](/Images/Pasted%20image%2020240704055820.png)
>
>Visiting /app_dev.php
>
>![Pasted image 20240704055906](/Images/Pasted%20image%2020240704055906.png)

>[!code]- Discover that RCE can be obtained if the secret key is known
>RCE can be obtained via the **\_fragment** page as per [this guide](https://www.ambionics.io/blog/symfony-secret-fragment) **if the secret key is known**.
>
>The secret key can be viewed via a LFI exploit and visiting **/app/parameters/config.yml** as per [this guide](https://infosecwriteups.com/how-i-was-able-to-find-multiple-vulnerabilities-of-a-symfony-web-framework-web-application-2b82cd5de144).
>
>![Pasted image 20240705044716](/Images/Pasted%20image%2020240705044716.png)
#### Access

>[!code]- Execute the exploit to obtain RCE
>[This guide](https://www.ambionics.io/blog/symfony-secret-fragment) links to this [Github repo](https://github.com/ambionics/symfony-exploits/blob/main/secret_fragment_exploit.py), which explains how to obtain RCE once the secret key is known.
>
>First use the basic command that just includes the secret key:
>
>![Pasted image 20240705052805](/Images/Pasted%20image%2020240705052805.png)
>
>The readme file of the Github repo gives an example that calls a system command:
>
>![Pasted image 20240705053235](/Images/Pasted%20image%2020240705053235.png)
>
>We can use this to create a system command which calls a reverse shell back to our attacking machine. We must select port 80 as the listener command as port 1234, for example, doesn't work.
>
>![Pasted image 20240705053331](/Images/Pasted%20image%2020240705053331.png)
>
>Visiting that link causes our listening to catch our reverse shell:
>
>![Pasted image 20240705053608](/Images/Pasted%20image%2020240705053608.png)

>[!success]- Obtain local.txt
>![Pasted image 20240705053647](/Images/Pasted%20image%2020240705053647.png)
#### Privilege Escalation

>[!code]- Find the benoit user, a MySQL instance and ProFTP database credentials
>There is a **benoit** user:
>>[!code]- /etc/password
>>![Pasted image 20240708050214](/Images/Pasted%20image%2020240708050214.png)
>
>>[!code]- /home/
>>![Pasted image 20240708050240](/Images/Pasted%20image%2020240708050240.png)
>
>___
>
>There is (probably a MySQL instance) running on port 3306
>>[!code]- netstat -anp
>>![Pasted image 20240708050535](/Images/Pasted%20image%2020240708050535.png)
>
>___
>
>There are database credentials in **sql.conf**, a file associated with proftpd, which rustscan earlier showed was running on port 21 (it didn't allow anonymous access, though).
>>[!code]- /etc/proftpd/sql.conf
>>![Pasted image 20240705062112](/Images/Pasted%20image%2020240705062112.png)
>

>[!info]- Possible setup with ProFTP and MySQL
>It seems the ProFTP service running on port 21 is using a MySQL database to record which users can authenticate.
>
>Logging into /phpmyadmin (found earlier during directory fuzzing) with the found database credentials, we can see the columns used in the **ftpuser** table:
>
>![Pasted image 20240708052304](/Images/Pasted%20image%2020240708052304.png)

>[!warning]- We cannot add a root user to the ProFTP database
>A root user would have its uid set to 0, but, as per [this guide](http://www.proftpd.org/docs/contrib/mod_sql.html#SQLMinID), because the **SQLMinID** is set to '33', we cannot set a user's uid to below 33. If we do, the service will simply change the uid to the default value of 999.
>>[!code]- /etc/proftpd/sql.conf
>>![Pasted image 20240708053204](/Images/Pasted%20image%2020240708053204.png) 

>[!code]- Add a user to the ProFTP database that imitates the benoit user
>>[!exploit]- If we can access benoit's home directory through the ProFTP service, we might be able to edit their **authorized_keys** file and SSH in as benoit.
>
>A password in the correct format can be created like so ([this guide](https://medium.com/@nico26deo/how-to-set-up-proftpd-with-a-mysql-backend-on-ubuntu-c6f23a638caf) showed how):
>
>![Pasted image 20240708052936](/Images/Pasted%20image%2020240708052936.png)
>
>User phpmyadmin to add a new user that imitates the benoit user on the victim. The uid MUST be the same as the uid assigned to uid on the victim, otherwise we won't be truly recognised as the benoit user.
>
![Pasted image 20240708054422](/Images/Pasted%20image%2020240708054422.png)
>
![Pasted image 20240708054409](/Images/Pasted%20image%2020240708054409.png)

>[!code]- Login to the ProFTP service and add our public key
>- Login to the ProFTP service with the newly added credentials.
>- **cd** to **/home/benoit** and **mkdir** a **.ssh** directory
>- In the **.ssh** directory, upload our **authorized_keys** file (which contains our public key)
>
![Pasted image 20240708055827](/Images/Pasted%20image%2020240708055827.png)

>[!code]- SSH into victim as benoit using our public key
>
>![Pasted image 20240708055926](/Images/Pasted%20image%2020240708055926.png)

>[!code]- Use the sudo privileges granted to benoit to get a shell as root
>List sudo privileges:
>
>![Pasted image 20240708060608](/Images/Pasted%20image%2020240708060608.png)
>
>Use those privileges to execute a new shell as root:
>
>![Pasted image 20240708060638](/Images/Pasted%20image%2020240708060638.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20240708060659](/Images/Pasted%20image%2020240708060659.png)