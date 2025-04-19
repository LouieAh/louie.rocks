#SQLi #blaze #port9090 #cockpit #authorized-keys #sudo #tar #tar-wildcard #tar-checkpoint

>[!code]- Find open ports (22, 80, 9090)
>![Pasted image 20240725053139](Images/Pasted%20image%2020240725053139.png)
#### Foothold

>[!code]- Find the **/login.php** page on port 80
>![Pasted image 20240726050820](Images/Pasted%20image%2020240726050820.png)
>
>![Pasted image 20240726050851](Images/Pasted%20image%2020240726050851.png)

>[!code]- Find the login is vulnerable to an error-based payload
>![Pasted image 20240726051037](Images/Pasted%20image%2020240726051037.png)

>[!code]- Find an SQLi payload that bypasses the login then find two encoded passwords
>These both work:
>- **admin'-- //**
>- **'OR '' = '** (sourced [from here](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt))
>
>Once logged in we see two base64 encoded passwords:
>![Pasted image 20240726045526](Images/Pasted%20image%2020240726045526.png)

>[!code]- Decode the passwords
>![Pasted image 20240726051500](Images/Pasted%20image%2020240726051500.png)

>[!fail]- Attempt to SSH as **james** or **cameron**
>Both fail as we haven't supplied a public key:
>
>![Pasted image 20240726051817](Images/Pasted%20image%2020240726051817.png)

>[!code]- Login as **james** on the login on port 9090
>![Pasted image 20240726051558](Images/Pasted%20image%2020240726051558.png)
>
>We can login as **james**:
>![Pasted image 20240726045954](Images/Pasted%20image%2020240726045954.png)

>[!code]- Add our attacking public key to the authorized key list
>Within Accounts there is an option to add a public key as an authorized public key.
>
>![Pasted image 20240726050322](Images/Pasted%20image%2020240726050322.png)
>
>![Pasted image 20240726050437](Images/Pasted%20image%2020240726050437.png)
#### Access

>[!code]- SSH as **james** using our attacking private key
![Pasted image 20240726050546](Images/Pasted%20image%2020240726050546.png)

>[!success]- Obtain local.txt
>![Pasted image 20240726053900](Images/Pasted%20image%2020240726053900.png)
#### Privilege Escalation

>[!code]- Find we have sudo privileges to run a vulnerable tar command
>The tar command accepts a wildcard, which can be exploited to execute arbritary commands.
>
![Pasted image 20240726052013](Images/Pasted%20image%2020240726052013.png)

>[!code]- Exploit the tar * wildcard to obtain root permissions
>As explained in [this guide](https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa), we can take advantage of the wildcard in the sudo tar command to create some files with malicious names. These names are interpreted as options for the tar command, with will cause the contents in our **privesc.sh** script to run.
>
>![Pasted image 20240726053651](Images/Pasted%20image%2020240726053651.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240726053830](Images/Pasted%20image%2020240726053830.png)