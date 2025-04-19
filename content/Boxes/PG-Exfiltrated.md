#### Tags
- All: #subrion-cms #default-credentials #file-upload #exploit-49876 #phar #cron #exiftool #djvu #exploit-50911
- Foothold: #subrion-cms #default-credentials 
- Access: #file-upload #phar #exploit-49876
- Privilege Escalation: #cron #exiftool #djvu #exploit-50911

>[!code]- Scan open ports (22, 80)
>
>![Pasted image 20240620060438](/Images/Pasted%20image%2020240620060438.png)
#### Foothold

>[!code]- Update /etc/hosts with `exfiltrated.offsec`
>Visiting the webserver redirects to reveal a hostname:
>![Pasted image 20240620060555](/Images/Pasted%20image%2020240620060555.png)
>
>___
>
>Updating /etc/hosts:
>![Pasted image 20240620060703](/Images/Pasted%20image%2020240620060703.png)
>
>___
>
>We now get to see the website:
>![Pasted image 20240620060737](/Images/Pasted%20image%2020240620060737.png)

>[!code]- Use credentials `admin:admin` to login on `/panel` subpage
>- The Nmap scan showed there was a **/panel** subpage. Visiting it reveals a login portal.
>- The default credentials **admin:admin** work
>- The login portal reveals that the CMS version is **4.2.1**
>
>![Pasted image 20240624044741](/Images/Pasted%20image%2020240624044741.png)
#### Access

>[!code]- Use an exploit to upload a file to obtain RCE
>- Exploit 49876: [https://www.exploit-db.com/exploits/49876](https://www.exploit-db.com/exploits/49876)
>
>Upload a .phar file (PHP Archive) on the Uploads page
>![Pasted image 20240624045356](/Images/Pasted%20image%2020240624045356.png)
>
>Start a listener on Kali, then execute the file via the Uploads directory on the webpage.
>![Pasted image 20240624045639](/Images/Pasted%20image%2020240624045639.png)
>![Pasted image 20240624045701](/Images/Pasted%20image%2020240624045701.png)
#### Privilege Escalation

>[!code]- Use pspy64 to find a cron job running a vulnerable exiftool command
>The script runs as root and uses Exiftool to parse any files with **jpg** in their filename that are in the **/var/www/html/subrion/uploads** folder.
>
>![Pasted image 20240624050311](/Images/Pasted%20image%2020240624050311.png)

>[!code]- Create a malicious JPG to exploit Exiftool and obtain root privileges
>- Some versions of Exiftool allow the execution of arbitrary code when parsing a file within the DjVu file format
>- This exploit creates the malicious file which causes a reverse shell to execute [https://github.com/LazyTitan33/ExifTool-DjVu-exploit/blob/main/CVE-2021-22204.py](https://github.com/LazyTitan33/ExifTool-DjVu-exploit/blob/main/CVE-2021-22204.py).
>
>Create the malicious JPG file:
>
>![Pasted image 20240624053500](/Images/Pasted%20image%2020240624053500.png)
>
>___
>
>Start a listener on Kali and transfer the file to the Uploads folder on victim. Wait for cron to parse the file and send a reverse shell to our listener:
>
>![Pasted image 20240624053649](/Images/Pasted%20image%2020240624053649.png)
>![Pasted image 20240624053707](/Images/Pasted%20image%2020240624053707.png)

>[!success]- Obtain local.txt and proof.txt
>![Pasted image 20240624053108](/Images/Pasted%20image%2020240624053108.png)




