#htaccess #nc-exe #file-upload #Invoke-RunasCs #SeManageVolumePrivilege #WerTrigger

>[!code]- Find open ports (53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389)
>![Pasted image 20241101062119](/Images/Pasted%20image%2020241101062119.png)

>[!code]- Get the domain name (**access.offsec**)
>###### LDAP naming contexts
>![Pasted image 20241101064246](/Images/Pasted%20image%2020241101064246.png)
#### svc_apache

>[!code]- The HTTP web server allows file uploads
>###### Landing page
>![Pasted image 20241104094200](/Images/Pasted%20image%2020241104094200.png)
>###### Select Buy Tickets > Buy Now > Upload Image (exploit.ps1)
>![Pasted image 20241104094304](/Images/Pasted%20image%2020241104094304.png)

>[!code]- Can access uploaded files at the /Uploads directory
>###### Finding the /Uploads directory
>![Pasted image 20241104094449](/Images/Pasted%20image%2020241104094449.png)
>![Pasted image 20241104094510](/Images/Pasted%20image%2020241104094510.png)
>###### Finding the uploaded exploit.ps1 file
>![Pasted image 20241104094604](/Images/Pasted%20image%2020241104094604.png)

>[!code]- Files with .php extensions (and similar) are blocked
>###### I tried every possible PHP extension pseudonym as well
>![Pasted image 20241104094724](/Images/Pasted%20image%2020241104094724.png)
>![Pasted image 20241104094736](/Images/Pasted%20image%2020241104094736.png)

>[!exploit]- Upload and execute a custom .htaccess file to allow PHP files to be executed
>###### Create a custom .htaccess file which tells the web server to interpret files with the '.xxx' extension as a PHP file
>![Pasted image 20241102162358](/Images/Pasted%20image%2020241102162358.png)
>###### Rename a PHP web shell to have a '.xxx' extension
>![Pasted image 20241102162412](/Images/Pasted%20image%2020241102162412.png)
>###### Upload the custom .htaccess file to the /Uploads directory
>![Pasted image 20241102162601](/Images/Pasted%20image%2020241102162601.png)
>###### Upload the web shell with the .xxx extension
>![Pasted image 20241104095619](/Images/Pasted%20image%2020241104095619.png)
>###### Execute the webshell
>![Pasted image 20241104095652](/Images/Pasted%20image%2020241104095652.png)
>![Pasted image 20241104095704](/Images/Pasted%20image%2020241104095704.png)

>[!exploit]- Obtain a reverse shell via nc.exe
>###### Use the web shell to upload nc.exe
>![Pasted image 20241104101243](/Images/Pasted%20image%2020241104101243.png)
>###### Use nc.exe to export cmd.exe and obtain a reverse shell
>![Pasted image 20241104101344](/Images/Pasted%20image%2020241104101344.png)
>###### Catch the reverse shell
>![Pasted image 20241104101507](/Images/Pasted%20image%2020241104101507.png)
#### svc_mssql

>[!code]- Find two accounts with SPNs
>###### Inject PowerView into victim memory
>![Pasted image 20241104112145](/Images/Pasted%20image%2020241104112145.png)
>###### Enumerate SPNs with PowerView
>![Pasted image 20241104104801](/Images/Pasted%20image%2020241104104801.png)
>###### Get hash for the svc_mssql account
>I tried for the krbtgt account but with no success - a Google search suggests 'kadmin/changepw' is a default machine-set SPN of some sort
>![Pasted image 20241104121555](/Images/Pasted%20image%2020241104121555.png)

>[!exploit]- Crack the hash for the svc_mssql account (trustno1)
>###### Hashcat
>![Pasted image 20241104121737](/Images/Pasted%20image%2020241104121737.png)
>![Pasted image 20241104121804](/Images/Pasted%20image%2020241104121804.png)

>[!code]- Run a command as svc_mssql using Invoke-RunasCs
>###### Inject Invoke-RunasCs into memory
>![Pasted image 20241104125503](/Images/Pasted%20image%2020241104125503.png)
>###### Run Invoke-RunasCs to export cmd.exe with nc.exe
>(nc.exe was uploaded to the web server earlier.)
>
>![Pasted image 20241104125554](/Images/Pasted%20image%2020241104125554.png)
>###### Catch the reverse shell as svc_mssql
>![Pasted image 20241104125622](/Images/Pasted%20image%2020241104125622.png)

>[!success]- Obtain local.txt
>####### C:/Users/svc_mssql/Desktop/local.txt
>![Pasted image 20241104125726](/Images/Pasted%20image%2020241104125726.png)

>[!code]- Find we have SeManageVolumePrivilege
>####### whoami /all
>![Pasted image 20241104145245](/Images/Pasted%20image%2020241104145245.png)
>

>[!exploit]- Exploit SeManageVolumePrivilege to obtain root shell
>###### Run [this exploit](https://github.com/CsEnox/SeManageVolumeExploit)
>![Pasted image 20241104145417](/Images/Pasted%20image%2020241104145417.png)
>###### As per [this guide](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) - create a malicious tzres.dll and copy to C:\Windows\System32\wbem\tzres.dll
>![Pasted image 20241104145507](/Images/Pasted%20image%2020241104145507.png)
>![Pasted image 20241104145534](/Images/Pasted%20image%2020241104145534.png)
>###### Run systeminfo to execute tzres.dll and obtain a shell
>(I could not get it to work, but two guides suggest it does work).

>[!code]- Alternative - [WerTrigger exploit](https://github.com/sailay1996/WerTrigger) (as per Offsec walkthrough)













