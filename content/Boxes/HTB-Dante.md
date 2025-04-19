#### Hosts
###### 10.10.110.2 (firewall - out of scope)
###### 10.10.110.100 / 172.16.1.100 (DANTE-WEB-NIX01)
- 21 - FTP
	- todo.txt
- 22 - SSH
- 65000 - Wordpress
	- james:Toyota
- Unknown

Credentials:
- Unknown
	- margaret:STARS5678FORTUNE401
- 10.10.110.100
	- root:qawsedrftgyhujikol (ssh)
	- james:Toyota (wordpress / ssh)
	- balthazar:TheJoker12345! (ssh)
- 172.16.1.10
	- margaret:Welcome1!2@3# (ssh)
	- frank:TractorHeadtorchDeskmat (ssh)
- 172.16.1.12:
	- admin:admin (port 80)
	  ben:Welcometomyblog (ssh)
	  julian:manchesterunited (ssh)
- 172.16.1.17
	- admin:Password6543 (webmin)
- 172.16.1.19:
	- Admin_129834765:SamsungOctober102030 (Jenkins - 8080)
- 172.16.1.20
	- mrb3n:S3kur1ty2020!
	- Several (see the xlsx file)
- 172.16.2.5:
	- jbercov:myspace7
- 172.16.2.6
	- sophie:TerrorInflictPurpleDirt996655

>[!code]- Find discoverable hosts (.2, .100)
>- 10.10.110.2 - firewall, out of scope
>- 10.10.110.100
>
>![Pasted image 20240902100905](Images/Pasted%20image%2020240902100905.png)

## ✅ 10.10.110.100 (DANTE-WEB-NIX01)

>[!code]- Find open ports (21, 22, 65000)
>
>![Pasted image 20240902103024](Images/Pasted%20image%2020240902103024.png)
#### Port 21 - FTP

>[!code]- Find a hint on the **FTP** server (todo.txt)
>###### Connect to the FTP server
>- Login as anonymous
>- Disable `passive` mode
>
>![Pasted image 20240902101940](Images/Pasted%20image%2020240902101940.png)
>###### Download all files
>![Pasted image 20240902110001](Images/Pasted%20image%2020240902110001.png)
>###### Find hint within **todo.txt**
>![Pasted image 20240902102206](Images/Pasted%20image%2020240902102206.png)
>![Pasted image 20240902102232](Images/Pasted%20image%2020240902102232.png)
#### Port 65000 - Wordpress

>[!success]- Obtain flag for **I'm nuts and bolts about you** within **robots.txt** (DANTE{Y0u_Cant_G3t_at_m3_br0!})
>
>![Pasted image 20240902105750](Images/Pasted%20image%2020240902105750.png)
###### James Wordpress login

>[!code]- Find Wordpress is running (there's a **/wordpress** directory)
>###### Via feroxbuster
>![Pasted image 20240902111958](Images/Pasted%20image%2020240902111958.png)

>[!code]- Find a Wordpress user (james)
>Execute WPscan (below) but also remember the **todo.txt** file found on the FTP server suggests a user for _James_ exists.
>
>![Pasted image 20240902135947](Images/Pasted%20image%2020240902135947.png)
>
>```powershell
>wpscan --url http://10.10.110.100:65000/wordpress/ -e u 
>```

>[!code]- Brute force password for james (Toyota)
>###### Create a custom password list
>Using words on the website.
>
>![Pasted image 20240902140041](Images/Pasted%20image%2020240902140041.png)
>###### Brute force the passwords
>![Pasted image 20240902140514](Images/Pasted%20image%2020240902140514.png)
>![Pasted image 20240902140529](Images/Pasted%20image%2020240902140529.png)

>[!code]- Login to /wp-admin using james:Toyota
>
>![Pasted image 20240903094929](Images/Pasted%20image%2020240903094929.png)
###### www-data shell

>[!code]- Obtain shell as **www-data** by editing an installed plugin
>###### Inject reverse shell into code of the Akismet plugin
>![Pasted image 20240903100341](Images/Pasted%20image%2020240903100341.png)
>###### Activate plugin (to activate injected PHP code)
>![Pasted image 20240903095844](Images/Pasted%20image%2020240903095844.png)
>###### Catch the reverse shell
>![Pasted image 20240903100259](Images/Pasted%20image%2020240903100259.png)
###### james shell

>[!code]- Obtain shell as **james** by **su** switching
>
>![Pasted image 20240903101631](Images/Pasted%20image%2020240903101631.png)

>[!success]- Obtain flag for **It's easier this way** (DANTE{j4m3s_NEEd5_a_p455w0rd_M4n4ger!})
>
>![Pasted image 20240903101810](Images/Pasted%20image%2020240903101810.png)
###### root shell

>[!code]- Obtain root shell by exploiting SUID bit for **find**
>###### Find SUID bit set for find
>![Pasted image 20240902164324](Images/Pasted%20image%2020240902164324.png)
>###### Exploit using [GTFOBins](https://gtfobins.github.io/gtfobins/find/)
>![Pasted image 20240902164256](Images/Pasted%20image%2020240902164256.png)

>[!success]- Obtain **It's easier this way** and **Show me the way** flags (DANTE{Too_much_Pr1v!!!!})
>
>![Pasted image 20240903101948](Images/Pasted%20image%2020240903101948.png)
#### Persistence

>[!code]- Crack root's hash (qawsedrftgyhujikol)
>###### Output /etc/shadow
>![Pasted image 20240903091838](Images/Pasted%20image%2020240903091838.png)
>###### Crack hash
>![Pasted image 20240903091942](Images/Pasted%20image%2020240903091942.png)
>![Pasted image 20240903091908](Images/Pasted%20image%2020240903091908.png) 

>[!code]- Obtain root's private key
>
>![Pasted image 20240903104504](Images/Pasted%20image%2020240903104504.png)

>[!code]- Obtain balthazar's password (TheJoker12345!)
>###### Output ~/.bash_history as james
>![Pasted image 20240904141535](Images/Pasted%20image%2020240904141535.png)
#### Pivot

>[!code]- Discover another network (172.16.1.0/24)
>This machine is dual-homed:
>
>![Pasted image 20240902164505](Images/Pasted%20image%2020240902164505.png)

>[!code]- Discover hosts on 172.16.1.0/24
>###### Perform an Nmap scan via the port forward
>![Pasted image 20240904103544](Images/Pasted%20image%2020240904103544.png)
## 172.16.1.1

>[!code]- Find open ports (80, 443)
>
>![Pasted image 20240906113557](Images/Pasted%20image%2020240906113557.png)
#### Port 80
#### Port 443 - pfsense

>[!code]- Find landing page for **pfsense**
>![Pasted image 20240904113111](Images/Pasted%20image%2020240904113111.png)

## 172.16.1.5 (DANTE-SQL01)

>[!code]- Find open ports (21, 111, 135, 139, 445, 1433, 2049)
>
>![Pasted image 20240906113640](Images/Pasted%20image%2020240906113640.png)
#### Port 21 - FTP

>[!code]- Connect to FTP server
>###### On 10.10.110.100
>![Pasted image 20240904121223](Images/Pasted%20image%2020240904121223.png)

>[!success]- Obtain **An open goal** flag (DANTE{Ther3s_M0r3_to_pwn_so_k33p_searching!})
>>###### Download flag.txt from the FTP server
>![Pasted image 20240904121127](Images/Pasted%20image%2020240904121127.png)

## ✅ 172.16.1.10 (DANTE-NIX02)

>[!code]- Find open ports (22, 80, 139, 445)
>
>![Pasted image 20240904103748](Images/Pasted%20image%2020240904103748.png)

>[!code]- Find internal listening ports (22, 53, 80, 139, 445, 631, 3306, 33060)
>Having obtained shell (via margaret & frank)
>
>![Pasted image 20240904172051](Images/Pasted%20image%2020240904172051.png)
#### Port 80 - HTTP

>[!code]- Find LFI vulnerability (?page=)
>###### The `page` parameter is vulnerable
>![Pasted image 20240904105719](Images/Pasted%20image%2020240904105719.png)

>[!code]- Exploit the LFI to reveal /etc/passwd and possible users (margaret, frank, omi)
>###### /etc/passwd
>![Pasted image 20240904105808](Images/Pasted%20image%2020240904105808.png)
>###### Formatted view
>![Pasted image 20240904110108](Images/Pasted%20image%2020240904110108.png)

>[!success]- Find flag for **Seclusion is an illusion** (DANTE{LF1_M@K3s_u5_lol})
>
>![Pasted image 20240904110006](Images/Pasted%20image%2020240904110006.png)

>[!code]- Exploit the LFI to reveal hostname (DANTE-NIX02)
>
>![Pasted image 20240904111338](Images/Pasted%20image%2020240904111338.png)

>[!code]- Exploit the LFI to reveal MySQL credentials (margaret:Welcome1!2@3#)
>###### Identify that Wordpress may be installed
>As per admintasks.txt obtained from the SMB server:
>
>![Pasted image 20240904135913](Images/Pasted%20image%2020240904135913.png)
>###### Identify that a PHP filter is required to access /wordpress/wp-config.php
>Without filter (blank):
>
>![Pasted image 20240904135158](Images/Pasted%20image%2020240904135158.png)
>
>With filter:
>
>![Pasted image 20240904135217](Images/Pasted%20image%2020240904135217.png)
>
>###### Decode the base64
>![Pasted image 20240904135302](Images/Pasted%20image%2020240904135302.png)

>[!code]- Exploit the LFI to find vim escape in the lshell config file (/etc/lshell.conf)
>###### Read /etc/lshell.conf (as per [the GitHub repo](https://github.com/ghantoos/lshell))
>![Pasted image 20240904152046](Images/Pasted%20image%2020240904152046.png)
#### Port 445 - SMB

>[!code]- Obtain a hint on the **SlackMigration** share (admintasks.txt)
>###### Setup port forward
>![Pasted image 20240904122917](Images/Pasted%20image%2020240904122917.png)
>###### List shares then the contents of the SlackMigration share then download file
>![Pasted image 20240904123124](Images/Pasted%20image%2020240904123124.png)
>###### Output file contents
>![Pasted image 20240904123159](Images/Pasted%20image%2020240904123159.png)
#### Port 22 - SSH
###### margaret

>[!code]- SSH as margaret (using credentials found via LFI at /wordpress/wp-config.php)
>###### SSH in
>![Pasted image 20240904151749](Images/Pasted%20image%2020240904151749.png)

>[!code]- Escape limited shell via vim exploit (:set shell=/bin/bash, :shell)
>###### Perform exploit ([as per GTFOBins](https://gtfobins.github.io/gtfobins/vim/))
>![Pasted image 20240904152914](Images/Pasted%20image%2020240904152914.png)
>![Pasted image 20240905125712](Images/Pasted%20image%2020240905125712.png)
>![Pasted image 20240905125731](Images/Pasted%20image%2020240905125731.png)
>![Pasted image 20240905125856](Images/Pasted%20image%2020240905125856.png)

>[!code]- Find passwords in cached Slack files (frank:TractorHeadtorchDeskmat, margaret:STARS5678FORTUNE401)
>###### Cat contents of a cached Slack conversation
>![Pasted image 20240904164517](Images/Pasted%20image%2020240904164517.png)
###### frank

>[!code]- Switch to frank using the credentials found in Slack file (frank:TractorHeadtorchDeskmat)
>###### Switch to frank
>![Pasted image 20240905130046](Images/Pasted%20image%2020240905130046.png)
###### root

>[!code]- Find a file that is being created in frank's home directory and executed (call.py)
>###### Run pspy64 to reveal a scheduled task being run by uid=0 (root)
>The task removes call.py (from frank's home directory)
>
>![Pasted image 20240904173723](Images/Pasted%20image%2020240904173723.png)
>###### Create a malicious call.py which adds SUID bit to /bin/bash
>![Pasted image 20240905131451](Images/Pasted%20image%2020240905131451.png)
>###### Run bash with -p
>![Pasted image 20240905131514](Images/Pasted%20image%2020240905131514.png)

>[!success]- Obtain **Snake it 'til you make it** flag (DANTE{L0v3_m3_S0m3_H1J4CK1NG_XD})


## ✅ 172.16.1.12 (DANTE-NIX04)

>[!code]- Find open ports (21, 22, 80, 443, 3306)
>
>![Pasted image 20240906155731](Images/Pasted%20image%2020240906155731.png)
#### Port 80

>[!code]- Find a blog ('Responsive Blog Site')
>###### Use feroxbuster
>![Pasted image 20240911060401](Images/Pasted%20image%2020240911060401.png)
>###### Landing page
>![Pasted image 20240911060304](Images/Pasted%20image%2020240911060304.png)
>###### Blog type
>![Pasted image 20240912044428](Images/Pasted%20image%2020240912044428.png)
###### SQLi

>[!code]- Find SQLi exploit
>###### [Find exploit](https://www.exploit-db.com/exploits/48615)
>![Pasted image 20240912044721](Images/Pasted%20image%2020240912044721.png)
>###### Proof of Concept
>![Pasted image 20240912044741](Images/Pasted%20image%2020240912044741.png)

>[!code]- Use exploit to dump database information
>###### Databases
>![Pasted image 20240912050000](Images/Pasted%20image%2020240912050000.png)

>[!success]- Find **Again and again** flag (DANTE{wHy_y0U_n0_s3cURe?!?!})
>###### Within database 'flag', table 'flag'
>![Pasted image 20240912050144](Images/Pasted%20image%2020240912050144.png)

>[!code]- Use exploit to find user's MD5 hashes
>###### 'membership_users' table in 'blog_admin_db' database
>![Pasted image 20240912051025](Images/Pasted%20image%2020240912051025.png)
>
>admin = 21232f297a57a5a743894a0e4a801fc3
>ben = 442179ad1de9c25593cabf625c0badb7
>egre55 = d6501933a2e0ea1f497b87473051417f
>
>admin:admin
>ben:Welcometomyblog

>[!code]- Crack passwords (ben:Welcometomyblog, admin:admin)
>###### Hashcat method
>![Pasted image 20240912053443](Images/Pasted%20image%2020240912053443.png)
>###### admin hash
>![Pasted image 20240912053424](Images/Pasted%20image%2020240912053424.png)
>###### ben hash
>![Pasted image 20240912053412](Images/Pasted%20image%2020240912053412.png)
>###### egre55 hash
>![Pasted image 20240912053504](Images/Pasted%20image%2020240912053504.png)
#### Port 22

>[!code]- SSH as ben using cracked password
>
>![Pasted image 20240912053722](Images/Pasted%20image%2020240912053722.png)

>[!success]- Obtain **Five doctors** flag (DANTE{Pretty_Horrific_PH4IL!})
>
>![Pasted image 20240912053811](Images/Pasted%20image%2020240912053811.png)
###### julian

>[!code]- Find ben can execute /bin/bash as any user other than root
>###### sudo -l
>![Pasted image 20240912054206](Images/Pasted%20image%2020240912054206.png)
>###### Find julian as another user
>![Pasted image 20240912054238](Images/Pasted%20image%2020240912054238.png)
>![Pasted image 20240912054255](Images/Pasted%20image%2020240912054255.png)

>[!code]- Switch to julian user
>
>![Pasted image 20240912054329](Images/Pasted%20image%2020240912054329.png)
###### root

>[!code]- Find victim is vulnerable to PwnKit
>###### Version is < 0.120
>![Pasted image 20240912060306](Images/Pasted%20image%2020240912060306.png)

>[!code]- Execute PwnKit exploit and obtain root shell
>###### Setup ligolo-ng listener then wget PwnKit binary from Kali
>![Pasted image 20240912060429](Images/Pasted%20image%2020240912060429.png)
>![Pasted image 20240912060355](Images/Pasted%20image%2020240912060355.png)
>![Pasted image 20240912060416](Images/Pasted%20image%2020240912060416.png)
>###### Execute PwnKit
>![Pasted image 20240912060512](Images/Pasted%20image%2020240912060512.png)

>[!success]- Obtain **Minus + minus = plus?** flag (DANTE{sudo_M4k3_me_@\_Sandwich})
###### Persistence

>[!code]- Crack julian hash (manchesterunited)
>
>![Pasted image 20240912062224](Images/Pasted%20image%2020240912062224.png)

## ✅ 172.16.1.13 (DANTE-WS01)

>[!code]- Find open ports (80, 443, 445)
>
>![Pasted image 20240906155641](Images/Pasted%20image%2020240906155641.png)
#### Port 80 - HTTP

>[!code]- Find a forum (/discuss/)
>###### Feroxbuster
>![Pasted image 20240906172345](Images/Pasted%20image%2020240906172345.png)
>###### Landing page
>![Pasted image 20240906172426](Images/Pasted%20image%2020240906172426.png)
###### Exploit Technical Discussion Forum

>[!code]- Find a file upload exploit
>A search for 'Technical Discussion Forum exploit' returns [this exploit](https://www.exploit-db.com/exploits/48512) in the avatar file upload when creating an account.
>###### Upload malicious file when creating an account
>_Later discovered simple-backdoor.php didn't upload so tried a simpler PHP script (test1.php)_
>
>![Pasted image 20240910052152](Images/Pasted%20image%2020240910052152.png)
>![Pasted image 20240910052534](Images/Pasted%20image%2020240910052534.png)
>###### Execute uploaded file from within /ups/ directory (as per the exploit)
>![Pasted image 20240910052740](Images/Pasted%20image%2020240910052740.png)
>![Pasted image 20240910052805](Images/Pasted%20image%2020240910052805.png)

>[!code]- Use malicious file to transfer netcat to machine
>###### Transfer netcat to 172.16.1.100
>![Pasted image 20240910053320](Images/Pasted%20image%2020240910053320.png)
>###### Transfer netcat to 172.16.1.13
>![Pasted image 20240910053408](Images/Pasted%20image%2020240910053408.png)
>![Pasted image 20240910053426](Images/Pasted%20image%2020240910053426.png)

>[!code]- Use malicious file to catch a reverse shell
>###### Set up a listener on 10.10.110.100
>![Pasted image 20240910053922](Images/Pasted%20image%2020240910053922.png)
>###### Execute netcat
>![Pasted image 20240910053839](Images/Pasted%20image%2020240910053839.png)
>###### Catch the reverse shell on Kali machine
>![Pasted image 20240910054004](Images/Pasted%20image%2020240910054004.png)

>[!success]- Obtain **Let's take this discussion elsewhere** flag (DANTE{l355_t4lk_m04r_l15tening})
>
>![Pasted image 20240910055318](Images/Pasted%20image%2020240910055318.png)
###### Webshell

>[!code]- Find Druva software version 6.6.3 installed and find an exploit
>###### Find the software
>![Pasted image 20240911045617](Images/Pasted%20image%2020240911045617.png)
>###### Get version info
>![Pasted image 20240911045919](Images/Pasted%20image%2020240911045919.png)
>###### Find exploit
>Searching results in [this exploit](https://www.exploit-db.com/exploits/48505).

>[!code]- Execute exploit on victim and receive reverse shell as Administrator
>###### Upload exploit to victim
>![Pasted image 20240911051017](Images/Pasted%20image%2020240911051017.png)
>###### Execute the exploit (I renamed file from 48505.txt to druva.py)
>![Pasted image 20240911055309](Images/Pasted%20image%2020240911055309.png)
>###### Catch the reverse shell (having setup a listener with ligolo-ng on 172.16.1.100)
>![Pasted image 20240911055412](Images/Pasted%20image%2020240911055412.png)

>[!success]- Obtain **Compare my numbers** flag (DANTE{Bad_pr4ct1ces_Thru_strncmp})
>
>![Pasted image 20240911055621](Images/Pasted%20image%2020240911055621.png)

## ✅ 172.16.1.17 (DANTE-NIX03)

>[!code]- Find open ports (80, 139, 445, 10000)
>
>![Pasted image 20240906113743](Images/Pasted%20image%2020240906113743.png)
#### Port 445 - SMB

>[!code]- Download a Wireshark PCAP file from the forensics share
>###### List shares and find file
>![Pasted image 20240906130140](Images/Pasted%20image%2020240906130140.png)
>##### Open with Wireshark
>![Pasted image 20240906130247](Images/Pasted%20image%2020240906130247.png)

>[!code]- Find admin credentials in a captured packet for a webmin server (admin:Password6543)
>###### Search for 'pass' (there is a first attempt that is wrong)
>![Pasted image 20240906133656](Images/Pasted%20image%2020240906133656.png)
>###### Look at the HTTP data on a previous packet to see webmin link
>![Pasted image 20240906130846](Images/Pasted%20image%2020240906130846.png)
#### Port 10000 - Webmin / Miniserv 1.900

>[!code]- Login to webmin portal using credentials found on SMB server (admin:Password6543)
>###### Landing page once logged in
>![Pasted image 20240906133826](Images/Pasted%20image%2020240906133826.png)
###### root

>[!code]- Find and execute an exploit for Webmin server
>###### [Find exploit](https://github.com/roughiz/Webmin-1.910-Exploit-Script) for version 1.900
>![Pasted image 20240906134110](Images/Pasted%20image%2020240906134110.png)
>###### Setup a ligolo-ng listener
>![Pasted image 20240906161252](Images/Pasted%20image%2020240906161252.png)
>###### Execute the exploit
>![Pasted image 20240906161344](Images/Pasted%20image%2020240906161344.png)
>###### Catch the reverse shell
>![Pasted image 20240906161420](Images/Pasted%20image%2020240906161420.png)

>[!success]- Obtain **Feeling fintastic** flag (DANTE{SH4RKS_4R3_3V3RYWHERE})
>
>![Pasted image 20240906161511](Images/Pasted%20image%2020240906161511.png)
## 172.16.1.19

>[!code]- Find open ports (80, 8080)
>
>![Pasted image 20240906154742](Images/Pasted%20image%2020240906154742.png)
#### Port 8080 - Jenkins Web Server

![Pasted image 20240906131724](Images/Pasted%20image%2020240906131724.png)

Attempted 117 password combos
![Pasted image 20240919060930](Images/Pasted%20image%2020240919060930.png)





## ✅ 172.16.1.20 (DANTE-DC01)

>[!code]- Find open ports (22, 53, 80, 88, 135, 1399, 389, 443, 445, 464, 593, 636, 3389)
>
>![Pasted image 20240906154821](Images/Pasted%20image%2020240906154821.png)
>![Pasted image 20240906154837](Images/Pasted%20image%2020240906154837.png)
>![Pasted image 20240906154906](Images/Pasted%20image%2020240906154906.png)
#### Port 80

>[!code]- Landing page
>
>![Pasted image 20240914103318](Images/Pasted%20image%2020240914103318.png)

>[!code]- Victim appears vulnerable to EternalBlue exploit
>###### Find an EternalBlue reference
>![Pasted image 20240914103805](Images/Pasted%20image%2020240914103805.png)
>###### Confirm with Nmap
>![Pasted image 20240914103733](Images/Pasted%20image%2020240914103733.png)
###### NT AUTHORITY

>[!code]- Obtain shell as root using EternalBlue metasploit exploit
>###### Setup exploit
>![Pasted image 20240914134256](Images/Pasted%20image%2020240914134256.png)
>![Pasted image 20240914134315](Images/Pasted%20image%2020240914134315.png)
>![Pasted image 20240914134352](Images/Pasted%20image%2020240914134352.png)
>![Pasted image 20240914134333](Images/Pasted%20image%2020240914134333.png)
>###### Catch reverse shell
>![Pasted image 20240914134420](Images/Pasted%20image%2020240914134420.png)

>[!success]- Obtain **That just blew my mind** flag
>
>![Pasted image 20240914133755](Images/Pasted%20image%2020240914133755.png)
#### Persistence

>[!code]- Find SSH private key for katwamba user
>###### Find private key
>![Pasted image 20240914134622](Images/Pasted%20image%2020240914134622.png)

>[!code]- Find 'employee_backup.xlsx' file
>###### Open file on attacking machine
>![Pasted image 20240914135718](Images/Pasted%20image%2020240914135718.png)
>![Pasted image 20240914135640](Images/Pasted%20image%2020240914135640.png)
>###### Unhide column B to reveal passwords
>![Pasted image 20240914135850](Images/Pasted%20image%2020240914135850.png)

>[!success]- Find **mrb3n leaves his mark** flag
>###### List users
>![Pasted image 20240914140418](Images/Pasted%20image%2020240914140418.png)
>###### Query mrb3n user
>![Pasted image 20240914140528](Images/Pasted%20image%2020240914140528.png)

## 172.16.1.101 (DANTE-WS02)

>[!code]- Find open ports (21, 135, 139, 445, 5040, 5985)
>
>![Pasted image 20240918052443](Images/Pasted%20image%2020240918052443.png)

>[!code]- Find FTP login credentials (dharding:WestminserOrange5)
>###### Use Metasploit to brute force users and passwords found in the xlsx file on .20
>![Pasted image 20240914155752](Images/Pasted%20image%2020240914155752.png)
>![Pasted image 20240914155729](Images/Pasted%20image%2020240914155729.png)

![Pasted image 20240914160442](Images/Pasted%20image%2020240914160442.png)
![Pasted image 20240915065855](Images/Pasted%20image%2020240915065855.png)

## ✅ 172.16.1.102 (DANTE-WS03)

>[!code]- Find open ports (80, 135, 139, 443, 445, 3306, 3389)
>
>![Pasted image 20240906113502](Images/Pasted%20image%2020240906113502.png)

#### Port 80

>[!code]- Find exploit for 'Online Marriage Registration System'
>###### Landing page
>![Pasted image 20240913051351](Images/Pasted%20image%2020240913051351.png)
>###### [Find an exploit](https://www.exploit-db.com/exploits/49557)
###### blake

>[!code]- Use exploit to obtain a reverse shell
>###### Setup listener on jump host (172.16.1.100)
>![Pasted image 20240913052351](Images/Pasted%20image%2020240913052351.png)
>###### Transfer nc.exe to victim
>![Pasted image 20240913052416](Images/Pasted%20image%2020240913052416.png)
>![Pasted image 20240913052433](Images/Pasted%20image%2020240913052433.png)
>###### Initiate and catch a reverse shell with nc.exe
>![Pasted image 20240913052504](Images/Pasted%20image%2020240913052504.png)
>![Pasted image 20240913052520](Images/Pasted%20image%2020240913052520.png)

>[!code]- Find blake has the **SeImpersonatePrivilege** right
>![Pasted image 20240913052801](Images/Pasted%20image%2020240913052801.png)
###### NT AUTHORITY

>[!code]- Obtain root shell by exploiting the SeImpersonatePrivilege with PrintSpoofer 
>###### Setup a listener on jump host (172.16.1.100)
>![Pasted image 20240914102728](Images/Pasted%20image%2020240914102728.png)
>###### Transfer PrintSpoofer to victim
>![Pasted image 20240914102804](Images/Pasted%20image%2020240914102804.png)
>###### Execute PrintSpoofer and catch reverse shell
>![Pasted image 20240914102826](Images/Pasted%20image%2020240914102826.png)
>![Pasted image 20240914102839](Images/Pasted%20image%2020240914102839.png)

>[!success]- Obtain **MinatoTW strikes again** flag (DANTE{D0nt_M3ss_With_MinatoTW})
>
>![Pasted image 20240913060318](Images/Pasted%20image%2020240913060318.png)
## ✅ 172.16.2.5 (DANTE-DC02)

>[!code]- Find open ports (53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269)
>![Pasted image 20240919055126](Images/Pasted%20image%2020240919055126.png)
## ✅ 172.16.2.6 (DANTE-ADMIN-NIX06)

![Pasted image 20240922064324](Images/Pasted%20image%2020240922064324.png)
## ✅ 172.16.2.101 (DANTE-ADMIN-NIX05)

172.16.1.20 > 172.16.2.5 > 172.16.2.101
DC01           > DC02        > 