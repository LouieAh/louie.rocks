## Network Services
#### DNS

>[!info]- Info - The different DNS records
>- **NS:** Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain
>- **A:** (aka host records) contain the IPv4 address of a hostname (eg www.example.com)
>- **AAAA:** (aka quad A host records) contain the IPv6 address of a hostname (eg www.example.com)
>- **MX:** Mail Exchange records contain the names of the servers responsible for handling email for the domain
>- **PTR:** Pointer Records are used in reverse lookup zones and can find the records associated with an IP address
>- **CNAME:** Canonical Name Records are used to create aliases for other host records
>- **TXT:** Text records can contain any arbitrary data

>[!code]- Find DNS records associated with a domain
>Find the IP address (A record) of a domain:
>```bash
>www.megacorpone.com has address 149.56.244.87
>```
>___
>
>Find other records (eg mx records) of a domain:
>```bash
>kali@kali:~$ host -t mx megacorpone.com
>kali@kali:~$ host -t txt megacorpone.com
>```

>[!code]- See if a particular server exists
>```bash
>kali@kali:~$ host idontexist.megacorpone.com
>```

>[!code]- Specify which DNS server to query
>Query the 192.168.50.151 DNS server for any TXT record related to the info.megacorptwo.com host:
>```bash
>C:\Users\student>nslookup -type=TXT info.megacorptwo.com 192.168.50.151
>```

>[!code]- Find hostnames by brute forcing DNS lookups
>Create a list of possible hostnames:
>```bash
>kali@kali:~$ cat list.txt www  
ftp  
mail
owa
proxy
router
>```
>___
>
>DNS lookup each hostname in the list:
>```bash
>kali@kali:~$ for ip in $(cat list.txt); do host $ip.megacorpone.com; done
>www.megacorpone.com has address 149.56.244.87  
>Host ftp.megacorpone.com not found: 3(NXDOMAIN)  
>mail.megacorpone.com has address 51.222.169.212
>Host owa.megacorpone.com not found: 3(NXDOMAIN)
>Host proxy.megacorpone.com not found: 3(NXDOMAIN)
>router.megacorpone.com has address 51.222.169.214
>```
>___
>
>More comprehensive wordlists are available in the **seclists** directory.

>[!code]- Automate DNS Enumeration with DNSRecon and DNSenum
>DNSRecon:
>- **-d** option to specify a domain name
>- **-t** option to specify the type of enumeration to perform (eg. standard)
>```bash
>kali@kali:~$ dnsrecon -d megacorpone.com -t std
>```
>- **-D** to specify a file name (_list.txt_) containing potential subdomain strings
>- **-t** to specify the type of enumeration to perform (eg brute force)
>```bash
>kali@kali:~$ dnsrecon -d megacorpone.com -D ~/list.txt -t brt
>```
>___
>
>DNSEnum:
>```bash
>kali@kali:~$ dnsenum megacorpone.com
>```

>[!code]- Transfer a domain
>```powershell
>dig @192.168.222.122 axfr hutch.offsec
>```
#### FTP

>[!code]- Connect to FTP server
>```bash
>ftp $ip
>```

>[!code]- Download all files
>- **-m** to mirror the directory and follow links recursively
>- **--no-passive** disables passive mode
>```bash
>wget -m ftp://anonymous:anonymous@10.10.10.98
>wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98
>```
#### LDAP

>[!code]- Get domain name
>
>```powershell
>ldapsearch -H ldap://192.168.122.175:389/ -x -s base namingcontexts
>```

>[!code]- List all available objects
>###### Ldapsearch
>```powershell
># Null
>ldapsearch -x -H ldap://192.168.122.175 -D '' -w '' -b "DC=megabank,DC=local"
>
># Credentialed
>ldapsearch -x -H ldap://192.168.122.175 -D 'CN=Freddy McSorley,CN=Users,DC=hutch,DC=offsec' -w 'password' -b "DC=megabank,DC=local"
>```

>[!code]- LAPS
>###### ms-Mcs-AdmPwd attribute
>```powershell
># List all objects, then search for ms-Mcs-AdmPwd
>```

>[!code]- Test credentials
>###### CME
>```powershell
># /etc/hosts
>192.168.237.40    dc.hokkaido-aerospace.com
>
># command
>crackmapexec ldap dc.hokkaido-aerospace.com -u discovery -p 'Start123!'
>```

>[!code]- From Windows - List all objects
>Create the script:
>>[!code]- enumeration.ps1
>>```powershell
>>$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
>>$DN = ([adsi]'').distinguishedName 
>>$LDAP = "LDAP://$PDC/$DN"
>>
>>$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
>>
>>$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
>>$dirsearcher.FindAll()
>>```
>
>Run it:
>```powershell
>PS C:\Users\stephanie> .\enumeration.ps1
>```

>[!code]- From Linux - automated searches
>###### LDAPsearch
>```powershell
>ldapsearch -x -H ldap://AD_SERVER -b "dc=DOMAIN,dc=COM" -D "USERNAME@DOMAIN" -w "password"
>```
>###### Windapsearch
>```powershell
>python windapsearch.py
>
># Domain admins
>python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
>
># Privileged users
>python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
>```
#### MSSQL

>[!code]- Connect to a MSSQL server
>Using impacket:
>- **-windows-auth** forces NTLM authentication (as opposed to Kerberos)
>```bash
>kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
>```

>[!code]- Show MSSQL version
>```sql
>SQL>SELECT @@version;
>```

>[!code]- Enumerate the database
>###### List all available databases:
>```sql
>SQL>SELECT name FROM sys.databases;
>SQL> USE database-name;
>```
>The _master_, _tempdb_, _model_ and _msdb_ databases are default ones.
>
>###### List the tables within a database:
>```sql
>SQL>SELECT * FROM offsec.information_schema.tables;
>```
>###### List the records within a table:
>```sql
>SQL>select * from offsec.dbo.users;
>```

>[!code]- Check user permissions
>###### Is current user a sys admin?
>```sql
>select IS_SRVROLEMEMBER('sysadmin');    // 1 if true
>```
>###### What is the current user
>```powershell
>select system_user;
>```
>###### Impersonate another users
>```powershell
># See which users can be impersonated
>select distinct b.name from sys.server_permissions a inner join sys.server_principals b on a.grantor_principal_id = b.principal_id were a.permission_name = 'IMPERSONATE'
>
># Impersonate a user
>EXECUTE AS LOGIN = 'user';
>SELECT SYSTEM_USER;
>```
#### MySQL

>[!code]- Connect to a MySQL server
>Using mysql command:
>```bash
>kali@kali:~$ mysql -u root -p'root' -h 192.168.50.16 -P 3306
>```

>[!code]- Enumerate MySQL properties
>Version:
>```sql
>MySQL [(none)]> select version();
>MySQL [(none)]> select @@version;
>```
>Current database user:
>```sql
>MySQL [(none)]> select system_user();
>```

>[!code]- Enumerate the database
>Show available databases:
>```sql
>MySQL [(none)]> show databases;
>```
>
>Select a database:
>```sql
>MySQL [(none)]> use DATABASE;
>```
>
>Show tables:
>```sql
>MySQL [(none)]> show tables;
>```
>
>Base64 decode a column (e.g. password column)
>```sql
>SELECT username, CONVERT(FROM_BASE64(FROM_BASE64(password)), CHAR) FROM users;
>```

>[!code]- Create a file with custom content
>##### INTO OUTFILE
>```sql
>SELECT "file content" INTO OUTFILE "C:/path/to/file.php";
>```
#### RPC

>[!code]- Connect
>###### RPCClient
>```powershell
>rpcclient -U "" -N 10.10.10.169
>rpcclient -U 'admin%password' 192.169.209.40
>```

>[!code]- Commands
>###### [HackTricks article for more](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration)
>```powershell
>enumerdomusers  # list users
>queryuser 0x457  # user information
>querydispinfo  # display user text info field
>querygroupmem <0xrid> # get group members
>```

>[!code]- Extract usernames to a file
>###### Enumdomusers
>```powershell
>rpcclient -U 'discovery%Start123!' -c 'enumdomusers' 192.168.209.40 | awk -F'[][]' '{print $2}'
>```

>[!code]- Force reset a user's password
>###### setinfo
>```powershell
>setuserinfo2 MOLLY.SMITH 23 'Password123!'
>```
#### SMB

>[!code]- Nmap SMB enumeration
>Script location:
>```bash
>kali@kali:~$ ls -1 /usr/share/nmap/scripts/smb*
>```
>Using a script in a scan:
>```bash
>kali@kali:~$ nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
>```
>
>___
>
>Discovering hosts running an SMB server:
>```bash
>kali@kali:~$ nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
>```

>[!code]- nbtscan to find NetBIOS names
>This can reveal NetBIOS names:
>```bash
>kali@kali:~$ sudo nbtscan -r 192.168.50.0/24
>```

>[!code]- List available shares
>Net
>```powershell
>C:\Users\student>net view \\dc01 /all
>```
>smbclient
>```powershell
>smbclient -N -L //192.168.63.205
>smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //192.168.50.205
>smbclient -p 18000 -NL //192.168.63.205  # unusual port
>```
>###### CME
>```powershell
>bubbleman@htb$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
>
># Spider crawl a particular share
>bubbleman@htb$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
>```
>###### smbmap
>```powershell
>bubbleman@htb$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
>```

>[!code]- Connect to a share
>###### smbclient
>```powershell
>smbclient -N //192.168.24.168/share/  # Anonymous
>smbclient -U 'username' //192.168.24.168/share/   # Authenticated
>```

>[!code]- Recursively list files
>###### smbclient
>```powershell
>smbclient -N //10.10.10.100/sharename -c 'recurse;ls'
>```
>###### smbmap
>```powershell
>bubbleman@htb$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' [--dir-only]
>```

>[!code]- Recursively download files
>###### smbclient
>```powershell
>smbclient -N //10.10.10.100/Replication
>mask ""
>recurse ON
>Prompt OFF
>mget *
>```

>[!code]- Snaffler
>###### Execute
>```powershell
>Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
>```
#### SMTP

>[!info]- Info - The Simple Mail Transport Protocol (SMTP) is a mail server for delivering emails

>[!code]- Enumerate valid users
>The following example shows how the server will confirm or deny whether a particular user exists:
>```bash
>kali@kali:~$ nc -nv 192.168.50.8 25
>(UNKNOWN) [192.168.50.8] 25 (smtp) open
>220 mail ESMTP Postfix (Ubuntu)  
>VRFY root  
>252 2.0.0 root  
>VRFY idontexist
550 5.1.1 \<idontexist\>: Recipient address rejected: User unknown in local recipient table  
>^C
>```
>___
>A Python script which opens a TCP socket, connects to the SMTP server, and issues a VRFY command for a given username.
>>[!code]- smtp.py
>>```python
>>#!/usr/bin/python
>>
>>import socket import sys
>>
>>if len(sys.argv) != 3:  
>>print("Usage: vrfy.py \<username> <target_ip>") sys.exit(0)
>>
>># Create a Socket  
>>s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>
>># Connect to the Server  
>>ip = sys.argv[2]  
>>connect = s.connect((ip,25))
>>
>># Receive the banner banner = s.recv(1024)
>>
>>print(banner)
>>
>># VRFY a user  
>>user = (sys.argv[1]).encode() s.send(b'VRFY ' + user + b'\r\n') result = s.recv(1024)
>>
>>print(result)
>>
>># Close the socket s.close()
>>```
>
>We can run the script by providing the username to be test as the first argument and the target IP as the second argument:
>```bash
>kali@kali:~/Desktop$ python3 smtp.py root 192.168.50.8
>```

>[!code]- See whether a SMTP server is running using a Windows machine
>Test whether an SMTP server is running:
>```powershell
>PS C:\Users\student> Test-NetConnection -Port 25 192.168.50.8
>```
>___
>Interact with the SMTP server:
>
>**(Requires admin privileges)** - we can interact with the SMTP server from the Windows machine we can use the Microsoft version of the Telnet client:
>```powershell
>PS C:\Windows\system32> dism /online /Enable-Feature /FeatureName:TelnetClient
>```
>**(Doesn't require admin privileges)** - run the telnet binary (might need to transfer it first):
>```powershell
>c:\windows\system32\telnet.exe
>C:\Windows\system32>telnet 192.168.50.8 25
>``` 
#### SNMP

>[!info]- Commonly used SNMP tree branches
>![Pasted image 20240602094105](Pasted%20image%2020240602094105.png)

>[!code]- Enumerate the SNMP port
>With Nmap:
>```bash
>kali@kali:~$ sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
>```

>[!code]- Brute force the community string (password)
>First we must build a text file containing the community strings to brute force (_community_) and another one containing the IP addresses to scan:
>```bash
>kali@kali:~$ echo public > community
>kali@kali:~$ echo private >> community
>kali@kali:~$ echo manager >> community
>
>kali@kali:~$ for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
>
>kali@kali:~$ onesixtyone -c community -i ips
>```

>[!code]- Enumerate the SNMP tree
>Using **snmpwalk**, enumerate the entire MIB tree:
>- **-c** to specify the community string
>- **-v** to specify the SNMP version number
>- **-t 10** to increase the timeout period to 10 seconds
>```bash
>kali@kali:~$ snmpwalk -c public -v1 -t 10 192.168.50.151
>```
>Eg., enumerate all currently running process:
>```bash
>kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
>```
>
>___
>
>Using **snmp-check**, enumerate the tree and obtain key information:
>```bash
>kali@kali:~$ snmp-check 192.168.221.42
>```
#### HTTP

>[!code]- WordPress
>###### Enumerate plugins
>```powershell
># All plugins (ap)
>wpscan scan --url http://10.10.110.100:65000/wordpress/ -e ap
>
># Vulnerable plugins (vp)
>wpscan scan --url http://10.10.110.100:65000/wordpress/ -e vp
>```
>###### Enumerate users
>```powershell
>wpscan --url http://10.10.110.100:65000/wordpress/ -e u 
>```
>###### Enumerate themes
>```powershell
># All themes
>wpscan scan --url http://10.10.110.100:65000/wordpress/ -e at
>
># Vulnerable themes
>wpscan scan --url http://10.10.110.100:65000/wordpress/ -e vt
>```

>[!code]- Brute force http-post login
>###### Hydra
>```powershell
>hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"
>```

>[!code]- Create a wordlist from website
>###### CeWL
>- Defaults to a depth of `2`
>- `-d 5` changes depth to 5
>```powershell
>cewl http://10.10.110.100:65000/wordpress/
>```

>[!code]- WebDav
>###### Connect (might need credentials)
>```powershell
>cadaver http://192.168.122.120
>```
>###### Upload a file
>```powershell
>put /location/to/local/file.txt
>```