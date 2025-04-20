#kerbrute #sql #impersonate #mssql #sql-impersonate #impersonate-user #setuserinfo2 #rpc #sebackupprivilege #impacket-secretsdump

>[!code]- Open ports
>![Pasted image 20241107055435](Images/Pasted%20image%2020241107055435.png)
>![Pasted image 20241107055454](Images/Pasted%20image%2020241107055454.png)
>![Pasted image 20241107055514](Images/Pasted%20image%2020241107055514.png)
>![Pasted image 20241107055534](Images/Pasted%20image%2020241107055534.png)
>![Pasted image 20241107055551](Images/Pasted%20image%2020241107055551.png)
>![Pasted image 20241107055611](Images/Pasted%20image%2020241107055611.png)
>![Pasted image 20241107055642](Images/Pasted%20image%2020241107055642.png)
###### Kerbrute

>[!code]- Find some AD usernames (info, discover, administrator, maintenance)
>###### Kerbrute
>![Pasted image 20241108044729](Images/Pasted%20image%2020241108044729.png)

>[!code]- Find valid SMB credentials (info:info)
>###### Password list
>![Pasted image 20241108045010](Images/Pasted%20image%2020241108045010.png)
>###### Testing credentials
>![Pasted image 20241108045303](Images/Pasted%20image%2020241108045303.png)
###### SMB

>[!code]- List available shares with credentials
>###### Available shares
>![Pasted image 20241108051252](Images/Pasted%20image%2020241108051252.png)

>[!code]- Find a password in the SYSVOL share (Start123!)
>###### Password in 'password_reset.txt' file
>![Pasted image 20241108051537](Images/Pasted%20image%2020241108051537.png)

>[!code]- Find valid SMB and MSSQL credentials (discovery:Start123!)
>###### SMB
>![Pasted image 20241108052546](Images/Pasted%20image%2020241108052546.png)
>###### MSSQL
>![Pasted image 20241108052701](Images/Pasted%20image%2020241108052701.png)
###### MSSQL

>[!code]- Login to the MSSQL database
>###### impacket-mssqlclient
>![Pasted image 20241108053211](Images/Pasted%20image%2020241108053211.png)
>

>[!code]- Cannot access hrappdb database with current user
>###### Available databases
>![Pasted image 20241108053823](Images/Pasted%20image%2020241108053823.png)
>###### Cannot use hrappdb database
>![Pasted image 20241108060514](Images/Pasted%20image%2020241108060514.png)

>[!code]- Impersonate the 'hrappdb-reader' user to access hrappdb database
>###### Finding which users we can impersonate
>![Pasted image 20241108060539](Images/Pasted%20image%2020241108060539.png)
>###### Impersonate the 'hrappdb-reader' user and access the database
>![Pasted image 20241108060645](Images/Pasted%20image%2020241108060645.png)
>![Pasted image 20241108060744](Images/Pasted%20image%2020241108060744.png)

>[!code]- Find credentials in the 'sysauth' table (hrapp-service:Untimed$Runny)
>###### Credentials
>![Pasted image 20241108063032](Images/Pasted%20image%2020241108063032.png)

>[!code]- Find valid SMB credentials (info:Untimed$Runny) 
>###### Crackmapexec
>![Pasted image 20241108063204](Images/Pasted%20image%2020241108063204.png)
###### Bloodhound

>[!code]- Run bloodhound with found credentials (hrapp-service:Untimed$Runny)
>###### Collect data
>![Pasted image 20241108063740](Images/Pasted%20image%2020241108063740.png)

>[!code]- hrapp-service has GenericWrite permissions on hazel.green user object
>###### Bloodhound
>![Pasted image 20241108064134](Images/Pasted%20image%2020241108064134.png)

>[!code]- Use the GenericWrite permissions to set SPN on hazel.green and crack password (haze1988)
>###### Targeted kerberoast
>![Pasted image 20241108065559](Images/Pasted%20image%2020241108065559.png)
>###### Crack hash
>![Pasted image 20241108065719](Images/Pasted%20image%2020241108065719.png)

>[!code]- Find path from hazel.green to domain admin
>###### BloodHound
>Involves resetting molly.smith password > RDP into DC > obtain local Administrator privileges >  perform a DCSync attack > obtain Domain Admin hash
>
>![Pasted image 20241112062847](Images/Pasted%20image%2020241112062847.png)

>[!code]- Reset molly.smith password and RDP into DC with new credentials
>###### Reset password
>![Pasted image 20241112064300](Images/Pasted%20image%2020241112064300.png)
>###### RDP
>![Pasted image 20241112064353](Images/Pasted%20image%2020241112064353.png)
>
###### RDP

>[!success]- Obtain local.txt
>![Pasted image 20241113065301](Images/Pasted%20image%2020241113065301.png)

>[!code]- Use SeBackupPrivilege to crack hashes for local accounts
>###### Start a PS shell as administrator
>###### SeBackupPrivilege
>![Pasted image 20241113054716](Images/Pasted%20image%2020241113054716.png)
>###### Create copies of the SYSTEM AND SAM hives
>![Pasted image 20241113064022](Images/Pasted%20image%2020241113064022.png)
>###### Transfer those copies to Kali
>![Pasted image 20241113064448](Images/Pasted%20image%2020241113064448.png)
>###### Obtain local account hashes
>![Pasted image 20241113064721](Images/Pasted%20image%2020241113064721.png)

>[!code]- WinRM as Administrator with PtH
>###### Evil-winrm
>![Pasted image 20241113065408](Images/Pasted%20image%2020241113065408.png)

>[!success]- Obtain proof.txt
>







