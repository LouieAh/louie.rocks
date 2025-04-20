#generateADusernames #kerberoast #setuserinfo2 #chisel #internal-service #mssql #silver-ticket #seimpersonateprivilege #printspoofer

>[!code]- Open ports
>![Pasted image 20241114054101](Images/Pasted%20image%2020241114054101.png)
>![Pasted image 20241114054120](Images/Pasted%20image%2020241114054120.png)
#### Find employee names

>[!code]- Website contains a list of possible employee names
>###### /Team page
>![Pasted image 20241114060457](Images/Pasted%20image%2020241114060457.png)
>###### Copy to a wordlist
>![Pasted image 20241114060800](Images/Pasted%20image%2020241114060800.png)
>###### Generate a list of possible AD usernames
>![Pasted image 20241114060859](Images/Pasted%20image%2020241114060859.png)
#### Find AD credentials

>[!code]- Find multiple valid AD users
>###### Kerbrute
>![Pasted image 20241114061120](Images/Pasted%20image%2020241114061120.png)

>[!code]- Find 3 valid credentials (andrea.hayes:Nagoya2023, fiona.clark:Summer2023, craig.carr:Spring2023)
>###### The box was released in the Summer of 2023
>![Pasted image 20241114065140](Images/Pasted%20image%2020241114065140.png)
>###### Create possible passwords surrounding 2023
>![Pasted image 20241114065322](Images/Pasted%20image%2020241114065322.png)
>###### Valid credentials
>![Pasted image 20241114065517](Images/Pasted%20image%2020241114065517.png)
>![Pasted image 20241114065527](Images/Pasted%20image%2020241114065527.png)
>![Pasted image 20241114065537](Images/Pasted%20image%2020241114065537.png)
#### Using AD credentials

>[!code]- Use BloodHound to enumerate the AD network with andrea.hayes:Nagoya2023
>###### Bloodhound
>![Pasted image 20241115043751](Images/Pasted%20image%2020241115043751.png)

>[!code]- Kerberoast the available SPN-set accounts (svc_helpdesk & svc_mssql)
>###### impacket-GetUserSPNs
>![Pasted image 20241115044342](Images/Pasted%20image%2020241115044342.png)

>[!code]- Crack the hash for the svc_mssql account (Service1)
>###### Hashcat
>![Pasted image 20241115044714](Images/Pasted%20image%2020241115044714.png)

>[!code]- Find a path to remoting into the machine (nagoya.nagoya-industries.com)
>###### Users GenericAll > bethan.webster GenericAll > christopher.lewis > remote into nagoya.nagoya-industries.com
>![Pasted image 20241115051333](Images/Pasted%20image%2020241115051333.png)
###### Obtaining remote access to nagoya

>[!code]- Reset the password of bethan.webster
>###### rpcclient
>![Pasted image 20241115051625](Images/Pasted%20image%2020241115051625.png)
>###### Check it worked
>![Pasted image 20241115051745](Images/Pasted%20image%2020241115051745.png)

>[!code]- Reset the password of christopher.lewis
>###### rpcclient
>![Pasted image 20241115052008](Images/Pasted%20image%2020241115052008.png)
>###### Check it worked
>![Pasted image 20241115052044](Images/Pasted%20image%2020241115052044.png)
#### Shell access as christopher.lewis

>[!code]- WinRm as christopher.lewis
>###### Evil-winrm
>![Pasted image 20241115053501](Images/Pasted%20image%2020241115053501.png)

>[!success]- Find local.txt
>![Pasted image 20241115053546](Images/Pasted%20image%2020241115053546.png)

>[!code]- Port 1433 (MSSQL) is listening internally
>###### netstat
>![Pasted image 20241119053112](Images/Pasted%20image%2020241119053112.png)

>[!code]- Setup a Chisel reverse port forward (kali:1433 > victim:1433) to connect to the MSSQL server
>###### On Kali
>![Pasted image 20241119055357](Images/Pasted%20image%2020241119055357.png)
>###### On victim
>![Pasted image 20241119055421](Images/Pasted%20image%2020241119055421.png)
>###### On Kali (connection received)
>![Pasted image 20241119055451](Images/Pasted%20image%2020241119055451.png)
>###### On Kali, connect to the server
>![Pasted image 20241119060132](Images/Pasted%20image%2020241119060132.png)

>[!code]- Connect to the MSSQL server
>
#### Administrator

>[!code]- Create a silver ticket in the name of the Administrator account
>###### Generate the silver ticket ([this guide](https://medium.com/@0xrave/nagoya-proving-grounds-practice-walkthrough-active-directory-bef41999b46f) helped)
>![Pasted image 20241119062257](Images/Pasted%20image%2020241119062257.png)
>###### Export the cached ticket to the KRB5CCNAME environment variable
>![Pasted image 20241119062338](Images/Pasted%20image%2020241119062338.png)
>###### Create /etc/krb5user.conf file
>![Pasted image 20241119062610](Images/Pasted%20image%2020241119062610.png)
>###### Edit /etc/hosts
>![Pasted image 20241119062843](Images/Pasted%20image%2020241119062843.png)

>[!code]- Connect to the MSSQL server as an Administrator
>###### impacket-mssql
>![Pasted image 20241119063353](Images/Pasted%20image%2020241119063353.png)

>[!success]- Read the proof.txt file
>###### MSSQL
>![Pasted image 20241119063514](Images/Pasted%20image%2020241119063514.png) 

>[!code]- Alternative - Obtain a shell as Administrator
>###### Execute nc.exe
>![Pasted image 20241119065158](Images/Pasted%20image%2020241119065158.png)
>###### Obtain shell as svc_mssql
>###### Execute PrintSpoofer (as user has SeImpersonatePrivilege set)
>![Pasted image 20241119065251](Images/Pasted%20image%2020241119065251.png)
>![Pasted image 20241119065306](Images/Pasted%20image%2020241119065306.png)
