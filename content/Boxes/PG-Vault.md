#client-side-attack #shortcut-file #responder #SeBackupPrivilege #SeRestorePrivilege #GPO #gpo-policy #gpo-permissions #gpo-exploit

>[!code]- Open ports
>![Pasted image 20241126071036](/Images/Pasted%20image%2020241126071036.png)
>![Pasted image 20241126071058](/Images/Pasted%20image%2020241126071058.png)

>[!code]- We can anonymously list the SMB shares & upload a file to the DocumentsShare share
>###### Listing shares
>![Pasted image 20241127045047](/Images/Pasted%20image%2020241127045047.png)
>###### Uploading a test file
>![Pasted image 20241127045112](/Images/Pasted%20image%2020241127045112.png)

>[!code]- Upload a malicious Windows internet shortcut file and catch anirudh's hash
>###### File contents
>![Pasted image 20241127053215](/Images/Pasted%20image%2020241127053215.png)
>###### Setup Responder
>![Pasted image 20241127053327](/Images/Pasted%20image%2020241127053327.png)
>###### Upload the file to the SMB share
>![Pasted image 20241127053243](/Images/Pasted%20image%2020241127053243.png)
>###### Catch the NTLMv2 hash of anirudh in Responder
>![Pasted image 20241127053401](/Images/Pasted%20image%2020241127053401.png)

>[!code]- Crack the password hash of anirudh (anirudh:SecureHM)
>###### Hashcat -m 5600
>![Pasted image 20241127053458](/Images/Pasted%20image%2020241127053458.png)
#### anirudh shell

>[!code]- Evil-winRM as anirudh
>###### Evil-WinRM
>![Pasted image 20241127055108](/Images/Pasted%20image%2020241127055108.png)

>[!success]- Obtain local.txt
>![Pasted image 20241127055133](/Images/Pasted%20image%2020241127055133.png)

>[!code]- Use anirudh's SeBackupPrivilege to obtain Administrator hash
>###### List privileges
>![Pasted image 20241127060521](/Images/Pasted%20image%2020241127060521.png)
>###### Create a copy of the SYSTEM and SAM hive
>![Pasted image 20241127060650](/Images/Pasted%20image%2020241127060650.png)
>###### Transfer to Kali
>![Pasted image 20241127060712](/Images/Pasted%20image%2020241127060712.png)
>###### Extract hashes
>![Pasted image 20241127060812](/Images/Pasted%20image%2020241127060812.png)
#### root shell

>[!fail]- Evil-WinRM / RDP as Administrator
>###### Evil-WinRM
>![Pasted image 20241127061857](/Images/Pasted%20image%2020241127061857.png)
>###### xfreerdp
>![Pasted image 20241127061834](/Images/Pasted%20image%2020241127061834.png)

>[!code]- Administrator is not in the Remote Management or Desktop Users groups
>###### net localgroup
>![Pasted image 20241127061806](/Images/Pasted%20image%2020241127061806.png)

>[!code]- anirudh has SeRestorePrivilege
>###### SeRestorePrivilege
>![Pasted image 20241129043007](/Images/Pasted%20image%2020241129043007.png)

>[!code]- Use [an exploit](https://github.com/dxnboy/redteam/tree/master) to elevate privileges using the SeRestorePrivilege
>###### Create a reverse shell
>![Pasted image 20241129043155](/Images/Pasted%20image%2020241129043155.png)
>###### Use the exploit to execute that reverse shell as Admin
>![Pasted image 20241129043231](/Images/Pasted%20image%2020241129043231.png)
>###### Catch the reverse shell
>![Pasted image 20241129043307](/Images/Pasted%20image%2020241129043307.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241129043359](/Images/Pasted%20image%2020241129043359.png)

___

>[!code]- Alternative method to obtain root shell
> ###### Use PowerView to enumerate the GPO objects
> ![Pasted image 20241129043608](/Images/Pasted%20image%2020241129043608.png)
> ###### Find that anirudh has full control over one of these GPOs
> ![Pasted image 20241129043651](/Images/Pasted%20image%2020241129043651.png)
> ###### Use [an exploit](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_x64/SharpGPOAbuse.exe) to exploit the full permissions over the GPO to become Administrator
> ![Pasted image 20241129043752](/Images/Pasted%20image%2020241129043752.png)
> ###### Update the GPO policy
> ![Pasted image 20241129043811](/Images/Pasted%20image%2020241129043811.png)
> ###### Anirudh is now in the Administrators group
> ![Pasted image 20241129043837](/Images/Pasted%20image%2020241129043837.png)
> ###### PsExec to machine as anirudh to obtain root shell
> ![Pasted image 20241129043915](/Images/Pasted%20image%2020241129043915.png)
> 
