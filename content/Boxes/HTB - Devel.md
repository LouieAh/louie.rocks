---
created: 2025-05-16
lastmod: 2025-05-21
tags:
- ftp
- file upload
- aspx
- asp
- windows
- iis
- ms11-046
image: /static/completed-thumbnails/htb-devel.png
description: Devel, while relatively simple, demonstrates the security risks associated with some default program configurations. It is a beginner-level machine which can be completed using publicly available exploits.
---

<img src="/static/completed-thumbnails/htb-devel.png" alt="htb writeup" style="max-width: 450px; height: auto; display: block; margin: 0 auto; box-shadow: 0px 0px 14px 0px rgba(0,0,0,0.9);">

Time to complete: ~3 hours
## Initial Enumeration

>[!code]- Open ports (21 and 80)
>
>![[Images/Pasted image 20250516064720.png]]
### FTP server

>[!code]- The FTP server appears to give us access to the web server's files
>The anonymous login to the FTP server is enabled, and its immediate contents suggest it is showing files from the IIS webserver on port 80:
>
>![[Images/Pasted image 20250516065125.png]]
>
>![[Images/Pasted image 20250516065151.png]]
>
>The FTP server gives access to folders that we can't equally access through the web server. 
>
>![[Images/Pasted image 20250516065311.png]]
>
>This last-child directory can't be access through the web server. Similarly, the parent directories can't be accessed either (they all give 403 Forbidden errors):
>
>![[Images/Pasted image 20250516065400.png]]

>[!code]- The FTP server contains files being served by the HTTP server
>It's possible that the image on the home page of the web server is the `welcome.png` file within the FTP server. The image on the home page has a filename of `welcome.png`:
>
>![[Images/Pasted image 20250516065911.png]]
>
>I'm able to upload my own files to the FTP server:
>
>![[Images/Pasted image 20250516070119.png]]
>
>![[Images/Pasted image 20250516070148.png]]
>
>And have that file accessible on the HTTP server:
>
>![[Images/Pasted image 20250516070250.png]]
>
>This confirms that the files I can access through the FTP server are the same files/directories the HTTP server is serving.
## Local User Exploit

>[!code]- Upload an ASPX web shell to the web server
>Upload the `aspx` reverse shell:
>
>![[Images/Pasted image 20250520061300.png]]
>
>Use it to execute a command:
>
>![[Images/Pasted image 20250520061333.png]]

>[!code]- Upload and receive a reverse shell connection
>Use [this shell](https://gist.githubusercontent.com/qtc-de/19dfc9018685fce1ba2092c8e2382a79/raw/6d4df39b991b6fe54c606eee45483b17cdd09c4c/aspx-reverse-shell.aspx) to receive a reverse shell connection:
>
>![[Images/Pasted image 20250520062141.png]]

>[!code]- Upgrade to a PowerShell reverse shell connection
>I hosted the `nishang ps revershell ps1` at port 80:
>
>![[Images/Pasted image 20250520064504.png]]
>
>Then retrieved and executed that file, telling it to send the reverse shell connection to port 4444:
>
>![[Images/Pasted image 20250520064537.png]]
>
>Then I received that connection on port 4444:
>
>![[Images/Pasted image 20250520064600.png]]
## Privilege Escalation

>[!code]- The machine does not appear to have ever been updated
>There are no hotfixes listed:
>
>![[Images/Pasted image 20250521053916.png]]
>
>It's probable that an OS exploit exists.

>[!code]- Use MS11-046 to exploit the machine
>From researching viable exploit options for Windows 7 machines, the MS11-046 exploit appears to be viable.
>
>[This GitHub repo](https://github.com/abatchy17/WindowsExploits/tree/master/MS11-046) contains a pre-compiled copy of it (amongst several other Windows exploit executables).
>
>After downloading the exploit to the victim via the FTP server, upon executing it I can a new shell with SYSTEM permissions:
>
>![[Images/Pasted image 20250521060010.png]]

>[!success]- Obtain user and root flags
>![[Images/Pasted image 20250521060131.png]]

