#pdfkit #cve-2022-25765 #sudo #ruby #bash-p

>[!code]- Scan for open ports (22, 3000)
>![Pasted image 20240722044841](Images/Pasted%20image%2020240722044841.png)

>[!code]- Visit port 3000 to discover a HTML to PDF converter
>![Pasted image 20240722055535](Images/Pasted%20image%2020240722055535.png)
#### Foothold

>[!code]- Discover the app uses PDFKit and sends requests to /pdf
>Inputting a request that causes it to fail (like http://127.0.0.1) reveals that the web app uses a Ruby gem called PDFKit.
>
>![Pasted image 20240722055916](Images/Pasted%20image%2020240722055916.png)
>
>Any requests are sent to the **/pdf** page, and the POST parameter used is **url**.
>
>![Pasted image 20240722044744](Images/Pasted%20image%2020240722044744.png)
#### Access

>[!code]- Find and execute a exploit for PDFKit
>A Google search for 'PDFKit exploit' reveals this [Github repo](https://github.com/UNICORDev/exploit-CVE-2022-25765).
>
>Once downloaded, we can setup a netcat listener then execute the exploit.
>
>![Pasted image 20240722060115](Images/Pasted%20image%2020240722060115.png)
>
>We receive a reverse connection as the user 'andrew'.
>
>![Pasted image 20240722060155](Images/Pasted%20image%2020240722060155.png)

>[!success]- Obtain local.txt
>![Pasted image 20240722060703](Images/Pasted%20image%2020240722060703.png)
#### Privilege Escalation

>[!code]- Find sudo no password permissions to execute a write-enabled ruby file
>The andrew user can execute a ruby file as root, and andrew can edit the contents of that ruby file.
>
![Pasted image 20240723045219](Images/Pasted%20image%2020240723045219.png)
>
>![Pasted image 20240723045501](Images/Pasted%20image%2020240723045501.png)

>[!code]- Edit the ruby file and run it as root to obtain root permissions
>We can edit the **app.rb** file to set the SUID bit on **/bin/bash**. [GTFOBins shows](https://gtfobins.github.io/gtfobins/ruby/) the syntax to use to get a system command to run.
>
>![Pasted image 20240723050132](Images/Pasted%20image%2020240723050132.png)
>
>![Pasted image 20240723050027](Images/Pasted%20image%2020240723050027.png)
>
>Before and after running the command:
>
![Pasted image 20240723050324](Images/Pasted%20image%2020240723050324.png)
>
>![Pasted image 20240723050308](Images/Pasted%20image%2020240723050308.png)
>
>Execute **/bin/bash** as root.
>
>![Pasted image 20240723050421](Images/Pasted%20image%2020240723050421.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240723050449](Images/Pasted%20image%2020240723050449.png)