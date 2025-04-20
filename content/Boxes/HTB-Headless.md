#xss #user-agent #command-injection #syscheck #bash-p 

>[!code]- Open ports (22, 5000)
>![Pasted image 20250402055443](Images/Pasted%20image%2020250402055443.png)
## Port 5000 (HTTP)
#### Enumeration

>[!code]- Landing page
>![Pasted image 20250402055820](Images/Pasted%20image%2020250402055820.png)

>[!code]- A form is on the `/support` page
>###### Found having clicked `For questions` button on the landing page
>![Pasted image 20250402055922](Images/Pasted%20image%2020250402055922.png)

>[!code]- The form has an XSS vulnerability within the `User-Agent` header
>###### Given within the About section on HackTheBox
>![Pasted image 20250402060319](Images/Pasted%20image%2020250402060319.png)

>[!code]- Different responses are returned depending upon how the form is completed
>###### Response if a script tag is put in the comment box
>![Pasted image 20250402064845](Images/Pasted%20image%2020250402064845.png)
>
>The requests headers are outputted. This opens the door for a XSS attack.
>
>When the form is completed 'normally', it simply reloads the page with the form fields empty again.
#### Exploit (XSS)

>[!code]- Test the XSS vulnerability
>###### Capture a legitimate request with Burpsuite
>The request was made having submitted the form.
>
>![Pasted image 20250402061023](Images/Pasted%20image%2020250402061023.png)
>
>###### Edit the request to inject XSS into the `user-agent` header
>I took inspiration of how the exploit could work from [this XSS exploit](https://github.com/Piwigo/Piwigo/issues/1835) on a user-agent header with a different application.
>
>The request was edited by injecting a XSS payload into the `user-agent` header, as well as injecting a xss payload into the comment field in order to trigger the `hacking attempt detected` page.
>
>![Pasted image 20250402065435](Images/Pasted%20image%2020250402065435.png)
>
>###### The exploit also works for the `cookie` header (and possibly other headers)
>![Pasted image 20250402065245](Images/Pasted%20image%2020250402065245.png)
>
>
>

>[!code]- Use an XSS payload to obtain the admin cookie
>###### Change the payload to capture cookies
>![Pasted image 20250402070100](Images/Pasted%20image%2020250402070100.png)

>[!code]- Use the admin cookie to load the page as admin
>###### Add the cookie to cookie storage and reload the `/dashboard` page
>Before:
>
>![Pasted image 20250402070228](Images/Pasted%20image%2020250402070228.png)
>
>After:
>
>![Pasted image 20250402070418](Images/Pasted%20image%2020250402070418.png)
#### Command Injection

>[!code]- The `Generate Report` button sends a POST request
>###### After clicking generate report
>![Pasted image 20250403051305](Images/Pasted%20image%2020250403051305.png)
>###### Capturing the request in Burp
>Clicking the button causes a POST request with the data as `date=` then the current date.
>![Pasted image 20250403051416](Images/Pasted%20image%2020250403051416.png)

>[!code]- Inject a system command to the POST request data
>###### The malicious POST command
>![Pasted image 20250403051517](Images/Pasted%20image%2020250403051517.png)
>###### The result in the webpage
>![Pasted image 20250403051745](Images/Pasted%20image%2020250403051745.png)
#### Shell as dvir

>[!code]- Obtain a reverse shell as `dvir`
>###### Generate command with revshells
>![Pasted image 20250403061217](Images/Pasted%20image%2020250403061217.png)
>###### Submit the command and catch the reverse shell
>![Pasted image 20250403061254](Images/Pasted%20image%2020250403061254.png)
>###### Obtain TTY shell
>![Pasted image 20250403061516](Images/Pasted%20image%2020250403061516.png)

>[!code]- SSH into machine
>###### Setup the necessary `ssh` folder
>![Pasted image 20250403062059](Images/Pasted%20image%2020250403062059.png)
>###### SSH into machine
>(Having chmod 600 on my copy of id_rsa.)
>![Pasted image 20250403062807](Images/Pasted%20image%2020250403062807.png)

>[!success]- Obtain user flag
>![Pasted image 20250403065154](Images/Pasted%20image%2020250403065154.png)
#### Privilege Escalation

>[!code]- dvir can run `/usr/bin/syscheck` with sudo
>###### Check sudo permissions (`sudo -l`)
>![Pasted image 20250403063843](Images/Pasted%20image%2020250403063843.png)

>[!code]- Read `syscheck` and see that it runs `./initdb.sh` (ie from the current directory)
>![Pasted image 20250403064402](Images/Pasted%20image%2020250403064402.png)

>[!code]- Create a malicious `initdb.sh` and run `syscheck`
>###### Create `initdb.sh` which changes permissions on `/bin/bash` (also make `initdb.sh` executable)
>![Pasted image 20250403064725](Images/Pasted%20image%2020250403064725.png)
>###### Run `sudo /usr/bin/syscheck`
>![Pasted image 20250403064939](Images/Pasted%20image%2020250403064939.png)

>[!success]- Run `/bin/bash -p` and obtain root flag
>###### Run bash with root permissions
>![Pasted image 20250403065018](Images/Pasted%20image%2020250403065018.png)
>###### Obtain root flag
>![Pasted image 20250403065106](Images/Pasted%20image%2020250403065106.png)


