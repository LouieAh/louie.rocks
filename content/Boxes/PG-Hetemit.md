---
tags:
- api
- werkzeug
- port50000
- port18000
created: 2024-04-01
lastmod: 2024-04-01
published: 2024-04-01
image:
description: 
---

>[!code]- Open ports
>![Pasted image 20241206061232](Images/Pasted%20image%2020241206061232.png)
>![Pasted image 20241206062220](Images/Pasted%20image%2020241206062220.png)
#### cmeeks shell

>[!code]- Discover code injection vulnerability on port 50000
>###### Discover two endpoints (/verify and /generate)
>![Pasted image 20241211052747](Images/Pasted%20image%2020241211052747.png)
>###### Test /verify
>![Pasted image 20241211052816](Images/Pasted%20image%2020241211052816.png)
>###### Find a code injection vulnerability
>![Pasted image 20241211052842](Images/Pasted%20image%2020241211052842.png)
>###### Attempt a reverse shell
>![Pasted image 20241211052917](Images/Pasted%20image%2020241211052917.png)
>###### Catch the reverse shell
>![Pasted image 20241211052938](Images/Pasted%20image%2020241211052938.png)

>[!code]- The vulnerability comes from the eval() function
>###### app.py
>![Pasted image 20241211053201](Images/Pasted%20image%2020241211053201.png)

>[!success]- Obtain local.txt
>![Pasted image 20241211053258](Images/Pasted%20image%2020241211053258.png)
#### root shell

>[!code]- Find cmeeks can restart the machine and the Python service file (pythonapp.service) is editable (and therefore vulnerable)
>###### Python service file is editable (Linpeas output)
>![Pasted image 20241211060552](Images/Pasted%20image%2020241211060552.png)
>###### Cmeeks can restart the machine
>![Pasted image 20241212045948](Images/Pasted%20image%2020241212045948.png)

>[!code]- Edit the pythonapp.service file to execute a reverse shell as root upon a restart
>###### Before
>![Pasted image 20241212050149](Images/Pasted%20image%2020241212050149.png)
>###### After (edited ExecStart and User - the latter so that it executes as root rather than cmeeks)
>![Pasted image 20241212050100](Images/Pasted%20image%2020241212050100.png)

>[!code]- Restart the machine and receive a reverse shell as root
>###### Use sudo permissions to restart the machine
>![Pasted image 20241212050256](Images/Pasted%20image%2020241212050256.png)
>###### Catch the reverse shell
>![Pasted image 20241212050318](Images/Pasted%20image%2020241212050318.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241212050352](Images/Pasted%20image%2020241212050352.png)

>[!code]- Offsec alternative (similar)
>###### Modify the pythonapp.service (specify the User variable and execute a malicious file)
>![Pasted image 20241212051139](Images/Pasted%20image%2020241212051139.png)
>###### Create the malicious file
>![Pasted image 20241212051218](Images/Pasted%20image%2020241212051218.png)
>###### Reboot the machine and catch the reverse shell
>![Pasted image 20241212051244](Images/Pasted%20image%2020241212051244.png)

