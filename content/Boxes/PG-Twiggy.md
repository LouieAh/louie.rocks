#zeromq #zmtp #cve-2020-11651 #cve-2020-11652

>[!code]- Find open ports (22, 53, 80, 4505, 4506, 8000)
>![Pasted image 20240723051959](/Images/Pasted%20image%2020240723051959.png)
#### Foothold

>[!code]- Find an exploit for ZeroMQ ZMTP 2.0
>This service looked unusual so grabbed my attention. A google search led to [this Github repo](https://github.com/jasperla/CVE-2020-11651-poc/tree/master).
#### Access

>[!code]- Execute the exploit and obtain root permissions
>First had to install the **salt** python module:
>```bash
>python -m pip --install salt
>```
>
>Then I setup a **nc** listener and ran the exploit.
>
>![Pasted image 20240723060402](/Images/Pasted%20image%2020240723060402.png)
>
>![Pasted image 20240723060426](/Images/Pasted%20image%2020240723060426.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240723060456](/Images/Pasted%20image%2020240723060456.png)


