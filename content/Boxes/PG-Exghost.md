#default-credentials #pcap #exiftool #cve-2019-4034 #pwnkit

>[!code]- Find open ports (21, 80)
>![Pasted image 20240624055415](Pasted%20image%2020240624055415.png)
#### Foothold

>[!code]- Find default credentials for the FTP server
>Using Hydra:
>![Pasted image 20240625041759](Pasted%20image%2020240625041759.png)

>[!code]- Download all files from the FTP server
>
>![Pasted image 20240625042343](Pasted%20image%2020240625042343.png)

>[!code]- Find that the downloaded file is a PCAP which reveals a possible Exiftool exploit
>See that its a PCAP file:
>
>![Pasted image 20240625051943](Pasted%20image%2020240625051943.png)
>
>It contains a POST request to **/exiftest.php** whereby an image is uploaded:
>
>![Pasted image 20240625044030](Pasted%20image%2020240625044030.png)
>
>The uploaded files metadata is analysed by Exiftool 12.23 (vulnerable to an arbritary code execution bug):
>
>![Pasted image 20240625044139](Pasted%20image%2020240625044139.png)
#### Access (www-data)

>[!code]- Create a malicious JPG file and upload it with a curl POST request
>Setup a listener, then submit this POST request (generated with the help of ChatGPT):
>
>![Pasted image 20240625044912](Pasted%20image%2020240625044912.png)
>
>Catch the request:
>
>![Pasted image 20240625045010](Pasted%20image%2020240625045010.png)

>[!success]- Obtain local.txt
>
>![Pasted image 20240625050935](Pasted%20image%2020240625050935.png)
#### Privilege Escalation (root)

>[!code]- Find that victim is vulnerable to CVE-2021-4034 (PwnKit)
>After running linpeas:
>
>![Pasted image 20240625052351](Pasted%20image%2020240625052351.png)

>[!code]- Execute the PwnKit exploit
>One liner [as per](https://github.com/ly4k/PwnKit):
>
>![Pasted image 20240625052609](Pasted%20image%2020240625052609.png)
>
>___
>
>Python script ([find here](https://github.com/joeammond/CVE-2021-4034)):
>
>![Pasted image 20240625053206](Pasted%20image%2020240625053206.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20240625053501](Pasted%20image%2020240625053501.png)