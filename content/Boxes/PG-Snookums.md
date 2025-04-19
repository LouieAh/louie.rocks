#LFI #RFI #simple-photo-gallery #simple-php-gal #mysql #/etc/passwd #etc-passwd

>[!code]- Open ports
>![Pasted image 20241125054354](Images/Pasted%20image%2020241125054354.png)

>[!code]- Find Simple PHP Gal (aka Simple PHP Photo Gallery) web app
>###### Landing page
>![Pasted image 20241125055030](Images/Pasted%20image%2020241125055030.png)
>###### /README.txt (found via feroxbuster)
>![Pasted image 20241125060228](Images/Pasted%20image%2020241125060228.png)
>###### Simple PHP Gal
>![Pasted image 20241125060402](Images/Pasted%20image%2020241125060402.png)

>[!code]- Find a LFI and RFI vulnerability as per [this guide](https://www.exploit-db.com/exploits/48424)
>###### LFI
>![Pasted image 20241125060847](Images/Pasted%20image%2020241125060847.png)
>###### RFI
>![Pasted image 20241125060608](Images/Pasted%20image%2020241125060608.png)
>![Pasted image 20241125060622](Images/Pasted%20image%2020241125060622.png)
#### Apache shell

>[!code]- Use the RFI to obtain a reverse shell
>###### Retrieve a PHP web shell
>![Pasted image 20241126051948](Images/Pasted%20image%2020241126051948.png)
>###### Catch the reverse shell (on an approved port!! (i.e. not 8080 or 4444))
>![Pasted image 20241126052005](Images/Pasted%20image%2020241126052005.png)

>[!code]- In the web root find possible root credentials for a database (root:MalapropDoffUtilize1337)
>###### Find the credentials
>![Pasted image 20241126052926](Images/Pasted%20image%2020241126052926.png)

>[!code]- Find possible credentials in the mysql database (michael:HockSydneyCertify123)
>###### Mysql database is being hosted (see rustscan result)
>###### Connect to the mysql database with the root credentials
>![Pasted image 20241126055704](Images/Pasted%20image%2020241126055704.png)
>###### Enumerate the database to find encoded passwords
>![Pasted image 20241126055728](Images/Pasted%20image%2020241126055728.png)
>###### Base64 decoded the hash
>![Pasted image 20241126055750](Images/Pasted%20image%2020241126055750.png)
>
#### michael shell

>[!code]- Su to michael
>###### Su
>![Pasted image 20241126055855](Images/Pasted%20image%2020241126055855.png)

>[!success]- Obtain local.txt
>![Pasted image 20241126055948](Images/Pasted%20image%2020241126055948.png)
#### root shell

>[!code]- /etc/passwd is writeable for michael
>###### /etc/passwd
>![Pasted image 20241126062314](Images/Pasted%20image%2020241126062314.png)
>###### Add a new user
>![Pasted image 20241126063601](Images/Pasted%20image%2020241126063601.png)

>[!success]- Obtain proof.txt
>![Pasted image 20241126063528](Images/Pasted%20image%2020241126063528.png)

