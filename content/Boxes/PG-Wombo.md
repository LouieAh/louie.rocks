#redis #redis-5

>[!code]- Find open port (22, 80, 6379, 8080, 27017)
>![Pasted image 20240723062111](/Images/Pasted%20image%2020240723062111.png)
>![Pasted image 20240723062131](/Images/Pasted%20image%2020240723062131.png)
#### Foothold

>[!code]- Find exploit for Redis 5.x.x
>A google search revealed [this Github repo](https://github.com/Ridter/redis-rce).
>
>That repo linked to another repo which no longer existed, but I found [another repo](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand) which had the same name **RedisModules-ExecuteCommand**, so it may be a mirror.
>
#### Access

>[!code]- Execute the exploit and obtain root permissions
>I ran the exploit with help from the README file. I used the **-f** flag to link to the **module.so** file in the **RedisModules-ExecuteCommand** repo.
>
>![Pasted image 20240724052256](/Images/Pasted%20image%2020240724052256.png)

>[!success]- Obtain proof.txt
>![Pasted image 20240724052409](/Images/Pasted%20image%2020240724052409.png)