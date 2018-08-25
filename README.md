# RopEmporium Challenges Walkthrough

## Intro
The [RopEmporium](https://ropemporium.com) challenges are a series of ctf-like puzzles which are specifically designed for learning [Return Oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming) or ROP. 

### Why ROP?
The [original stack smashing techniques](http://insecure.org/stf/smashstack.html) relied on overflowing a stack buffer with essentially two things: executable shellcode and the address of that shellcode on the stack. When aligned correctly, an attacker could cause a vulnerable program to pop that address into the instruction pointer register and therefore move to execution of the shellcode they had put on the stack.
Since then, various mitigations/defenses have been developed to make that original style of exploit infeasible. One of them is [marking the stack as non-executable](https://en.wikipedia.org/wiki/Executable_space_protection). The basic idea is that the OS will simply refuse to execute instructions from areas of memory marked non-executable and during compilation/linking, the program's stack is marked as non-executable. 
ROP is a [more recent](https://hovav.net/ucsd/talks/blackhat08.html) innovation which provides for taking over execution of an exploitable program without needing to jump to shellcode in the stack. Thje concept is that by looking for special sets of instructions (ROP gadgets) within the program's own code section and jumping to them in the correct order, an attacker has access to a "turing complete" language with which to work.
A ROP gadget is some set of assembly instructions which are followed by a `ret` or `jmp`, eg:
```
0x00400b73                 5f  pop rdi
0x00400b74                 c3  ret
```
By overwriting the instruction pointer such that it jumps to that `0x00400b73`, an attacker can cause the assembly instruction `pop rdi; ret;` to be executed. If, for example, there were also another piece of code in the program such as:
```
0x00400829      e8b2fdffff     call sym.imp.system
```
The following stack overflow (in psuedo-code style):
```
0x00400b73
"/bin/sh"
0x00400829
```
Would cause "/bin/sh" to be popped into the `rdi` register and then execution to jump to the system call. In x86_64, `rdi` is the first argument to a function, so `system("/bin/sh")` would be executed.

There's obviously a lot more to ROP than the above, but that's the sense of it. RopEmporium is great because it's a set of challenges that are focused strictly on ROP techniques. They present trivial stack overflows, but require various ROP techniques to actually chain the stack overflow to successful exploits.

I found that it was worth reading the [Beginner's Guide](https://ropemporium.com/guide.html).

### Setup
Getting the appropriate tooling setup on my machine was really helpful for me. I'm sure that it would be possible to complete these challenges with `gdb` and `objdump` and `readelf` and some calculations by hand, but a number of tools exist which can make your life easier, so why not use them. 

One thing to consider is whether you should do all of this on a separate virtual machine. Downloading and executing random binaries from the internet can be dangerous, and there's no guarantee that any of these tools are 100% safe. Additionally, though some of them *might* work on other platforms, they've all been designed to work on fairly recent linux. 

The first thing we'll want to do is install radare2. Radare2 is a reverse engineering toolkit that is often infuriating to learn and use, but which is very powerful and is free and open source. It *is* included in some linux package repositories, but those are often out of date and the program has gone through several major changes recently, so it's better to download directly and build from source.

The instructions from their [github](https://github.com/radare/radare2) page worked perfectly fine for me:
```
git clone https://github.com/radare/radare2.git
cd radare2
sys/user.sh
```

Next we'll want to setup pwntools. I generally prefer creating a python virtual environment, and then installing with `pip`:
```
mkvirtualenv venv
source venv/bin/activate
pip install pwntools
```

## Challenges
Individual challenge walkthroughs are in their respective folders. They go easiest to hardest. Obviously, there are SPOILERS in these :)

* [ret2win](ret2win/README.md)
