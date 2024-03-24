---
layout: post
title: "Stack Canary Notes"
---

Stack canaries (or stack cookies) are a mitigation technique against stack-based buffer overflows. A random 8 byte number is generated and placed between the buffer and return address, and if an attacker overwrites the cookie, the program crashes.

## Prologue
```
0x401741:  mov     rax, qword [fs:0x28]
0x40174a:  mov     qword [rbp-0x8], rax
```

```[fs:0x28]``` is the location of the cookie, generated by the OS. It is the same for the entire process (including child processes).

## Epilogue
```
0x4017fd:  mov     rax, qword [rbp-0x8]
0x401801:  xor     rax, qword [fs:0x28]
0x40180a:  je      0x401811
0x40180c:  call    __stack_chk_fail
```

This compares the current value at ```[rbp-0x8]``` with the original cookie, and crashes the program if they are not equal.

## Guess the cookie
If the process spawns children, then you could use their crash status as indication that your guess was correct, and just enumerate through all possible cookies.

## Leak the cookie
With an info leak, you could read the cookie. An example:

```
printf("%lx\n", some_array[i]);
```
If ```i``` is out of bounds, you might be able to leak the cookie, which is right before the stored ```rbp```.

## Arbitrary write
If you can write memory into the return address without overflowing the buffer, you don't need to bypass the cookie. For example, if a program doesn't bounds check for an array access, you could overwrite the stored RIP without messing up the cookie. Another example:
```
struct some_struct {
    unsigned int x[2];
    void (*fnptr)();
}
...
some_struct.x[i] = val;
```
If there is no bounds checking on ```i```, you could change the address of the function pointer.