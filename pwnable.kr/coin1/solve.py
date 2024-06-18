from pwn import *

p = remote('pwnable.kr', 9007)

'''
[10, 10, 10, 10, 10, 10, 10, | 10, 10, 9, 10, | 10, 10]

lo, hi = 0, 13
mid = 13//2 = 6
sum = ask(0, 6) = 70
actual = 10 * (6-0+1) = 70

this feels like binary search...

lo, hi = 0, n
while lo < hi:
  if lo == hi:
    ans = lo    
    break

  mid = n // 2

  sum = ask(lo, mid)
  actual = 10 * (mid - lo + 1)

  if sum != actual:
    hi = mid
  else:
    lo = mid+1

'''

def ask(lo, hi):
  nums = ' '.join([str(x) for x in range(lo, hi+1)])
  p.sendline(nums)
  result = int(p.recvline().decode())
  return result

print(p.recvuntil(b'in 3 sec... -').decode())
for _ in range(100):
  if _ % 10 == 0:
    print(_)

  p.recvuntil(b'N=').decode()
  N = int(p.recvuntil(' ').decode())
  p.recvuntil(b'C=').decode()
  C = int(p.recvline().decode())

  lo, hi = 0, N
  for i in range(C):
    mid = (lo + hi) // 2
    sum = ask(lo, mid)
    actual = 10 * (mid - lo + 1)
    if sum != actual:
      hi = mid
    else:
      lo = mid + 1

  p.sendline(str(lo).encode())

p.interactive()
