# pwnable.kr: memcpy

The `movdqa` instruction needs to have 16 byte aligned args. I think `src` is guaranteed to align stuff because it's allocated with `mmap` and the first arg is `NULL` (so it'll give you something on a page boundary), but not `dst` (it's allocated with `malloc`).

So the challenge is to get 10 successive calls to `malloc` to be aligned, where the sizes must be within a certain range. Oh and it's a 32 bit binary.

Address of next chunk = `x+4`, where `x` is address of current chunk. Since we want it to be divisible by 16, `x + 4 = 0 (mod 16)`, so `x = 12 mod 16`.

```
specify the memcpy amount between 8 ~ 16 : 8
specify the memcpy amount between 16 ~ 32 : 16
specify the memcpy amount between 32 ~ 64 : 32
specify the memcpy amount between 64 ~ 128 : 64
specify the memcpy amount between 128 ~ 256 : 128
specify the memcpy amount between 256 ~ 512 : 256
specify the memcpy amount between 512 ~ 1024 : 512
specify the memcpy amount between 1024 ~ 2048 : 1024
specify the memcpy amount between 2048 ~ 4096 : 2048
specify the memcpy amount between 4096 ~ 8192 : 4096
```

It always adds 8 bytes of extra metadata between returned ptrs, so we can just input 8, 24, 40, 72, 136, 264, 520, 1032, 2056, 4104.
