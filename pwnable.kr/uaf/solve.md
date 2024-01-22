# pwnable.kr: uaf

Roughly,
```
m->introduce();
w->introduce();
break;
```

gets translated to:

```
0x0000000000400fcd <+265>:	mov    rax,QWORD PTR [rbp-0x38]
0x0000000000400fd1 <+269>:	mov    rax,QWORD PTR [rax]
0x0000000000400fd4 <+272>:	add    rax,0x8
0x0000000000400fd8 <+276>:	mov    rdx,QWORD PTR [rax]
0x0000000000400fdb <+279>:	mov    rax,QWORD PTR [rbp-0x38]
0x0000000000400fdf <+283>:	mov    rdi,rax
0x0000000000400fe2 <+286>:	call   rdx
0x0000000000400fe4 <+288>:	mov    rax,QWORD PTR [rbp-0x30]
0x0000000000400fe8 <+292>:	mov    rax,QWORD PTR [rax]
0x0000000000400feb <+295>:	add    rax,0x8
0x0000000000400fef <+299>:	mov    rdx,QWORD PTR [rax]
0x0000000000400ff2 <+302>:	mov    rax,QWORD PTR [rbp-0x30]
0x0000000000400ff6 <+306>:	mov    rdi,rax
0x0000000000400ff9 <+309>:	call   rdx
0x0000000000400ffb <+311>:	jmp    0x4010a9 <main+485>
```

This means that the pointer `m` is stored at `rbp-0x38` (this is also the `this` pointer that gets passed to `introduce` at `0x400fe2`).

Similarly, `w` is stored at `rbp-0x30`.

The vtables for both objects is stored in `rax` after `0x400fd1`. There's a call to the function at index 1 in the vtable.

So basically, the code is doing:

1. Store object's address into `rax`.
2. Store the first qword of the object (address of the vtable) into `rax`.
3. Add 8 to `rax`.
4. Dereference `rax` to get the address of the first instruction of the function. Then call this function.

Since PIE is off, we know that `Human::give_shell` is at `0x40117a`. Additionally, the vtable for `Man` is at `0x401570`, and contains two entries: the address of `Human::give_shell`, then the address of `Man::introduce`.

With the UAF, we can essentially overwrite `m`'s contents. We should overwrite the vtable pointer to point to the current vtable minus 8, so that when the first index is accessed in the call to `m->introduce`, it will be `Human::give_shell`.

The exploit plan is:

1. Allocate `m` and `f`.
2. Delete `m`, then `f`.
3. Allocate data with size `sizeof(f)`. This will fill `w`'s spot.
4. Allocate data with size `sizeof(m)`. This will fill `m`'s spot. The data that is written should be `p64(0x401570-8)` (aka `Man`'s vtable minus 8).
5. Call `m->introduce()`.

To make our data occupy the same spot as `m` or `f`, we need to know the exact size in bytes of the objects. With a bit of reverse engineering, we can infer that the size is `0x18==24` bytes (probably vtable, then int (padded out to 8 bytes), then string pointer?).

Therefore, the input file must be exactly 24 bytes, and the first 8 bytes should be `p64(0x401570-8)`.
