---
layout: post
title: "ASLR Notes"
---

ASLR randomizes the address space so that hardcoded addresses are not possible to use.

## PIE
ASLR randomizes most addresses, but not the addresses within the binary itself. PIE (position independent executable) is ASLR applied to every address.

```
0x558e0f08a000-0x558e0f08d000 r-x program
0x558e0f28c000-0x558e0f28d000 r-- program
0x558e0f28d000-0x558e0f28e000 rw- program
0x7f38b9b36000-0x7f38b9b5c000 r-x ld-2.23.so
0x7f38b9b5c000-0x7f38b9b5d000 rw-
0x7f38b9b5d000-0x7f38b9b5e000 rw-
0x7f38b9d5b000-0x7f38b9d5c000 r-- ld-2.23.so
0x7f38b9d5c000-0x7f38b9d5e000 rw- ld-2.23.so
0x7f38b9d5e000-0x7f38b9f1e000 r-x libc.so.6
0x7f38b9f1e000-0x7f38ba11e000 --- libc.so.6
0x7f38ba11e000-0x7f38ba122000 r-- libc.so.6
0x7f38ba122000-0x7f38ba124000 rw- libc.so.6
0x7f38ba124000-0x7f38ba128000 rw-
0x7fff11a3d000-0x7fff11a5e000 rw- [stack]
```

```
0x559a5dc50000-0x559a5dc53000 r-x program
0x559a5de52000-0x559a5de53000 r-- program
0x559a5de53000-0x559a5de54000 rw- program
0x7f45086fc000-0x7f4508722000 r-x ld-2.23.so
0x7f4508722000-0x7f4508723000 rw-
0x7f4508723000-0x7f4508724000 rw-
0x7f4508921000-0x7f4508922000 r-- ld-2.23.so
0x7f4508922000-0x7f4508924000 rw- ld-2.23.so
0x7f4508924000-0x7f4508ae4000 r-x libc.so.6
0x7f4508ae4000-0x7f4508ce4000 --- libc.so.6
0x7f4508ce4000-0x7f4508ce8000 r-- libc.so.6
0x7f4508ce8000-0x7f4508cea000 rw- libc.so.6
0x7f4508cea000-0x7f4508cee000 rw-
0x7ffc37dac000-0x7ffc37dcd000 rw- [stack]
```

This means that every function call is to an offset from some base address.

```
gdb> p main
$1 = 0x1a3b
```

## Bypassing ASLR
Usually, you need to use a bug to leak information. For example:

```
void * ptr = &strlen;
char other[8] = {};
char buffer[48] = {};

printf("Enter data: ");
gets(buffer);

memmove(other, buffer, strlen(buffer));

printf("Your input was: %s\n", other);
```

In this case, ```printf``` may also print ```ptr``` if there is no null terminator in ```other```. Then, we could use the offset of ```strlen``` to find the ```libc``` base adderss.
