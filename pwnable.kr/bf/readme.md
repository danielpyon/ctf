# brainf*ck solution

The buffer is stored in `.bss`. We can probably overwrite a GOT entry with `system` to get a shell.

However, we don't know any `libc` addresses so we need a leak. We'll do this by using brainf*ck's print functionality.

Infoleak will look something like this:

1. `<<< (etc)` shift the pointer left however many bytes we need to reach `setvbuf`'s GOT entry.

2. `.>.>.> (etc)` prints the bytes of the leaked address

Infoleak payload: `"<" * (0x804A0A0 - 0x804A030) + .>.>.>.`

Next is the exploit itself. We will overwrite `putchar`'s GOT entry with a one gadget, then use `.` to trigger the shell.

See `solve.py` for the full exploit.
